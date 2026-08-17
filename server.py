from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from flask import Flask, jsonify, render_template_string, request, send_file

app = Flask(__name__)
MAX_MB = int(os.environ.get('MAX_UPLOAD_MB', '2048'))
app.config['MAX_CONTENT_LENGTH'] = MAX_MB * 1024 * 1024
REPO = 'LavaGang/MelonLoader.UnityDependencies'

# The server is deliberately local-only when run normally. The uploaded library is kept
# under a temporary directory and is removed on errors; the final JSON is also temporary.
HTML = open(Path(__file__).with_name('index.html'), encoding='utf-8').read()


def run(cmd: list[str], *, cwd: Path | None = None, timeout: int = 3600) -> str:
    p = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError(p.stderr.strip() or p.stdout.strip() or f'Command failed: {cmd[0]}')
    return p.stdout


def tool(name: str) -> str | None:
    return shutil.which(name)


def elf_info(path: Path) -> tuple[int, int]:
    data = path.read_bytes()[:64]
    if len(data) < 20 or data[:4] != b'\x7fELF':
        raise RuntimeError('The selected file is not an ELF binary.')
    if data[5] != 1:
        raise RuntimeError('Only little-endian Android ELF files are supported.')
    return data[4], int.from_bytes(data[18:20], 'little')


def strings_text(path: Path) -> str:
    exe = tool('llvm-strings') or tool('strings')
    if not exe:
        return ''
    return run([exe, '-a', str(path)], timeout=600)


def detect_unity_version(path: Path) -> str:
    text = strings_text(path)
    # Unity commonly leaves its editor/runtime version in plain ASCII. Accept both
    # exact f/build forms and the shorter release form used by UnityDependencies.
    pats = [
        r'Unity\s+(20\d{2}\.\d+\.\d+(?:f\d+)?)',
        r'\b(20\d{2}\.\d+\.\d+f\d+)\b',
        r'\b(20\d{2}\.\d+\.\d+)\b',
    ]
    for pat in pats:
        m = re.search(pat, text)
        if m:
            v = m.group(1)
            return re.sub(r'f\d+$', '', v)
    raise RuntimeError('Could not detect a Unity version from libunity.so. Set UNITY_VERSION_OVERRIDE to the matching Unity release before starting the server.')


def unity_release(version: str) -> dict:
    def get(url: str) -> dict | list:
        req = urllib.request.Request(url, headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'symbolmap-maker'})
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)

    tag_url = f'https://api.github.com/repos/{REPO}/releases/tags/{version}'
    try:
        x = get(tag_url)
        if isinstance(x, dict):
            return x
    except Exception:
        pass

    # Fall back to release pages and locate a tag that starts with the detected version.
    for page in range(1, 5):
        arr = get(f'https://api.github.com/repos/{REPO}/releases?per_page=100&page={page}')
        if not isinstance(arr, list):
            continue
        for r in arr:
            tag = str(r.get('tag_name', ''))
            if tag == version or tag.startswith(version + '.') or tag.startswith(version + 'f'):
                return r
    raise RuntimeError(f'No UnityDependencies release was found for Unity {version}.')


def download_clean_libunity(work: Path, version: str, machine: int) -> Path:
    release = unity_release(version)
    assets = release.get('assets', [])
    if not assets:
        raise RuntimeError(f'UnityDependencies {version} has no downloadable assets.')

    # Prefer Android/runtime archives. We still inspect archive contents rather than
    # trusting the asset name because the repository has changed packaging over time.
    preferred = []
    for asset in assets:
        name = str(asset.get('name', ''))
        low = name.lower()
        if name.endswith('.zip') and ('android' in low or 'runtime' in low or 'dependencies' in low):
            preferred.append(asset)
    preferred += [a for a in assets if a not in preferred and str(a.get('name', '')).endswith('.zip')]

    wanted = 'arm64' if machine == 183 else 'arm' if machine == 40 else ''
    for asset in preferred:
        aid = asset.get('id')
        name = str(asset.get('name', ''))
        if not aid:
            continue
        archive = work / name
        url = f'https://api.github.com/repos/{REPO}/releases/assets/{aid}'
        req = urllib.request.Request(url, headers={'Accept': 'application/octet-stream', 'User-Agent': 'symbolmap-maker'})
        try:
            with urllib.request.urlopen(req, timeout=180) as r, archive.open('wb') as f:
                shutil.copyfileobj(r, f)
            with zipfile.ZipFile(archive) as z:
                candidates = [n for n in z.namelist() if n.lower().endswith('/libunity.so') or n.lower() == 'libunity.so']
                if wanted:
                    arch_candidates = [n for n in candidates if wanted in n.lower()]
                    if arch_candidates:
                        candidates = arch_candidates
                if not candidates:
                    continue
                chosen = sorted(candidates, key=lambda x: (x.lower().count('android'), len(x)))[0]
                out = work / 'clean-libunity.so'
                with z.open(chosen) as src, out.open('wb') as dst:
                    shutil.copyfileobj(src, dst)
                return out
        except (urllib.error.URLError, zipfile.BadZipFile, OSError):
            continue
    raise RuntimeError(f'Could not find a compatible clean libunity.so inside UnityDependencies {version}.')


def ghidra_headless() -> Path | None:
    override = os.environ.get('GHIDRA_HEADLESS')
    if override and Path(override).exists():
        return Path(override)
    home = os.environ.get('GHIDRA_HOME')
    if home:
        p = Path(home) / 'support' / ('analyzeHeadless.bat' if os.name == 'nt' else 'analyzeHeadless')
        if p.exists():
            return p
    exe = tool('analyzeHeadless')
    return Path(exe) if exe else None


def export_pseudocode(binary: Path, output: Path, job: Path) -> None:
    headless = ghidra_headless()
    if not headless:
        raise RuntimeError('Ghidra headless is required. Set GHIDRA_HOME (or GHIDRA_HEADLESS) to a Ghidra installation.')
    project_dir = job / ('ghidra-' + binary.stem)
    project_dir.mkdir(parents=True, exist_ok=True)
    project_name = 'symbolmap'
    cmd = [str(headless), str(project_dir), project_name, '-import', str(binary), '-scriptPath', str(Path(__file__).parent), '-postScript', 'ExportPseudo.java', str(output), '-deleteProject']
    run(cmd, cwd=job, timeout=3600)
    if not output.exists() or output.stat().st_size == 0:
        raise RuntimeError(f'Ghidra did not produce pseudocode for {binary.name}.')


def load_pseudocode(path: Path) -> list[dict]:
    raw = path.read_text(encoding='utf-8', errors='replace')
    records = []
    # Format emitted by ExportPseudo.java: a header line followed by C text until the next header.
    chunks = re.split(r'(?m)^@@FUNC@@\t', raw)
    for chunk in chunks[1:]:
        lines = chunk.splitlines()
        if not lines:
            continue
        head = lines[0].split('\t', 1)
        if len(head) != 2:
            continue
        address, name = head
        records.append({'address': address, 'name': name, 'code': '\n'.join(lines[1:])})
    return records


def normalize(code: str, names: set[str]) -> str:
    x = re.sub(r'/\*.*?\*/', ' ', code, flags=re.S)
    x = re.sub(r'//.*', ' ', x)
    x = re.sub(r'0x[0-9A-Fa-f]+', ' ADDR ', x)
    x = re.sub(r'\b\d+(?:\.\d+)?\b', ' NUM ', x)
    # Ghidra local identifiers and generated function labels are not stable between binaries.
    x = re.sub(r'\b(local|param|in_stack|unaff|extraout|uVar|iVar|fVar|dVar|cVar|bVar|auVar|puVar)_\w+\b', ' VAR ', x)
    for n in sorted(names, key=len, reverse=True):
        if n:
            x = re.sub(r'(?<![\w$])' + re.escape(n) + r'(?![\w$])', ' FUNC ', x)
    x = re.sub(r'\s+', ' ', x).strip()
    return x


def map_decompiled(target: list[dict], clean: list[dict]) -> dict[str, str]:
    clean_names = {f['name'] for f in clean}
    target_names = {f['name'] for f in target}
    clean_norm = [(f, normalize(f['code'], clean_names)) for f in clean]
    exact: dict[str, list[dict]] = {}
    for f, n in clean_norm:
        if n:
            exact.setdefault(n, []).append(f)

    result: dict[str, str] = {}
    used: set[str] = set()
    for f in target:
        n = normalize(f['code'], target_names | clean_names)
        candidates = exact.get(n, [])
        if len(candidates) == 1 and candidates[0]['name'] not in used:
            result[f['name']] = candidates[0]['name']
            used.add(candidates[0]['name'])

    # Similarity fallback for minor compiler/Ghidra differences. Restrict candidates by
    # normalized size so matching stays tractable on large libunity.so files.
    buckets: dict[int, list[tuple[dict, str]]] = {}
    for f, n in clean_norm:
        buckets.setdefault(len(n) // 250, []).append((f, n))
    for f in target:
        if f['name'] in result:
            continue
        n = normalize(f['code'], target_names | clean_names)
        if not n:
            continue
        candidates = []
        b = len(n) // 250
        for bb in range(max(0, b - 1), b + 2):
            candidates.extend(buckets.get(bb, []))
        best_name, best_score = None, 0.0
        for cf, cn in candidates:
            if cf['name'] in used:
                continue
            score = difflib.SequenceMatcher(None, n, cn, autojunk=False).ratio()
            if score > best_score:
                best_name, best_score = cf['name'], score
        if best_name and best_score >= 0.88:
            result[f['name']] = best_name
            used.add(best_name)
    return result


def analyze_pipeline(target: Path, work: Path) -> tuple[dict, str, str]:
    _, machine = elf_info(target)
    version = os.environ.get('UNITY_VERSION_OVERRIDE') or detect_unity_version(target)
    clean = download_clean_libunity(work, version, machine)
    target_pseudo, clean_pseudo = work / 'bad.txt', work / 'good.txt'
    export_pseudocode(target, target_pseudo, work)
    export_pseudocode(clean, clean_pseudo, work)
    target_funcs = load_pseudocode(target_pseudo)
    clean_funcs = load_pseudocode(clean_pseudo)
    mapping = map_decompiled(target_funcs, clean_funcs)
    return mapping, version, f'Unity {version}; target functions {len(target_funcs):,}; clean functions {len(clean_funcs):,}; mappings {len(mapping):,}'


@app.get('/')
def index():
    return HTML


@app.post('/analyze')
def analyze_route():
    upload = request.files.get('libunity')
    if not upload or not upload.filename.lower().endswith('.so'):
        return jsonify(error='Select a libunity.so ELF shared library.'), 400
    work = Path(tempfile.mkdtemp(prefix='symbolmap-'))
    try:
        target = work / 'libunity.so'
        upload.save(target)
        mapping, version, summary = analyze_pipeline(target, work)
        out = work / 'SymbolMap.json'
        out.write_text(json.dumps(mapping, indent=2) + '\n', encoding='utf-8')
        return jsonify(id=work.name, message=f'Completed.\n{summary}\n\nDetected clean Unity reference automatically.\nSymbolMap.json downloaded next.\n\nThe uploaded game library and clean reference stayed in the local temporary directory.')
    except Exception as e:
        shutil.rmtree(work, ignore_errors=True)
        return jsonify(error=str(e)), 500


@app.get('/download/<job>')
def download(job: str):
    root = Path(tempfile.gettempdir()) / job / 'SymbolMap.json'
    if not root.exists():
        return 'Not found', 404
    return send_file(root, as_attachment=True, download_name='SymbolMap.json', mimetype='application/json')


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=int(os.environ.get('PORT', '5000')))
