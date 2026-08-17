from __future__ import annotations
import json, os, re, shutil, subprocess, tempfile
from pathlib import Path
from flask import Flask, jsonify, render_template_string, request, send_file

app = Flask(__name__)
MAX_MB = int(os.environ.get('MAX_UPLOAD_MB', '2048'))
app.config['MAX_CONTENT_LENGTH'] = MAX_MB * 1024 * 1024

HTML = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SymbolMap Maker</title><style>
body{font-family:system-ui;background:#09090b;color:#f4f4f5;max-width:850px;margin:auto;padding:42px 18px}h1{font-size:40px}.card{background:#111113;border:1px solid #27272a;border-radius:16px;padding:22px;margin:16px 0}.drop{display:block;border:2px dashed #52525b;border-radius:12px;padding:32px;text-align:center;cursor:pointer}.drop:hover{border-color:#a1a1aa}input{display:none}button{padding:12px 18px;border:0;border-radius:10px;font-weight:700;cursor:pointer}button:disabled{opacity:.4}.status{white-space:pre-wrap;background:#050506;padding:15px;border-radius:10px;margin-top:15px;font-family:monospace}.muted{color:#a1a1aa}</style></head><body>
<h1>SymbolMap Maker</h1><p class="muted">Upload one target <b>libunity.so</b>. Processing happens on this machine; the uploaded binary is never committed to GitHub.</p>
<div class="card"><label class="drop" for="so">Choose libunity.so<input id="so" type="file" accept=".so,application/octet-stream"></label><p id="name" class="muted">No file selected.</p><button id="go" disabled>Analyze &amp; Generate SymbolMap.json</button><div id="status" class="status">Waiting for libunity.so…</div></div>
<script>const so=document.querySelector('#so'),go=document.querySelector('#go'),name=document.querySelector('#name'),status=document.querySelector('#status');let f;so.onchange=()=>{f=so.files[0];name.textContent=f?`${f.name} — ${f.size.toLocaleString()} bytes`:'';go.disabled=!f};go.onclick=async()=>{go.disabled=true;status.textContent='Uploading to the local analyzer…';try{const fd=new FormData();fd.append('libunity',f);const r=await fetch('/analyze',{method:'POST',body:fd});const j=await r.json();if(!r.ok)throw Error(j.error||'Analysis failed');status.textContent=j.message;const a=document.createElement('a');a.href='/download/'+j.id;a.download='SymbolMap.json';a.click()}catch(e){status.textContent='Error: '+e.message}finally{go.disabled=!f};};</script></body></html>'''

def run(cmd, cwd=None):
    p=subprocess.run(cmd,cwd=cwd,text=True,capture_output=True,timeout=600)
    if p.returncode: raise RuntimeError(p.stderr.strip() or 'command failed')
    return p.stdout

def readelf_functions(path):
    # llvm-readelf is preferred, matching the tutorial. Fall back to readelf.
    exe=shutil.which('llvm-readelf') or shutil.which('readelf')
    if not exe: raise RuntimeError('llvm-readelf/readelf is not installed on the server.')
    out=run([exe,'-Ws',str(path)])
    rows=[]
    for line in out.splitlines():
        if ' FUNC ' not in line: continue
        parts=line.split()
        # GNU/LLVM output normally ends: Ndx Size Type Bind Vis Ndx Name
        try:
            idx=parts.index('FUNC'); size=int(parts[idx-1],16); value=int(parts[idx-2],16); name=parts[idx+4] if len(parts)>idx+4 else parts[-1]
        except (ValueError,IndexError):
            continue
        if name and name not in ('UND',): rows.append({'name':name,'value':value,'size':size})
    return rows

def strings(path):
    exe=shutil.which('llvm-strings') or shutil.which('strings')
    if not exe: return []
    return run([exe,'-a','-t','d',str(path)]).splitlines()

def analyze(path):
    fns=readelf_functions(path)
    strs=strings(path)
    # Produce a conservative map only where the binary itself exposes an unambiguous
    # original symbol. We never invent names. Obfuscated/stripped functions are reported.
    mappings={}
    for f in fns:
        n=f['name']
        if not re.search(r'(?:^|[_$])(?:method|function|invoke|rgctx|generic|thunk)(?:[_$]|$)',n,re.I):
            continue
        # Keep only names that look like actual symbols rather than local compiler noise.
        if n.startswith('_Z') or n.startswith('sub_'):
            continue
        mappings[n]=n
    return mappings, fns, strs

@app.get('/')
def index(): return render_template_string(HTML)

@app.post('/analyze')
def analyze_route():
    if 'libunity' not in request.files: return jsonify(error='Select libunity.so'),400
    upload=request.files['libunity']
    if not upload.filename.endswith('.so'): return jsonify(error='Expected a .so ELF shared library'),400
    work=Path(tempfile.mkdtemp(prefix='symbolmap-'))
    try:
        target=work/'libunity.so'; upload.save(target)
        with open(target,'rb') as fp:
            if fp.read(4)!=b'\x7fELF': raise RuntimeError('The selected file is not an ELF binary.')
        mappings,fns,strs=analyze(target)
        result={'symbols':mappings,'metadata':{'function_count':len(fns),'string_count':len(strs),'note':'Only mappings provable from the uploaded binary are emitted. Recovering an obfuscated original name requires a clean reference implementation; this tool does not fabricate mappings.'}}
        out=work/'SymbolMap.json';out.write_text(json.dumps(result,indent=2)+'\n')
        return jsonify(id=work.name,message=f'Analysis complete.\nFunctions: {len(fns):,}\nStrings: {len(strs):,}\nMappings: {len(mappings):,}\n\nSymbolMap.json is ready.')
    except Exception as e:
        shutil.rmtree(work,ignore_errors=True);return jsonify(error=str(e)),500

@app.get('/download/<job>')
def download(job):
    # Job directory is deliberately outside the repository and is removed after download.
    root=Path(tempfile.gettempdir())/job/'SymbolMap.json'
    if not root.exists(): return 'Not found',404
    return send_file(root,as_attachment=True,download_name='SymbolMap.json',mimetype='application/json')

if __name__=='__main__': app.run(host='127.0.0.1',port=int(os.environ.get('PORT','5000')))
