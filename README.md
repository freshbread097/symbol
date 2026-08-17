# SymbolMap Maker

This project automates the workflow described in the tutorial from a single uploaded target `libunity.so`.

## Workflow

1. Select the target `libunity.so` in the local web UI.
2. The local backend validates the ELF and detects its architecture.
3. It scans the library's strings for a Unity version.
4. It queries the `LavaGang/MelonLoader.UnityDependencies` releases for that Unity version and downloads a matching clean runtime archive automatically.
5. The backend extracts a clean `libunity.so` matching the detected architecture.
6. Ghidra headless analyzes both libraries and `ExportPseudo.java` exports decompiled C-like pseudocode for every successfully decompiled function.
7. The Python mapper normalizes generated names, addresses, comments, and common Ghidra temporaries, then performs exact and high-confidence similarity matching.
8. The result is exported as `SymbolMap.json` and downloaded.

## Local-only upload

The browser sends the `.so` only to the Flask process listening on `127.0.0.1`. The target library and downloaded clean reference live under the OS temporary directory while the job runs and are not committed to GitHub.

## Setup

Install Java and Ghidra, then set `GHIDRA_HOME` to the Ghidra installation directory. The app specifically needs Ghidra's `support/analyzeHeadless` executable.

Also install Python 3 and an LLVM toolchain containing `llvm-strings` (the analyzer falls back to the platform `strings` command).

Then run:

```bash
bash run_local.sh
```

Open `http://127.0.0.1:5000`.

### Version override

Some stripped libraries do not retain a readable Unity version. In that case set the exact Unity release used by the game before launching:

```bash
export UNITY_VERSION_OVERRIDE=2021.3.45
bash run_local.sh
```

## Accuracy note

This is substantially closer to the tutorial than simple ELF byte matching: it automatically obtains the clean Unity implementation and performs decompiler-based function matching. However, decompilers can produce different pseudocode for compiler, build, or optimization differences, so the mapper uses a conservative exact pass followed by a high-confidence similarity pass and does not claim unmatched functions are mapped.

Unity runtime libraries in the dependency repository are Unity software and remain subject to Unity's applicable terms.
