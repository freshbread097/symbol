# SymbolMap Maker

A local web UI for analyzing an Android ELF `libunity.so` with `llvm-readelf`/`readelf` and exporting `SymbolMap.json`.

## Run locally

Install LLVM (for `llvm-readelf` and optionally `llvm-strings`), then:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python3 server.py
```

Open `http://127.0.0.1:5000` and select the target `libunity.so`.

The upload is sent only to the local Flask process bound to `127.0.0.1`; it is not uploaded to GitHub and is never stored in the repository.

## Important limitation

The original tutorial's `bad.txt`/`good.txt` comparison gets an original symbol name by comparing an obfuscated implementation with a matching unobfuscated Unity implementation. A single obfuscated `libunity.so` does not contain enough information to reconstruct an arbitrary original symbol name. This project therefore never fabricates mappings: it emits only mappings supported by symbols exposed by the uploaded ELF.

A future backend can add a clean Unity-version reference provider and a native decompiler while keeping the uploaded game binary local.
