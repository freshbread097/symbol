# SymbolMap Maker

Browser-only automation for the tutorial workflow: upload a single Android `libunity.so` and download `SymbolMap.json`.

## What happens

1. The page reads the uploaded ELF locally and detects its Android architecture and Unity version from embedded strings.
2. The browser queries the public `MelonLoader.UnityDependencies` release API and selects the matching clean `libunity.so` for that architecture.
3. The clean reference is downloaded directly into browser memory.
4. Rizin is loaded as WebAssembly and analyzes both libraries in-memory.
5. The Pages build includes JSDec so the browser can generate C-like pseudocode with `pdd` without installing Ghidra or Rizin.
6. Functions are matched first with normalized instruction signatures and then, for ambiguous candidates, with normalized decompiler output.
7. High-confidence renamed-symbol matches are written to `SymbolMap.json` and downloaded.

## Privacy

The target game binary is processed in the browser. It is not POSTed to this repository, a Flask server, or a decompilation service. The clean Unity dependency is fetched by the browser from its public release URL.

## No local tools

There is no Python server, Ghidra install, Java install, LLVM install, or native reverse-engineering tool required.

## GitHub Pages

`.github/workflows/pages.yml` builds Rizin + JSDec to WebAssembly with `rzwasi`, places the WASM engine beside the static site, and deploys the result to GitHub Pages on pushes to `main`.

The upstream `rzwasi` project documents the browser-facing `rizin.js`/`rizin.wasm` artifacts and persistent `rzweb_*` session API. Its optional JSDec build enables the `pdd` decompiler command for browser use. citeturn14file0

## Accuracy

This is the automated equivalent of the tutorial's clean-reference comparison rather than a fabricated name generator. Exact function identity is established from normalized code signatures first; ambiguous functions are checked with normalized pseudo-code. Compiler or build differences can still leave some functions unresolved, so only high-confidence mappings are exported.

Unity runtime libraries distributed by `MelonLoader.UnityDependencies` are Unity software and remain subject to Unity's applicable terms. citeturn545029search0
