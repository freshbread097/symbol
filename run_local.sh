#!/usr/bin/env bash
set -euo pipefail

if ! command -v java >/dev/null 2>&1; then
  echo 'Java is required.' >&2; exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo 'Python 3 is required.' >&2; exit 1
fi
if [[ -z "${GHIDRA_HOME:-}" && -z "${GHIDRA_HEADLESS:-}" && -z "$(command -v analyzeHeadless || true)" ]]; then
  echo 'Set GHIDRA_HOME to your Ghidra installation (or GHIDRA_HEADLESS to analyzeHeadless).' >&2
  exit 1
fi

python3 -m pip install -r requirements.txt
exec python3 server.py
