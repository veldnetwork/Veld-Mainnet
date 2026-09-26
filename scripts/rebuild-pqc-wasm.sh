#!/usr/bin/env bash
set -Eeuo pipefail

[[ $# -eq 1 ]] || {
  echo "usage: VELD_EMSDK_ROOT=/path/to/emsdk $0 EMPTY_OUTPUT_DIR" >&2
  exit 2
}
: "${VELD_EMSDK_ROOT:?set VELD_EMSDK_ROOT to the activated exact emsdk 4.0.10 checkout}"

src=$(realpath "$(dirname "$0")/..")
if command -v python3 >/dev/null; then
  python_cmd=python3
elif command -v python >/dev/null; then
  python_cmd=python
else
  echo "Python 3 is required" >&2
  exit 2
fi

exec "$python_cmd" "$src/scripts/rebuild-pqc-wasm.py" \
  --emsdk-root "$VELD_EMSDK_ROOT" "$1"
