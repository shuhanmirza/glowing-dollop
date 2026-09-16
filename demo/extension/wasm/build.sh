#!/usr/bin/env bash
# Build the OpenPubkey client to WebAssembly for the browser extension.
#
# Produces two files in ../ (the extension root):
#   pkt.wasm      - the compiled module
#   wasm_exec.js  - Go's runtime glue (copied from the toolchain)
#
# Requires Go 1.25+ (the module pins go 1.25 and OpenPubkey v0.26.0).
set -euo pipefail

cd "$(dirname "$0")"
OUT_DIR=".."

echo "Building pkt.wasm ..."
GOOS=js GOARCH=wasm go build -trimpath -o "${OUT_DIR}/pkt.wasm" .

# Copy the matching wasm_exec.js from this toolchain (Go 1.21+ path first,
# falling back to the older location).
GOROOT="$(go env GOROOT)"
if [ -f "${GOROOT}/lib/wasm/wasm_exec.js" ]; then
  cp "${GOROOT}/lib/wasm/wasm_exec.js" "${OUT_DIR}/wasm_exec.js"
elif [ -f "${GOROOT}/misc/wasm/wasm_exec.js" ]; then
  cp "${GOROOT}/misc/wasm/wasm_exec.js" "${OUT_DIR}/wasm_exec.js"
else
  echo "error: could not find wasm_exec.js in ${GOROOT}" >&2
  exit 1
fi

echo "Done: ${OUT_DIR}/pkt.wasm ($(wc -c < "${OUT_DIR}/pkt.wasm") bytes), ${OUT_DIR}/wasm_exec.js"
