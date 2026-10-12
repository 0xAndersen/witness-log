#!/usr/bin/env sh
# Build the Go verifier for the browser into web/pkg-go/. Needs only the Go
# toolchain (stdlib, no modules to fetch). The Rust build (web/build.sh) is
# the primary engine; this one is the second implementation of the same
# API so a reader can cross-check the two.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out="$here/pkg-go"
mkdir -p "$out"
( cd "$here/../clients/go" && GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o "$out/witness_log_go.wasm" ./cmd/witness-log-wasm )
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" "$out/wasm_exec.js" 2>/dev/null \
  || cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" "$out/wasm_exec.js"
cp "$here/witness_log_go.js" "$out/witness_log_go.js"
echo "built $out/witness_log_go.wasm ($(wc -c < "$out/witness_log_go.wasm") bytes)"
