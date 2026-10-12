#!/usr/bin/env sh
# Build the Rust verifier for the browser into web/pkg/.
# Needs: rustup target add wasm32-unknown-unknown; cargo install wasm-bindgen-cli --version 0.2.129
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
( cd "$here/.." && cargo build -p witness-log-wasm --release --target wasm32-unknown-unknown )
wasm-bindgen --target web --out-dir "$here/pkg" --out-name witness_log_wasm \
  "$here/../target/wasm32-unknown-unknown/release/witness_log_wasm.wasm"
echo "built $here/pkg/witness_log_wasm_bg.wasm ($(wc -c < "$here/pkg/witness_log_wasm_bg.wasm") bytes)"
