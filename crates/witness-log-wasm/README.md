# witness-log-wasm

WebAssembly bindings over the canonical Rust verifier
(`witness-log-network::Dossier::verify`) for use in a browser: strings in,
a JSON report out, no I/O, no network, no clock.

Exports (`wasm-bindgen`, `--target web`):

| Function | Returns |
|---|---|
| `verify_dossier(json, directory_json?)` | verdict (one of five, INVALID included), exit code (0, 11, 10, 20, 30, 40), the `witness-log verify --json` report, and a display summary (leaves, checkpoint, receipts, bindings) |
| `verify_dossier_with_options(json, directory_json?, options_json)` | same, with `expected_identity_pubkey`, `threshold`, `min_receipts`, `allow_sub_majority` (exit 0 instead of 11 for a sub-majority WITNESSED), `revocations`, `known_heads` (`"<size>:<root hex>"`) and `evidence` (witness equivocation proofs, bare or as `witness serve` writes them) |
| `verify_disclosure(leaf_json, payload: Uint8Array, salt_hex)` | `{matches, committed, recomputed, leaf_index}` (SPEC §8) |
| `bind(a_json, b_json)` | the `witness-log bind` matching with its exit code |
| `version()` | crate version |

Every export has a pure-Rust twin (`*_value`) returning `serde_json::Value`,
which is what `tests/conformance.rs` runs on the host against the corpus
(the verification vector `13_verdicts.json` included) and the golden
dossiers in `clients/go/testdata`. The crate is a member of
the root workspace, so `cargo test --workspace` covers it without a wasm
toolchain.

Build for the browser:

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.129   # must match Cargo.toml
sh web/build.sh                                      # -> web/pkg/
```

The crate is `publish = false`; the static page in `web/` is its only
consumer.
