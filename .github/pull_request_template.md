<!-- One change per PR. The checklist is what review will ask about. -->

**What and why**

**Checklist**
- [ ] Tests that fail without the change and pass with it
- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`
- [ ] A verification or wire-format change is made in every implementation (Rust, Go `clients/go`, TypeScript `clients/typescript`) and `clients/go/testdata/compare-with-rust.sh` passes
- [ ] Corpus: `cargo run -p witness-log-core --example generate_corpus` and `cargo run -p witness-log-network --example generate_verdict_corpus` leave `corpus/` unchanged, or the change is intended and `spec/SPEC.md` says so (normative changes go through an RFC in `docs/rfcs/`)
- [ ] `CHANGELOG.md` entry under the next version
