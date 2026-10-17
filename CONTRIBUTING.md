# Contributing

Participation is covered by `CODE_OF_CONDUCT.md`. Questions and ideas go
to Discussions; security reports go through a private advisory
(`SECURITY.md`); the pull request template lists what review checks.

## Before you start

Spec changes (anything touching `spec/SPEC.md` §2–§9) go through a public
RFC process: a PR adding `docs/rfcs/RFC-NNNN-<slug>.md` (template and the
four steps, RFC → corpus vectors → implementation behind a flag → spec
change, in `docs/rfcs/README.md`) before writing the implementation. See
`GOVERNANCE.md` for the reasoning.

## The conformance gate

If your change touches leaf encoding, Merkle construction, identity
binding, checkpoint signing, witness receipts, or redaction (anything in
`witness-log-core::leaf`, `::merkle`, `::identity`, `::sth`, `::redaction`, or
`witness-log-network`), you must:

1. Regenerate the corpus: `cargo run -p witness-log-core --example generate_corpus`
   (encoding vectors 01–12) and `cargo run -p witness-log-network --example
   generate_verdict_corpus` (verification vector 13, `13_verdicts.json`);
   `make corpus` runs both and fails on drift
2. Confirm the diff against `/corpus/*.json` is either empty (no wire
   format or verdict impact) or is the intended, documented change.
3. If the wire format changed intentionally, bump the spec version in
   `spec/SPEC.md` and document the change in that file directly — the
   corpus is the enforcement mechanism, the spec text is the human-readable
   explanation, and they should never drift apart.

A from-scratch reimplementation is expected to reproduce every value in
the encoding vectors (`/corpus/01_*.json` to `12_*.json`) exactly, byte for
byte, given the described inputs, and a verifier to reach the verdict,
exit code and report fields of every case in the verification vector
`/corpus/13_verdicts.json`. This is what "conformant" means in this
project — not "reads like the spec," but "passes the corpus."

## Local development

`make check` runs what CI's main jobs run (rustfmt, clippy, rustdoc and
tests; the corpus drift check; Go vet, tests and the Rust/Go parity
script; the TypeScript tests; the Python wheel and pytest; and every doc
block marked runnable), skipping with a message any language you do not
have installed. `make help` lists the single-language targets. The
repository opens in a dev container (Codespaces, or VS Code's "Reopen in
Container") with Rust, Go, Node, Python and a venv already set up.

```bash
cargo build --workspace
cargo test --workspace
make check            # or: make rust / corpus / go / ts / python / docs
witness-log doctor    # after `cargo build -p witness-log-cli`: is this setup sound?
```

Docs that show commands are tested: a fenced block preceded by
`<!-- doctest -->` runs in CI exactly as written (`docs/doctest.py`
explains the options). Mark a new quickstart block the same way, or say in
the PR why it cannot run.

Good first issues are labelled
[`good first issue`](https://github.com/0xAndersen/witness-log/labels/good%20first%20issue);
running a witness is one of them
([issue #1](https://github.com/0xAndersen/witness-log/issues/1)).

Python bindings (`crates/witness-log-python`) are a standalone Cargo workspace
(so PyO3's `extension-module` feature doesn't leak into the main
workspace's builds) — build and test them separately:

```bash
cd crates/witness-log-python
maturin develop   # builds and installs into your active venv
python3 -c "import witness_log; print(witness_log.WitnessLog.generate().identity_pubkey_hex())"
```

## Adding a witness

See `GOVERNANCE.md`'s "Witness network recruitment" section. In short:
register a `WitnessEntry` (name, operator org, URL, public key) — the
`operator_org` field is what diversity scoring keys off of, so use your
real, distinct organization name, not a placeholder.

## Code style

Standard `rustfmt` / `clippy` conventions. Keep public API doc comments
honest about what a function does and does not guarantee — this project's
credibility rests on THREAT_MODEL.md being accurate, and that starts with
accurate doc comments at the source.
