# Contributing

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
   generate_verdict_corpus` (verification vector 13, `13_verdicts.json`)
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

```bash
cargo build --workspace
cargo test --workspace
```

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
