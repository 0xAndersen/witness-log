# Contributing

See [`CONTRIBUTING.md`](https://github.com/0xAndersen/witness-log/blob/main/CONTRIBUTING.md)
for the conformance-gate workflow. Short version:

- **Wire-format changes** move spec, corpus and implementation together in
  one PR; CI fails if the corpus drifts without being committed.
- **Everything else**: `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `pytest crates/witness-log-python/tests integrations/mcp -p anyio`,
  and `python examples/swarm/run.py` must pass. CI runs them all.
- **Security issues**: `SECURITY.md`, privately.
- **Witness operators**: a PR to `registry/witnesses/` is the contribution
  that matters most.

Good first contributions: a framework adapter package (see
[Framework guides](Framework-Guides)), a second-language implementation
that passes `witness-log conform`, a new swarm persona, documentation in
another language.
