# One target per question a contributor asks. `make check` runs what CI's
# main jobs run, minus the live-network, swarm and cross-platform steps,
# and skips (with a message) any language whose toolchain is missing.
#
#   make check     everything below that your machine can run
#   make rust      fmt check, clippy -D warnings, rustdoc, cargo test
#   make corpus    regenerate the conformance corpus; fail if it drifted
#   make go        go vet + go test + the Rust/Go parity script
#   make ts        the TypeScript client's tests
#   make python    build the Python wheel into the active venv, run pytest
#   make docs      run every doc block marked <!-- doctest --> (needs python)
#   make pilot     the three-organisation pilot on localhost
#   make demo      witness-log demo --tamper

SHELL := bash
.SHELLFLAGS := -eo pipefail -c
.DEFAULT_GOAL := help
CLI := target/debug/witness-log

.PHONY: help check rust corpus cli go ts python docs pilot demo

help:
	@sed -n '1,13p' Makefile | sed 's/^# \{0,1\}//'

check: rust corpus go ts python docs
	@echo
	@echo "make check: all done"

rust:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --quiet
	cargo test --workspace

corpus:
	cargo run --quiet -p witness-log-core --example generate_corpus
	cargo run --quiet -p witness-log-network --example generate_verdict_corpus
	cargo run --quiet -p witness-log-network --example generate_fleet_corpus
	cargo run --quiet -p witness-log-network --example generate_evidence_corpus
	@git diff --exit-code corpus/ || { echo "corpus drifted: commit it if the change is intended (CONTRIBUTING.md, 'The conformance gate')"; exit 1; }

cli:
	cargo build --quiet -p witness-log-cli

go: cli
	@if ! command -v go >/dev/null; then echo "skip go: not installed"; exit 0; fi; \
	cd clients/go && go vet ./... && go test ./... && go build -o ../../target/witness-log-verify ./cmd/witness-log-verify; \
	cd ../.. && clients/go/testdata/compare-with-rust.sh

ts: cli
	@if ! command -v npm >/dev/null; then echo "skip ts: npm not installed"; exit 0; fi; \
	cd clients/typescript && { [ -d node_modules ] || npm ci; } && npm test

python: cli
	@if [ -z "$$VIRTUAL_ENV" ]; then echo "skip python: activate a virtualenv first (python3 -m venv .venv && . .venv/bin/activate)"; exit 0; fi; \
	pip install --quiet maturin pytest jsonschema; \
	cd crates/witness-log-python && maturin develop --release --quiet && python -m pytest tests -q

docs: cli
	@if ! python3 -c "import witness_log" 2>/dev/null; then echo "skip docs: witness_log not importable (make python first, in a venv)"; exit 0; fi; \
	WITNESS_LOG_CLI=$(CLI) python3 docs/doctest.py

pilot: cli
	WITNESS_LOG_BIN=$(CLI) python3 examples/pilot-triangle/run.py

demo: cli
	$(CLI) demo --tamper || true
