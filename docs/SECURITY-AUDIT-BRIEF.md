# Security audit brief: witness-log core and verifier

A scoping document for an external audit of `crates/witness-log-core`
and the verification path in `crates/witness-log-network`. It says what
the code is for, what it must guarantee, where to look, what has already
been found and fixed, and how to run every test, vector and fuzzer the
project has. Version at the time of writing: 0.3.5 plus the unreleased
changes in `CHANGELOG.md`.

## 1. What the system claims

An agent's tool calls become leaves of an RFC 6962 Merkle tree. The
agent's long-lived Ed25519 **identity key** signs checkpoints
`(tree_size, root, time)`; per-process **session keys** are vouched for
by signed key bindings. Independent **witnesses** cosign checkpoints over
`c2sp.org/tlog-witness` after checking a consistency proof from the last
head they cosigned, and refuse (422) anything that contradicts it. A
**dossier** (one JSON file) is verified offline against two inputs the
verifier supplies itself, the expected identity key and a trusted witness
directory, and yields one of five verdicts (exit code in parentheses):
`WITNESSED` (0, or 11 when the cosigners are not a strict majority of the
directory), `CONSISTENT-UNWITNESSED` (10), `UNANCHORED` (20), `DIVERGED`
(30: valid, but contradicts a head or an equivocation proof the verifier
supplied), `INVALID` (40: a check failed). `WITNESSED` requires valid
cosignatures from at least two distinct `operator_org` values in the
verifier's directory. Since 0.5.0 (RFC-0002) the verifier can also be
given heads it already trusts (`--known-head`) and witness equivocation
proofs (`--evidence`); before 0.5.0 every failed check was `DIVERGED`. A leaf's
payload is committed as `SHA256(bucket_pad(payload) || salt || index)`
with the salt outside the tree, so deleting the salt erases the content
without changing any hash.

Normative documents: `spec/SPEC.md` (wire format, §2–§9),
`spec/dossier.schema.json`, `THREAT_MODEL.md` (what is and is not proven,
actors, witness independence, accusation standard), `docs/wiki/Threat-Model.md`
and `docs/wiki/Verification-and-Verdicts.md` (verdict semantics).

## 2. Scope

### In scope

| area | files | non-test code lines (approx.) |
|---|---|---|
| Merkle tree, inclusion and consistency proofs | `core/src/merkle.rs` | 240 |
| Leaf model, canonical encoding, structural validation | `core/src/leaf.rs` | 380 |
| Log: append, checkpoints, bindings, redaction, sized heads | `core/src/log.rs` | 650 |
| Identity / session keys, key bindings, revocation | `core/src/identity.rs` | 210 |
| Signed tree heads, write receipts | `core/src/sth.rs` | 170 |
| Salted redaction, salt stores | `core/src/redaction.rs` | 290 |
| Journal: append-only file, replay, torn-line healing, lock, sealed mode | `core/src/journal.rs` | 670 |
| C2SP checkpoints, signed notes, cosignatures, verifier keys | `core/src/c2sp.rs` | 460 |
| Dossier verification, quorum and operator-diversity scoring, receipts, witness selection | `network/src/lib.rs` | 950 |
| `tlog-witness` request parsing, witness state machine, equivocation evidence | `network/src/tlog_witness.rs` | 500 |

Total roughly 4,500 lines of non-test Rust (counted with test modules and
comment-only lines removed; `core/src/lib.rs` is mostly documentation).
There is no `unsafe` in either crate. The core crate denies
`unwrap_used`, `expect_used`, `panic`, `indexing_slicing` outside tests
(`core/src/lib.rs`): a panic on hostile input is a finding.

Questions we most want answered:

1. Can any dossier the identity key did not produce verify as anything
   other than `INVALID` when `--identity` is pinned? (`Dossier::verify`)
   Conversely, can an equivocation proof not signed by the identity's key
   (a stranger's key under its canonical origin, a proof about another
   identity) make a valid dossier `DIVERGED`? (`ctx.evidence`,
   `EquivocationProof::verify`; corpus vector 13 has both cases)
2. Can `WITNESSED` be reached without cosignatures from two distinct
   operators **in the verifier's directory** (dossier-supplied directories,
   duplicate keys, case/whitespace variants of `operator_org`, project-run
   witnesses, receipts for a different head, replayed or reordered
   receipts)? (`evaluate_quorum`, receipt verification)
3. Can a witness be made to cosign a head that does not extend the one it
   holds, or to record honest behaviour as equivocation? (`verify_consistency`,
   `WitnessService::handle_add_checkpoint`, `EquivocationProof`)
4. Is the canonical leaf encoding injective (two different leaves, one
   hash)? Are domain separation and length prefixes complete? (`leaf.rs`,
   SPEC §3–§4)
5. Does redaction leak: can a forgotten payload be recovered or confirmed
   from anything left in the tree, the journal, the salts sidecar or the
   dossier? (`redaction.rs`, SPEC §8)
6. Can journal replay be driven into accepting a history different from
   the one written, or into exhausting memory? (`journal.rs`)
7. Do the C2SP encodings match the published specifications byte for
   byte, and does `cosignature_to_receipt` bind a cosignature to exactly
   one `(origin, size, root)`? (`c2sp.rs`, `tlog_witness.rs`)

### Out of scope (or lower priority)

- `crates/witness-log-cli` beyond `verify` rendering (the HTTP server in
  `cli/src/http.rs` and `witness_cmd.rs` is a reasonable second phase:
  request limits, lock handling, persist-before-cosign ordering).
- The Python bindings, the MCP server, the TypeScript client, deploy
  scripts and the registry tooling.
- Key custody (KMS/HSM integration is the integrator's), timestamps
  (self-asserted, documented as such), availability of witnesses, and the
  social question of whether a directory's operators are independent.
- Ed25519, SHA-256 and the `ed25519-dalek` / `sha2` implementations
  themselves.

## 3. Prior findings and their fixes

Every row has a regression test or corpus vector in the tree; the
CHANGELOG entry gives the detail.

| version | finding | severity | fix |
|---|---|---|---|
| 0.4.2 | Journal record written as two `write(2)` calls; a crash between them dropped a committed leaf on the next-but-one resume (review round 2, `docs/reviews/round-2-core-and-verify.md`) | high | one write per record; unterminated last record kept and terminated on open; same in the salt sidecar |
| 0.4.2 | Equivocation proof trusted its embedded vkey: a forged proof under a victim's origin verified | medium | key taken from the canonical origin; `verify_with_key` / `--vkey` otherwise |
| 0.4.2 | Revocation cut-off on holder-set timestamps only; no verifier-supplied revocations | medium | checkpoint timestamp under the cut-off; `verify --revocations`; RFC-0005 for an index cut-off |
| 0.4.2 | Type-inapplicable leaf fields neither committed nor rejected; marker hash and redaction target unchecked; anchor leaves "forgettable" | low | rejected by all three verifiers; anchor forget refused |
| 0.2.0 | Leaf encoding not injective; algorithm and signer key not inside signed messages | high | Length-prefixed fields, presence bytes, `sig_alg` and signer inside every signed message (wire-format break) |
| 0.3.0 | Sybil vector: one operator under many names counted as independent | critical | Independence counted by distinct `operator_org`, deduplicated by key; project-run witnesses one bucket; the log's own operator excluded |
| 0.3.0 | Restarted agent reported as a forger (bindings for earlier sessions missing) | critical | `all_bindings()` in every dossier; bindings persisted in journal and snapshots |
| 0.3.0 | `compare_checkpoints` false rollback accusations; double resume corrupted the journal | high | Fixed with tests in `review_regressions*.rs` |
| 0.3.1 | `verify_consistency` rebuilt only the new root: witnesses cosigned forks at non-power-of-two old sizes | critical | RFC 9162 §2.1.4.2 (both roots); exhaustive test for every `1 <= m < n <= 64`; property tests (below) |
| 0.3.1 | Cosignatures from real `tlog-witness` witnesses never counted | critical | Receipts carry `c2sp_origin`, verified against `cosignature/v1` |
| 0.3.1 | Junk consistency proof recorded as equivocation; `add_log` reset a known log | high | Evidence only for two log-signed notes at one size; `add_log` refuses known logs |
| 0.3.1 | `diff` called an edited copy plus an honest copy "equivocation" | high | Both copies must reproduce their own roots first |
| 0.3.1 | Inclusion proof for the last leaf verified for any larger index | high | Index range check (RFC 9162 §2.1.3.2) |
| 0.3.2 | Redaction after restart impossible; `evidence_window(0..u64::MAX)` hang; journal accepted unreplayable leaves; empty payloads unsalted | high | Salts sidecar, bounded windows, pre-append size checks, §8 empty-payload rule |
| 0.3.4 | Verifier hang on `tree_size > 2^63` | high | Bit arithmetic in `largest_power_of_two_lt_u64`; test at `u64::MAX` |
| 0.3.4 | Anchor proof JSON not bound to its committed hash | medium | `AnchorProofMismatch`; http(s) URLs only |
| 0.3.4 | Split views under a sub-majority gate reached WITNESSED silently | medium | `split_view_resistant` in the report; CLI warnings; since 0.5.0 `split_view_unsafe` and exit 11 by default |
| unreleased | Non-http anchor URL and non-key counterparties committed by the writer, making a log permanently DIVERGED or unbindable; expired TTL sessions kept writing | medium | Refused before the leaf exists; session rotation; `tests/fresh_eyes_regressions.rs` |

## 4. How to run everything

```sh
# Unit, integration and adversarial suites (about 2 minutes)
cargo test --workspace
cargo test --workspace --release          # debug_assert-gated paths differ

# Property tests: inclusion and consistency, trees up to 3,000 leaves,
# every single-bit mutation of leaf, roots and proof elements, fork
# rejection (both-roots reconstruction)
cargo test -p witness-log-core --test merkle_properties
PROPTEST_CASES=2000 cargo test -p witness-log-core --test merkle_properties --release

# Conformance corpus: regenerate and require no drift, then check the
# CLI against it (a second implementation would run `conform` on its own vectors)
cargo run -p witness-log-core --example generate_corpus && git diff --exit-code corpus/
cargo run -p witness-log-cli -- conform corpus --reference corpus

# Verification vector 13 (verdicts, exit codes and report fields for 20
# cases; not part of `conform`, which compares encoding vectors 01-12)
cargo run -p witness-log-network --example generate_verdict_corpus && git diff --exit-code corpus/13_verdicts.json
cargo test -p witness-log-network --test corpus_13_verdicts

# Live protocol runs over real sockets
cargo build --release -p witness-log-cli
python examples/live-network/scenarios.py          # 10 witnesses, 10 scenarios
python examples/swarm/run.py --cli target/release/witness-log   # 100 scenarios

# Supply chain
cargo deny --config deny.toml check
```

### Fuzzers

`fuzz/` holds six `cargo-fuzz` targets: `fuzz_merkle_proofs` (inclusion
and consistency verifiers on attacker-chosen sizes, indices, proofs and
roots), `fuzz_dossier_verify`, `fuzz_checkpoint_verify`,
`fuzz_journal_replay`, `fuzz_witness_request` (the `add-checkpoint` body
parser and state machine) and `fuzz_cli_render`. They run nightly for 30
minutes each in `.github/workflows/fuzz.yml` (cron `17 4 * * *`, plus
manual dispatch) with a cached corpus per target; crashes are uploaded as
artifacts. Locally:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run fuzz_merkle_proofs -- -max_total_time=300
cargo +nightly fuzz run fuzz_dossier_verify fuzz/corpus/fuzz_dossier_verify -- -max_len=65536
# reproduce a crash file
cargo +nightly fuzz run fuzz_dossier_verify fuzz/artifacts/fuzz_dossier_verify/crash-<hash>
```

## 5. Where the sharp edges are

- `merkle.rs`: `verify_consistency` (both-roots reconstruction, step 6 bit
  manipulation), `verify_path` (proof fully consumed), size and index
  arithmetic on `u64` (32-bit targets: `usize` conversions).
- `network/src/lib.rs`: `Dossier::verify` ordering of checks, identity
  pinning, `bindings_and_revocations_valid` (session window and revocation cut-off),
  `evaluate_quorum` (operator normalisation, deduplication by key,
  project-operated bucket, subject-operator exclusion, count gate versus
  fraction gate).
- `tlog_witness.rs`: parsing of the request body, origin canonicalisation
  (`witness-log/<identity key>`), the persist-before-cosign contract the
  caller must honour, and when a refusal is evidence.
- `journal.rs`: replay validation, line-length caps, torn-line healing,
  lock takeover, sealed journals (seed never written).
- `c2sp.rs`: note signature parsing, key hashes, verifier key encoding.

## 6. Contacts and reporting

Report findings privately as described in `SECURITY.md` (GitHub private
vulnerability reporting). Proofs of concept in the style of
`crates/witness-log-network/tests/review_regressions.rs` are the fastest
to act on.
