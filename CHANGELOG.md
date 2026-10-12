# Changelog

## 0.3.6 — 2026-10-12

Driven by a fresh-eyes evaluation of the published 0.3.5 packages
(integrator, adversary and hostile-input personas working only from the
README, `pip install witness-log` and `cargo install witness-log-cli`).
The adversary found no way to a dishonest verdict: tampering, truncation,
reordering, forged and re-signed logs, stolen receipts, duplicated
receipts, dossier-supplied directories and forks submitted to witnesses
all ended where they should (DIVERGED, UNANCHORED, CONSISTENT-UNWITNESSED,
or a 422 with verifiable evidence). The integrator and hostile-input
personas found the defects below; each fix has a regression test that
fails on 0.3.5. No wire-format or verdict change.

### Fixed

- **A bad anchor URL bricked the journal.** `append_external_anchor`
  committed a non-http(s) URL that the verifier rejects: every later
  dossier was DIVERGED and `resume` refused the journal. Now refused
  before the leaf exists (`JournaledLog`, and `WitnessLog::try_append_external_anchor`);
  the validation error names the URL rule instead of "64 lowercase hex".
- **Handoff and authorization counterparties were not checked.** Any
  string ("zz", "") was committed as the other agent's key, producing a
  leaf that verifies but can never `bind`; an uppercase key never bound
  either. `JournaledLog` refuses non-keys; keys are stored lowercase.
- **Expired TTL sessions made honest logs DIVERGED.** After
  `resume_with_ttl`'s binding expired the log kept writing under it. The
  next append now rotates to a fresh session bound with the same TTL.
- **The MCP server read local files.** `submit_to_witnesses` followed any
  URL scheme in a caller-supplied directory and returned the first 200
  bytes of the response, so `file:///path#` disclosed local files to the
  caller. Witness URLs must be http(s) (MCP, `Witnesser`, entry builders,
  `witness init`).
- **MCP witnessing did not stick.** After a successful
  `submit_to_witnesses`, `verify_chain_integrity` said
  `consistent_unwitnessed` and `export_dossier` had no receipts. The
  witnessed dossier is kept and used while the head is unchanged
  (`witnessed_size` / `witnessed_verdict` after). The MCP witness state
  now uses the CLI's `<journal>.witnesses.json` format (it shared the path
  with a different format) and the CLI's refuse-to-equivocate rule.
- MCP tool errors carried no reason ("Error executing tool X"); they now
  say what to fix.
- `@witness_log.step` raised `TypeError`/`ValueError` into the agent for
  values `json` cannot encode with sorted keys (mixed key types, cycles),
  after the tool had run, losing its return value. `canonical_json` never
  raises and always emits valid JSON (NaN/infinity become strings).
- `witness-log verify /dev/zero` (or a FIFO) read until the OOM killer
  ended it; inputs are capped at 512 MiB with a message.
- `witness submit` ignored unknown flags (`--mni 2` meant `--min 1`);
  `witness init` accepted an empty `--org` (scored as an operator) and a
  non-http `--url`; `verify` silently ignored directory entries with
  malformed keys (now a warning); `witness_entry_independent` accepted a
  pubkey of "zz" and an empty org; `select_witnesses` rejected the bare
  list form `verify_dossier_json` accepts.
- `conform` only worked from a checkout's root: `--reference <corpus>`.
- `from witness_log import *` exported `open`, shadowing the builtin.

### Fixed (routed from the operator-kit and launch-content work)

- **A witness in a container never restarted after `docker kill`.** Its
  lock file named pid 1, the restarted witness was pid 1 again, the
  liveness check saw itself and refused forever. A lock naming the
  process's own pid is now treated as stale (it cannot be held by a live
  witness: this process has not taken it yet).
- **`diff` hedged on a whole-history rewrite.** Two dossiers under one
  identity diverging at leaf 0 printed "usually means these are two
  SEPARATE logs" and never "EQUIVOCATION DETECTED". Under the canonical
  origin the key names the log, so it is equivocation (witnesses refuse
  it the same way); the output now says so and names the same-seed case.
- `bind` printed authorization kinds in Rust Debug form (`Some(GrantedByMe)`);
  it now prints `granted_by_me` etc.
- **No Linux ARM binary was released**, so the Oracle Always Free path
  (Ampere A1) had nothing to download. `aarch64-unknown-linux-gnu` is now
  built, and Linux binaries are built on Ubuntu 22.04 for older glibc.
- `registry/validate.py` rejects loopback URLs (`witness init` without
  `--url` writes `http://127.0.0.1:7380`).
- SPEC §0 said every leaf is signed by a session key; leaves are not
  individually signed. SPEC §1 claimed a wire-compatibility aim with the
  agent-record draft and an IETF working group's conclusion; both are
  corrected.

### Operators

- Public witness status page, every 10 minutes, on the `status` branch
  (`STATUS.md`, `status.json`); empty registry rendered honestly.
- `ghcr.io/0xandersen/witness-log` multi-arch image that initialises
  itself from `WITNESS_ORG` on first start (docker one-liner).
- cloud-init survives offline steps (IP fallback, Caddy optional, ARM
  compile fallback); a QEMU end-to-end workflow (manual).
- Operator onboarding page with current, cited hosting facts; a Founding
  operators list in GOVERNANCE.md; `witnessed-report` workflow that writes
  the first independent-WITNESSED report only when two outside
  organisations are registered and up.

### Launch material

- `examples/rewrite-attack/run.py`: the same-key history rewrite refused
  by two witnesses with 422, evidence verified, `diff` flagging
  equivocation, in under a second on localhost.
- Per-project comparison pages (Tessera, Microsoft AGT, Signet, immudb,
  Agent Receipts, SCITT) from primary sources; SCITT RFC 9943 mapping with
  the agent-record divergence list; a runnable AP2 mandates tutorial.

### Added

- `witness_log.Witnesser`: background witnessing for a journal.
  `request()` never blocks or raises; retries with exponential backoff,
  honours `Retry-After`, follows 409 resyncs, pins the head it submits
  while the agent keeps appending; `status()` with a structured
  `last_error`; `flush(timeout)` and `await aflush(timeout)`; state shared
  with the CLI. `witness_log.submit_round` is one synchronous round.
- Sized heads: `root_hex_at`, `add_checkpoint_body_at`,
  `dossier_from_responses_at` (Python); `root_at`,
  `consistency_proof_between`, `c2sp_checkpoint_at`, `checkpoint_at` (Rust).
- The MCP server ships in the package: `pip install "witness-log[mcp]"`,
  then `witness-log-mcp` (or `python -m witness_log.mcp_server`).
  `integrations/mcp/witness_mcp_server.py` remains as a launcher. New
  tool `record_result`: intent before acting, result after.
- Framework adapters as extras: `witness-log[langchain]`
  (`WitnessLogCallbackHandler`), `witness-log[openai-agents]`
  (`WitnessLogHooks`), `witness-log[crewai]` (`witness_crewai`).
- `@witness-log/client` (`clients/typescript`): typed verdicts from the
  CLI and `WitnessLogMCP` (`step`, `forget`, `exportDossier`, `verify`,
  `submit`) over the MCP server. Published by `npm.yml` on `ts-v*` tags.
- Benchmarks with a budget (`bench.yml`, `benches/`), proptest properties
  for inclusion and consistency proofs, `docs/SECURITY-AUDIT-BRIEF.md`.

### Docs

- Framework guides point at the adapters; the OpenAI Agents SDK snippet
  raised `KeyError` when one tool was called twice in parallel, and the
  LangChain snippet recorded every result under the name "tool".
- MCP pages: nine (now ten) tools, not seven; state lives in
  `<session>/journal.jsonl`; leaves are not individually signed.
- Quickstart: Python uses `Witnesser`, shows the intent payload as it
  really is, and explains `min_witnesses` against a two-witness setup;
  Quickstart: CLI shows how to build `trusted.json` from `witness init`
  output and says that `submit` contacts every witness in the directory.

## 0.3.5 — 2026-10-11

### Changed

- **License: Apache-2.0** (was AGPL-3.0-only through 0.3.4). The outside
  evaluation's second-ranked blocker: copyleft on an in-process library
  fails most enterprise and payment-company legal review, and every
  comparable project is MIT/Apache. Openness of the network rests on the
  public spec, the conformance corpus and the C2SP witness protocol, not
  on the license. `NOTICE` records the relicensing and reserves the name.

## 0.3.4 — 2026-10-11

Driven by an independent three-persona evaluation of 0.3.3 (agent
developer, transparency-log engineer, agent-commerce infrastructure lead;
each built it, attacked it, and ran competitors on the same tasks). Every
core claim held; six defects were found, all fixed here.

### Fixed — security and correctness

- **Verifier hang on absurd tree sizes.** `largest_power_of_two_lt_u64`
  doubled `k` until `k * 2 >= n`; for `n > 2^63` the multiplication wraps
  to 0 and the loop never ends, so a dossier claiming `tree_size = 2^63+1`
  hung `verify` (release) or panicked it (debug) with no valid proof
  needed. Now bit arithmetic; test covers `u64::MAX`.
- **Anchor proofs were not bound to their hash.** An `ExternalAnchor`
  leaf carrying `anchor_proof_json` is now rejected unless
  `SHA-256(anchor_proof_json) == anchor_proof_hash`
  (`LeafValidationError::AnchorProofMismatch`), and `anchor_url` must be
  an http(s) URL. `verify` lists how many anchors a dossier records and
  states plainly that it does not fetch or check them with the provider.
- **Split views passed a sub-majority gate silently.** With
  `--threshold 0.5` or `--min-witnesses N <= directory/2`, two conflicting
  histories cosigned by disjoint halves of a directory both reached
  WITNESSED and nothing said so. `QuorumResult.split_view_resistant`
  (`2 × receipts > directory`) is reported in JSON; the CLI warns when the
  dossier's cosigners are not a majority and, separately, when the chosen
  gate would admit one. THREAT_MODEL.md has the row; the live test
  `split_view_below_a_majority_is_reported_not_hidden` reproduces it.
- `witness submit --out dossier.json` from the journal's own directory
  wrote the file and the cache, then reported "No such file or directory"
  and exited 1 (`Path::parent()` of a bare filename is `Some("")`).

### Added

- **Sealed journals**: `JournaledLog::create_sealed` /
  `resume_with_identity` and Python `open(path, identity_seed=, seal=True)`
  keep the identity seed out of the journal; the header pins only the
  public key and the seed comes from your KMS / secrets manager on every
  start. Resume without it, or with the wrong seed, is refused.
- **Cross-agent features everywhere, not just Rust.** Python:
  `append_authorization_event(kind, scope, counterparty)`,
  `append_external_anchor`, `verify_handoff_binding`,
  `verify_authorization_binding`. MCP: `record_handoff` and
  `record_authorization` tools. CLI: `witness-log bind <a.json> <b.json>
  [--json]` matches two agents' handoff and authorization leaves (exit 0
  bound, 30 mismatch, 10 nothing to bind).

### Docs

- README no longer claims `pip install witness-log` / `cargo install
  witness-log-cli` work before publication; measured cost is stated as
  tens of microseconds; leaves are described accurately as unsigned
  records under an identity-signed checkpoint; a "Where it sits" section
  positions the project under AP2 / verifiable-intent / x402 mandates and
  beside SCITT (RFC 9943).
- Wiki: named comparison (Tessera, Microsoft AGT, Signet, immudb,
  agent-receipts, mandate schemes, SCITT), sealed journals, `bind`, split
  views; quickstarts rewritten as educational walkthroughs; ten new pages.
- README restructured around a 15-second demo GIF and stage graphics.

## 0.3.3 — 2026-10-11

Found by `examples/swarm/outside.py`: 1,000 concurrent agents in 18
personas against a 100-witness, four-operator network.

### Fixed — verification did not scale to a registry-sized directory

- `VerifyContext.min_receipts`, CLI `--min-witnesses N`, Python
  `verify_dossier_json(..., min_witnesses=)`, MCP `min_witnesses`: an
  absolute receipt-count gate. `--threshold` as a fraction of the directory
  meant 66 cosignatures per checkpoint against a 100-witness directory.
  `QuorumResult.count_gate` reports which gate applied; the CLI warns when
  a fraction is used against a directory of 16 or more.
- `select_diverse_witnesses` now picks, within each operator, the witness
  determined by the subject's identity key, so a thousand agents spread
  across an operator's witnesses instead of all choosing its first entry
  (which tripped enrollment rate limits and left most of the network idle).
  New `select_witnesses` (Rust and Python) fills to `want` round-robin
  after one per operator. The MCP `submit_to_witnesses` tool contacts at
  most `max_witnesses` (default 8) chosen this way instead of the whole
  directory.
- `witness submit` and the MCP client honour `Retry-After` up to 60 s on
  429/503 instead of giving up.

### Added

- `deploy/witness/fleet.py` (init/serve/status N witnesses on one host),
  `witness-log-witness@.service` template, `AGENT_OPERATOR.md` (a playbook
  an agent can execute end to end on free always-on compute).
- `registry/`: the public witness list, PR-registered, validated in CI
  (`validate.py`), with `build_directory.py` for verifiers.
- `examples/swarm/outside.py` and the 1,000-agent reports.

### Removed

- `crates/witness-log-network/examples/agent_witness.rs` (a pre-protocol
  sketch superseded by `witness serve` / `WitnessService`).

### Compatibility

`VerifyContext` gained a field; code constructing it with a struct literal
adds `min_receipts: None` or uses `..Default::default()`. No wire-format
change.

## 0.3.2 — 2026-10-10

Found by four independent integrators (Rust service, Python agent loop,
witness operator, auditor) using only the public 0.3.1 release, and by
the 100-scenario swarm in `examples/swarm`. No wire-format change: every
0.3.1 dossier, journal, corpus vector and cosignature is accepted
unchanged.

### Fixed — redaction after a restart (high)

`forget()` returned `false` for every leaf written before the last
process restart on the journal path, because salts lived only in memory.
`JournaledLog` now persists salts in a `<journal>.salts` sidecar (one
record per payload leaf, `0600`); `forget` erases the salt from that file
by rewriting it (temp file, fsync, rename) before the 0x03 marker is
journaled, and `resume` reconciles the sidecar against the replayed tree.
Journals from 0.3.1 resume as before; only their pre-0.3.2 leaves have no
salt to forget. New: `JournaledLog::can_forget`, `WitnessLog::can_forget`,
`redaction::FileSaltStore`, `SaltStore::{sync, take_error}` (defaulted);
Python `JournaledLog.can_forget`.

### Fixed — a crashed agent could not resume without a human (high)

A journal lock left by a process that died (`kill -9`, OOM) required
`force_unlock`, which Python did not expose. On Linux `resume` now
recovers a lock whose recorded PID is no longer running (never one that
is live, never one it cannot read), confirms it still holds the lock
after a settle, and only ever deletes a lock file that still carries its
own PID. Python gains `JournaledLog.force_unlock(path)` for the other
platforms.

### Fixed — `evidence_window(0..u64::MAX)` hung the process (high)

The range was iterated element by element. It is clamped to the tree.

### Fixed — a journal could accept a leaf it could never replay

`append_external_anchor` with a proof over the 16 MiB line cap wrote a
line `replay` refuses, bricking the journal. The budget is checked before
the leaf enters the tree (`InvalidInput`), and `LeafJournal::append`
refuses an oversized line as a last resort.

### Fixed — empty payloads were not salted

`append_*(b"")` committed the all-zero hash, revealing which entries were
empty and leaving them unforgettable; SPEC §8 defines `payload_hash` for
the empty payload (vector 11). Only the marker types 0x03/0x04 commit the
zero hash now. SPEC §8 says so.

### Fixed — witness state could be inherited by the wrong key

`WitnessState` now records `witness_pubkey` (`bind`/`check_bound_to`);
the Python `WitnessService` refuses a state file bound to another key, and
`witness.json` records the key `init` generated so `serve` refuses a
swapped `witness.key`. A key restored without its `logs/` cannot be
detected by software: `deploy/witness/OPERATORS.md` and THREAT_MODEL.md
state the backup rule.

### Changed — `verify` output and report

- `DossierReport` gains `identity_pinned`, `internally_consistent` and
  `bindings_asserted`. `QuorumResult::operators_represented` is renamed
  `independent_operators_represented` (its contents were already the
  independent set; the old name is accepted on input).
- Text output now shows the key-binding check (the one failure that was
  invisible outside `--json`), names the gate that kept a verdict at
  CONSISTENT-UNWITNESSED (no directory receipts / count below threshold /
  fewer than two independent operators), distinguishes "identity bound to
  --identity" from "self-consistent, not pinned", and warns when a
  WITNESSED or CONSISTENT-UNWITNESSED verdict was reached without
  `--identity`. The UNANCHORED line no longer claims `--identity` was
  missing when it was supplied; the DIVERGED line no longer calls every
  failure tampering.
- `explain witnessed` / `consistent-unwitnessed` / `unanchored` /
  `diverged` now state the real rules: two distinct independent operators,
  `--directory` lifts the ceiling, `--identity` names the party.
- `--identity` must be 64 hex characters (usage error 2 otherwise);
  `--threshold` is likewise validated in Python (`ValueError`).
- `--directory` accepts a bare JSON array of entries as well as
  `{"witnesses": [...]}` (CLI `verify`, `witness submit`, Python).

### Added

- `witness-log --version`; `verify --help`; `witness <sub> --help`.
- `witness-log witness verify-evidence <file>`: check an equivocation
  proof from `evidence/` (exit 0 proven, 30 not).
- `witness-log c2sp show --raw` (body only, pipeable) and
  `--sign-with <journal>` (a signed note `c2sp verify` accepts); unknown
  flags on `c2sp show`/`verify` are errors; `c2sp verify` with only a
  witness key says the note itself is unverified.
- `witness init` warns when `--org` is omitted.
- `witness serve` stops cleanly on SIGTERM/SIGINT (finishes the in-flight
  decision, releases `witness.lock`, exits 0); the CLI no longer panics
  with a backtrace when its output pipe closes (`| head`).
- `deploy/witness/`: Dockerfile, docker-compose with TLS proxy, hardened
  systemd unit, `OPERATORS.md`.
- `examples/swarm/`: 100 named scenarios against the released CLI and
  wheel, with ten live witnesses; writes a JSON and Markdown report.
- Python type stubs (`_core.pyi`, `py.typed`) checked against the
  runtime surface by a test.
- SPEC §5 documents `custody` (unsigned, informational); the JSON Schema
  accepts all seven custody values. `crates/witness-log-network/README.md`
  describes the real witness protocol instead of the 0.2 pull model.
- rustdoc builds with `-D warnings` in CI (misattached and broken doc
  comments fixed).

## 0.3.1 — 2026-10-09

Found by running ten live witnesses (8 Rust, 2 Python) through ten
interaction scenarios over real sockets (`examples/live-network`).
**0.3.0 must not be used for witnessing.**

### Security — witnesses cosigned forks (critical)

`merkle::verify_consistency` rebuilt only the NEW root from a consistency
proof. When the old size was not a power of two the trusted old root was
never consulted, so any self-consistent fork that grew past such a size
verified. Live: all ten witnesses cosigned a forked history at 10 → 12
leaves. Every fork-detection path depended on this (witnesses,
`compare_checkpoints`, silence proofs). Replaced with RFC 9162 §2.1.4.2,
which rebuilds both roots. New exhaustive test: every `1 <= m < n <= 64`,
honest proofs accepted, forks at the first/middle/last old leaf rejected,
tampered/short/long proofs rejected; it fails against the old code at
m=3, n=4. Proof *generation* is unchanged; `/corpus` is byte-identical.

### Fixed — cosignatures from real witnesses never counted (critical)

`cosignature_to_receipt` produced receipts that `Dossier::verify`
re-checked against the native receipt message and silently dropped, so
no `tlog-witness` witness could ever produce WITNESSED. Receipts now carry
`c2sp_origin` and verify offline against the `cosignature/v1` message
(SPEC §9.3). Only the identity's canonical origin
`witness-log/<identity key hex>` counts, which also gives witnesses open
enrollment with no key exchange and stops an agent from showing different
forks to different witnesses under different names. Native receipts are
unchanged on the wire.

### Fixed — c2sp.org/tlog-witness conformance

- 409 body is now just the size and a newline, `Content-Type:
  text/x.tlog.size` (was `old <size>\n<root hex>`; real C2SP clients
  could not resync).
- Old size larger than the checkpoint is now 400 `StaleCheckpoint`, not a
  422 "misbehaviour evidence" accusation — a late-arriving genuine
  checkpoint (a client retry) looks identical. `AddCheckpointOutcome` is
  now `#[non_exhaustive]`.
- 422 for a proof sent from size 0, and for a size-0 checkpoint without
  the empty-tree root. More than 63 proof lines is rejected.
- 200 bodies end each cosignature line with a newline.

### Added — a runnable witness and client

- `witness-log witness init | serve | add-log | info | submit`. The server
  persists each new record (fsync, atomic rename, directory fsync) before
  releasing a cosignature and withholds it if that fails; one process per
  state directory (lock, stale-lock recovery on Unix); refused forks to
  `evidence/` (one self-contained proof per log); bounded headers, bodies, time, connections (total and
  per client address), enrollments and evidence size; `Retry-After` on
  429/503. Std-only HTTP, no new network dependencies.
- `WitnessService::{enroll_canonical, export_state, from_state,
  set_known_log, remove_log, log_count}`, `WitnessState`,
  `EquivocationProof`, `AddCheckpointOutcome::is_misbehaviour_evidence`
  narrowed to provable equivocation, `add_log` returns `bool`,
  `AddCheckpointOutcome::http_body`, `c2sp::{canonical_origin,
  identity_from_canonical_origin}`, `NoteSignature::parse` is public.
- Python: `WitnessService(name, seed, state_path=None,
  open_enrollment=False, max_logs=100000)` persists before cosigning and
  records fork evidence; `handle_add_checkpoint_http` returns the content
  type; `log.canonical_origin()`, `log.add_checkpoint_body(old_size)`,
  `log.dossier_from_responses(...)` give Python agents the whole client
  side.
- `examples/live-network`: the ten-witness, ten-scenario pressure test.
- CI integration test running real witness processes on all three OSes;
  fuzz target `fuzz_witness_request`.

### Fixed — independent security review of the above (not in any release)

- `WitnessService::add_log` on an already-known log reset it to size 0;
  a startup script that reloads state and then re-adds its logs would
  then cosign a fork (confirmed: 200 for a fork after restart). It now
  refuses and returns `false`.
- Any failed consistency proof was treated as "misbehaviour evidence", so
  anyone could relay an honest log's checkpoint with a junk proof and get
  it recorded as a fork (and fill the evidence cap so real evidence was
  dropped). Evidence is now only provable equivocation: `ConsistencyFailed
  { equivocation: Some(EquivocationProof) }`, two log-signed notes for one
  size, checkable with `EquivocationProof::verify`. Witnesses keep the
  last log-signed note they cosigned (`KnownLog::checkpoint_note`).
- Python witness: single-writer lock on the state file; a missing state
  file is an error (`WitnessService.create_state(path)` creates one);
  key names validated; temp files 0600; `add_log` persists.
- Server: refuses to start with a missing state directory; re-checks it
  still holds its lock before every cosignature; stale-lock removal only
  if the file still names the dead pid; IPv6 clients keyed by /64;
  slowloris bound is now exactly the 10 s deadline; bare CR/LF inside a
  header line is rejected; chunk-size overflow in the client is an error.
- Re-review: checkpoint bodies over 1 KiB are refused (stored notes and
  proofs stay small; was up to 64 KiB per log), evidence is one file per
  log in `evidence/` so it can never crowd out other logs', lock takeover
  settles 250 ms and re-checks ownership before loading state, and
  `witness submit` refuses to publish a journal that contradicts what
  witnesses already cosigned for the identity (an honest agent restoring
  an old backup would otherwise be recorded as equivocating).

### Fixed — final pre-publish review (independent, whole codebase)

Three ways to produce a **false accusation**, closed:

- `witness-log diff` reported EQUIVOCATION for an honest copy plus a copy
  whose leaves had been edited after signing (it checked both signatures
  but never that each copy's leaves reproduce its own root). Anyone with
  one honest copy could frame the log. Both copies must now be
  internally consistent before divergence is called equivocation;
  otherwise the tampered copy is named.
- `compare_checkpoints` returned `Diverged` ("equivocation") without
  verifying either signature. New `CheckpointRelation::InvalidSignature`.
- `silence_proof` took a plain checkpoint as the "write receipt", which
  commits to no event, so any payload hash could be "proven" censored
  against any witnessed log. New `WriteReceipt` (signed by the log
  identity over the payload hash, size and time; `WitnessLog::
  write_receipt(index)` issues one) is now required, and tampered or
  foreign receipts prove nothing.

Also:

- `c2sp verify` exited 0 with a forged cosignature from a `--vkey` the
  caller supplied (printed FAILED, ignored for the verdict). Known-key
  cosignature failures now fail the gate; such lines are no longer
  counted as "unknown keys ignored".
- `verify_inclusion` accepted leaf indices outside the tree (RFC 9162
  §2.1.3.2 step 1).
- Journal resume computed `header + 1` for every resume, so sessions
  after the first all shared number 1; now one past the highest bound.
  Three `+ 1` sites that could panic in debug builds at `u64::MAX`
  (no-panic contract) are saturating.
- Witness server: a 422 on first contact left a phantom in-memory
  enrollment counting toward `--max-logs`.
- Exit code for unreadable/unparsable input is 2 as documented (was 1).
- SPEC §8 described a different `bucket_pad` than the code computes (a
  spec-following reimplementation would have produced different
  `payload_hash`es and nothing in the corpus caught it). Spec corrected;
  new corpus vector `11_payload_hash.json` pins the function, verified
  by an independent reimplementation from the spec text.
- SPEC §9.2 and the `Verdict` docs described the old ≥50%-diversity gate;
  the code requires ≥2 independent operators. Docs corrected.
- `--explain` claimed timestamps are checked for order; they are not.
  README Python example used `WitnessService(...)` instead of `.new`.
  `--help` named `evidence.jsonl`; evidence lives in `evidence/`.

### Fixed — journal resume failed on Windows (first CI run)

`LeafJournal::open_for_append` reopened the journal append-only and then
called `set_len` to heal a torn tail; on Windows an append-only handle
cannot truncate, so every `JournaledLog::resume` failed with "Access is
denied" (7 tests, all the same cause). The journal is now opened for
write and positioned at the end; the lock already guarantees a single
writer. CI no longer cancels the other platforms when one fails.

### Packaging and release (publish-readiness pass)

- Every crate and the Python wheel/sdist now ship the AGPL `LICENSE` text
  (none did); crates.io README, keywords and categories added; Python
  metadata uses PEP 639 (`License-Expression`, embedded license file) and
  passes `twine check`.
- `release.yml`: on a `v*` tag, builds abi3 wheels (manylinux x86_64 and
  aarch64, musllinux, macOS Intel and Apple Silicon, Windows) and an sdist,
  publishes to PyPI via Trusted Publishing, and attaches CLI binaries and
  `SHA256SUMS` to a GitHub Release. A locally built wheel is
  `manylinux_2_34` and would not install on older Linux; CI builds portable
  ones. `RELEASING.md` has the exact publish order.
- Fixed a timing-dependent test that failed in `--release` (two
  checkpoints signed in the same millisecond correctly compare as
  `Unproven`, not `Rollback`; the test assumed different timestamps).
- README install instructions point at crates.io / PyPI / release binaries.

### Found and fixed during the live run (not in any release)

Enrollment rate limit of 30/min/address blocked 50 agents behind one
address (now 600, configurable); an open-enrollment witness answered a
forged canonical-origin signature with 404 instead of 403; the accept loop
would spin on EMFILE; one client could occupy every connection slot with
idle sockets; fork evidence was unbounded; the reference Python witness's
listen backlog (5) refused connections from 50 concurrent agents.

## 0.3.0 — 2026-10-08 (superseded: do not use for witnessing)

First tagged release. **Breaking:** `JournaledLog::create(path, identity)` now takes the identity (the old one-argument form silently generated a throwaway key); use `create_ephemeral(path)` for the old behaviour. `create_with_identity` is deprecated.

### Fixed — launch-blocking packaging and CI defects

- **Python bindings: PyO3 0.20 → 0.29, built as abi3 (stable ABI).** 0.20
  refused to build on Python 3.13+ and was affected by RUSTSEC-2025-0020
  and RUSTSEC-2026-0177. One wheel now serves every CPython ≥ 3.9.
  Binding objects are now safe to share across Python threads (inner
  state behind a mutex); 8 threads × 500 appends lands exactly 4,000
  leaves. `requires-python` is now `>=3.9`.
- **CI would have failed on first push:** cargo-deny rejected the
  project's own AGPL-3.0 license and `unicode-ident`'s Unicode-3.0;
  Rust 1.97 clippy flagged `cloned_ref_to_slice_refs`; the fuzz crate
  could not build (Cargo workspace conflict). All fixed and verified
  locally with the same tool versions CI uses.
- CI now tests Python 3.9 and 3.13 and runs cargo-deny on the Python
  crate's separate dependency tree too.
- Inter-crate path dependencies now carry versions, so
  `cargo publish` of `witness-log-network` / `witness-log-cli` is accepted.
- Journal deletion/replacement tests are Unix-only (Windows cannot delete
  an open file and has no inode to compare).

### Fixed — `compare_checkpoints` made false rollback accusations

Ordering two checkpoints by timestamp alone made the verdict depend on
argument order whenever they shared a millisecond — routine for an agent
that appends and checkpoints quickly. `compare(small, big)` returned
`Unproven`; `compare(big, small)` returned `Rollback`. A rollback verdict
is an accusation, so this is the most serious kind of false positive.
Now orders by `(timestamp, tree_size)`, since logs only grow; a property
test asserts every relation is symmetric. Found while evaluating whether
same-timestamp checkpoints should be flagged as a rewrite tell — they
shouldn't, and the investigation turned up the real bug instead.

### Fixed — deleting a journal under a live process lost writes silently

On Unix an open handle to a deleted or replaced file keeps writing to an
unlinked inode, and every append is lost when the process exits.
`sync()` now re-checks that the path still names the file it opened
(device + inode on Unix) and fails loudly if not. Detection, not
prevention — but it turns silent loss of audit data into an error at the
exact point the caller asked for durability.

### Documented — concurrency and session numbers

`WitnessLog` is `Send` but not `Sync`; share it with
`Arc<Mutex<WitnessLog>>`. `session_number` on raw `resume` is
caller-managed and unenforced.

### Deliberately not fixed

Two review findings were evaluated and rejected because fixing them
would make the product worse: rejecting a witness receipt timestamped
before its checkpoint (routine clock skew between witness and log), and
rejecting duplicate leaves (agents legitimately repeat actions). Every
false-accusation bug this project has had came from treating an honest
but unusual condition as tampering.


### Fixed — double-resume corrupted the journal (HIGH)

Two live handles on one journal both appended, interleaving two sessions'
leaves with conflicting indices. A supervisor restarting a
crashed-but-not-dead process would hit this. Journals now take an
exclusive `O_EXCL` sidecar lock; a second open fails with
`AlreadyExists` and a clear message. `JournaledLog::force_unlock`
recovers from a stale lock after a hard crash — explicit, because
silently stealing a lock is how two processes end up writing one file.

### Added — regulator-facing evidence APIs

Found by a three-perspective review (skeptic / integrator / regulator,
ten scenarios each). The regulator's most common requests had no direct
API:

- `WitnessLog::inclusion_proof(index)` — "prove this one action was
  logged." Was: rebuild the Merkle tree by hand.
- `WitnessLog::consistency_proof(earlier_size)` — "prove nothing was
  deleted between these two checkpoints."
- `WitnessLog::evidence_window(range, key)` — "show me Q3 only." A
  verifiable partial export: every leaf in the window proven against the
  full signed checkpoint, nothing outside it disclosed. `verify()` names
  any tampered entry by index. Previously a windowed request yielded
  either over-disclosure or a non-verifiable subset.
- `compare_checkpoints(a, b, proof)` → `Extends | Identical | Rollback |
  Diverged | Unproven | DifferentIdentity`. Rollback detection from two
  dossiers was by hand.
- `QuorumResult::operators_represented` — WHICH operators cosigned, not
  just how many.

### Three-perspective findings recorded, not fixed

- A witness receipt timestamped before its checkpoint is accepted. Both
  timestamps are self-asserted so there is no ground truth, but it is
  worth surfacing.
- Two checkpoints from one key at one timestamp with different sizes is
  a rewrite tell that nothing flags.
- Deleting a journal under a live Unix process loses writes silently;
  not fixable in-library.
- `WitnessLog` is `Send` but not `Sync` (correct) and `session_number`
  is caller-managed on raw `resume` — both undocumented.
- Duplicate leaves with corrected indices verify. Not a bug: agents can
  legitimately repeat an action.

Every skeptic attack — receipt replay, reordering, truncation,
revocation bypass, foreign bindings, cross-log leaf mixing, tombstone
tampering, inflated tree size — was caught.


### Breaking — `JournaledLog::create` now takes the identity

`create(path)` used to invent an identity internally with no way to
supply your own. Nothing failed; the resulting dossiers simply belonged
to a key nobody chose and nobody could reproduce. The 1,000-agent cohort
hit this on every crash-restart agent. The constructor whose name
newcomers reach for now does the right thing: `create(path, identity)`.
The bare form is `create_ephemeral(path)`, named for what it does.
`create_with_identity` is deprecated and delegates to `create`.

### Added — `WitnessEntry::independent` / `::project_operated`

Building a `WitnessEntry` by hand puts `is_project_operated: false` into
every copied example — the one field whose honesty the entire diversity
model depends on. Newcomers should be choosing a constructor whose name
says what they're declaring, not typing a boolean they don't understand.

### Python bindings brought to parity

The bindings were four sessions behind and exposed none of: journaling
(so Python users had the restart-as-forgery bug with no fix available),
C2SP, witness selection, the `tlog-witness` transport, or the honest
`WitnessEntry` constructors. Most agents are Python; this was the one
genuine launch blocker.

Added: `JournaledLog` (create/create_ephemeral/resume/append_*/forget/
sync/to_dossier_json, all with binding history correct across restarts),
`WitnessService` (full `tlog-witness` service: add_log,
handle_add_checkpoint returning `(http_status, body)`),
`select_diverse_witnesses`, `witness_entry_independent`,
`witness_entry_project_operated`, and on both log classes
`c2sp_checkpoint_text`, `sign_c2sp_checkpoint`, `c2sp_vkey`,
`all_bindings_json`. A pytest exercises the whole surface including a
Python `WitnessService` refusing an equivocating log with HTTP 422.

Also fixed a leftover from the project rename: the `ContinuityError`
exception's `__module__` was the hyphenated `witness-log` rather than
`witness_log`.


### Fixed — a restarted agent was reported as a forger (CRITICAL)

Resuming a log mints a NEW session key, but leaves written before the
restart were signed by the OLD one — and session keys are ephemeral and
never persisted. A dossier carrying only `current_binding()` therefore
left every pre-restart leaf uncovered, and verification returned
`Diverged`: *"evidence of tampering"* for an agent that merely rebooted.

This was previously documented as a "known limitation" of
`Dossier::key_bindings`. The 1,000-agent cohort showed what the
limitation actually meant: **10% of the cohort followed a crash-restart
profile and 100% of them were flagged as forged.** Restart is normal, not
exceptional.

- `WitnessLog::all_bindings()` returns the full binding history; this,
  not `current_binding()`, is what a dossier should carry
- Binding history is persisted across snapshots (`LogSnapshot.key_bindings`,
  `serde(default)` so older snapshots still load) and across journal
  replays (a new untagged `JournalRecord::Binding` line — leaf lines keep
  their exact existing shape, so older journals replay unchanged)
- Every dossier builder in the tree now uses `all_bindings()`

### Fixed — an operator witnessing itself counted as independence

200 witnesses all run by `hyperscale-a`, cosigning an agent *also* run by
`hyperscale-a`, scored a nonzero independent-operator count. It failed to
reach `Witnessed` only because the floor is 2 — an operator with two
sub-brands would have cleared it. `evaluate_quorum` now excludes
witnesses sharing the subject log's operator from the independence count.
Self-attestation is not independence, however many keys it holds.

### Added — `JournaledLog::create_with_identity`

`create()` calls `WitnessLog::new()`, which generates its own identity,
and offered no way to supply your own. So the documented model — a
long-lived identity, generated once and persisted as a seed — was
**incompatible with the main persistence path**: any dossier built from a
journaled log was attributed to an identity the caller never chose and
could not reproduce. Found when the cohort's crash-restart agents failed
identity binding for exactly this reason.

### Added — 1,000-agent cohort simulation

`crates/witness-log-network/tests/cohort_1000.rs`, built to surface
product-viability problems rather than crashes. Realistic conditions:
a power-law operator distribution (3 hyperscalers run 50% of agents, a
195-operator long tail runs the rest), five behavior profiles (chatty,
sparse, crash-restart, heavy-checkpoint, 16KB-payload), clock skew, and
single-operator collusion at scale.

Headline result, and a documentation gap worth acting on: **naive witness
selection (nearest peers) reaches the independence floor only ~53-62% of
the time; operator-aware selection reaches 100%.** Under a power-law
distribution, neighbouring agents frequently share an operator. Witness
selection must be operator-aware or `WITNESSED` is unreliable in
production — this needs to be documented guidance, not something each
integrator rediscovers.


### Fixed — Sybil vector in operator diversity (CRITICAL)

Operator and compute-provider labels were compared as raw strings, so
case and whitespace variants of one name counted as separate operators.
Because `distinct_independent_operators` gates `Verdict::Witnessed`, this
was the cheapest possible attack on the entire trust model: **no
cryptography, no extra infrastructure, just the shift key.**

Measured before the fix: **100 witnesses run by a single operator,
labeled with case and whitespace variants of one name, scored as SEVEN
independent operators** — a 7x inflation of the security parameter, and
enough to clear `production()`'s 3-operator bar with one party.

Labels are now normalized for bucketing (trim, lowercase, collapse
internal whitespace runs) on both diversity axes and, critically, in the
set that gates the verdict. Normalization is deliberately conservative:
over-collapsing would be worse than the bug, because it would silently
merge genuinely independent operators. A test asserts five similar but
distinct names (`acme-corp`, `acme-corporation`, `acmecorp`, …) still
count as five.

**Known limitation, documented not solved:** Unicode homoglyphs. A
Cyrillic "а" in "аcme" is a different codepoint and still buckets
separately. Defending that needs a UTS #39 confusables table — a
dependency and maintenance commitment not taken on here. Directory
curators should treat visually-identical operator names from different
parties as a review item.

### Fixed — memory documentation was a 2.5x under-estimate

The integration contract claimed "~200 bytes per leaf", reasoning from
the two 64-character hex strings each `Leaf` carries. **Measured: ~500
bytes per leaf**, stable and linear from 25k to 200k leaves. The derived
figure ignored `String` headers, `Option` fields, `Vec` capacity slack,
and allocator overhead. Anyone sizing a deployment from the old number
would have under-provisioned by more than half. Corrected to the measured
value, with a soak test that fails if it drifts by an order of magnitude.

### Added — Sybil and soak test suites

`crates/witness-log-network/tests/sybil_and_soak.rs` (9 tests):

- Sybil resistance: case variants, whitespace variants, internal
  whitespace, compute-provider variants, a 100-witness single-operator
  fleet, project-operated collapse under label manipulation, and a
  guard that genuinely distinct operators are NOT over-collapsed
- Soak: 200,000 leaves with periodic checkpointing, asserting that both
  memory and per-leaf time stay linear (measured 0.94x per-leaf cost
  ratio end-to-start) and that a 200k-leaf log still verifies its own
  continuity
- Checkpoint cost independence: 100x more leaves must cost well under
  10x per checkpoint — the direct assertion of the O(log n) root
  property, where an O(n) regression would show as ~100x


### Fixed — witness diversity did not scale (found by 100-agent simulation)

`Verdict::Witnessed` required `diversity_fraction >= 0.5`, where the
denominator is every distinct operator in the trusted directory. That
made a **larger witness network harder to verify against**: at 1,000
known operators the rule demanded 500 cosignatures on a single
checkpoint. The metric punished exactly the network growth the project
is trying to cause.

Found by a new 100-agent concurrent fleet simulation. Five genuinely
independent operators cosigned a checkpoint and scored 5/12 = 0.42, so
**zero of 100 agents could reach WITNESSED**. Every prior unit test used
3–4 witness directories where 3/4 = 75% passed trivially, so nothing
smaller than fleet scale would have surfaced it.

- `QuorumResult::distinct_independent_operators` added: the absolute
  count of distinct non-project-operated operators. This is what
  actually delivers equivocation resistance, and its meaning does not
  change as the network grows.
- The verdict now gates on that count (`MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED
  = 2` — the floor at which equivocation is detectable at all, since a
  single operator cannot contradict itself).
- `WitnessPolicy::min_independent_operators` added; `production()` sets
  it to 3 and drops `min_operator_diversity` to 0.0, since 0.66 was
  unreachable on any network of meaningful size.
- `diversity_fraction` is still reported — it is a useful *coverage*
  measure over a small, fixed, known witness set — but is documented as
  unsuitable for gating, and the policy error message says so.

After the fix: 100 of 100 agents reach WITNESSED. A regression test pins
verdict stability across directory sizes from 4 to 4,000.

### Added — 100-agent fleet simulation

`crates/witness-log-network/tests/agent_fleet_simulation.rs`. Real OS
threads, five phases, invariant violations collected rather than fatal so
one failure doesn't mask the rest:

1. Concurrent construction of 100 agents x 20 actions (~17ms)
2. 100 cross-agent handoffs, each verified to bind — and verified NOT to
   bind when attributed to the wrong counterparty
3. Reciprocal witness mesh: every agent cosigns 5 peers (500 receipts, ~29ms)
4. All 100 dossiers verified, both unanchored and anchored, with quorum
   arithmetic bounds-checked (~61ms)
5. Adversaries inside the fleet: impersonation, self-authored witness
   directories, cross-fleet receipt replay, and a genuine equivocating
   fork — all producing cryptographically *valid* artifacts that lie


### C2SP transparency-log interoperability

New `witness_log_core::c2sp` module implementing `c2sp.org/signed-note`,
`c2sp.org/tlog-checkpoint`, and `c2sp.org/tlog-cosignature` (v1), so that
witnesses already running in the Certificate Transparency ecosystem can
cosign WitnessLog checkpoints without implementing anything
WitnessLog-specific. This is the answer to the witness cold-start
problem: inherit an installed base rather than recruit one from zero.

Conformance is verified against the specs' **own published example
vectors** — the implementation parses the spec's signed note, verifies it
against the spec's verifier key, re-encodes it byte-for-byte, and
independently recomputes the spec's key ID from its public key. Those
tests prove interoperability against bytes this project did not produce,
which round-trip tests cannot.

Documented normatively in SPEC.md §9.3, including the consequence that a
C2SP checkpoint carries no timestamp: time comes only from cosigners, so
a log structurally cannot assert its own.

### Performance

`MerkleTree` now maintains an incremental right spine. `root()` was O(n)
— it rehashed the entire tree on every call — making `checkpoint()` O(n)
and a log that checkpoints per leaf O(n²) overall. Measured on this
machine:

- append + checkpoint every leaf: 1K → 10K → 100K leaves now costs
  0.71ms → 8.5ms → 106ms (linear, was quadratic)
- `root()` on a **million-leaf tree: 696 nanoseconds**, previously ~1M
  SHA-256 operations per call

All 9 corpus vectors are byte-identical after the rewrite, and a
reference-oracle test validates the incremental root against the original
recursive implementation at every size from 1 to 200 plus every
power-of-two boundary through 1025. A separate test asserts the spine
stays logarithmic, so a regression to linear behaviour fails the build
rather than silently degrading.

### Integration contract

`witness-log-core` now states and enforces what it promises to the
process it is embedded in: no panics on explicit panic paths (`unwrap`,
`expect`, `panic!`, `todo!`, `unimplemented!` denied at compile time in
non-test code, and none present), `append` never touches disk or network,
`checkpoint` is O(log n), no background threads or ambient state.

Honestly scoped: `clippy::indexing_slicing` and
`clippy::arithmetic_side_effects` would currently fail this crate and are
listed as commented-out with an explanation, not silently omitted. Slice
indexing and unchecked arithmetic remain real panic surfaces. Enabling
those lints requires auditing every index and arithmetic site — contained
work, not yet done.

### C2SP wired end to end

- Corpus vector `10_c2sp_checkpoint.json`: a WitnessLog checkpoint as a
  C2SP signed note plus a witness cosignature, deterministic from the
  fixed seed. The generator verifies every signature before writing, so a
  broken generator cannot emit a corpus that merely looks right. Included
  in `witness-log conform`, so C2SP conformance is now part of the
  interoperability gate rather than a library detail. Note the vector's
  `log_vkey` contains `+` characters in its base64 payload — the exact
  shape that broke the original parser, now permanently pinned.
- `witness-log c2sp show` renders a dossier's checkpoint as a C2SP
  checkpoint body and derives the log's verifier key. Never touches
  private keys; signing stays in the process that holds them.
- `witness-log c2sp verify` verifies signed notes and cosignatures
  against supplied verifier keys, reports how many unknown-key signatures
  were ignored (and why that's correct), and refuses to run with no
  `--vkey` at all — a note verified against no keys proves nothing.

### Integration contract hardened

`clippy::indexing_slicing` is now **enabled**, not aspirational. Every
slice-indexing site in library code was converted to a checked slice
pattern or `get`, including routing all seven `JournaledLog` append paths
through a single checked lookup. Out-of-bounds access is now a
compile-time impossibility rather than a runtime risk.

`clippy::arithmetic_side_effects` remains off, documented, with the
reason stated: unchecked arithmetic is pervasive in index and tree-size
computation, and converting it is invasive work that has not been audited
here. The gap is named rather than hidden.

Added: explicit memory budgeting (~200 bytes per leaf, ~200 MB at a
million leaves, with `JournaledLog` as the long-lived path) and async
guidance — nothing here is `async` and nothing needs to be, except
`sync()`, which fsyncs and belongs in `spawn_blocking`.

### Fixed

- **C2SP verifier keys failed to parse for roughly 60% of real keys.**
  `+` is both the vkey field separator and a member of the standard
  base64 alphabet, and the parser split from the right — cutting into the
  base64 payload whenever it contained a `+`. Caught only because the
  verification pass ran the suite twice with fresh random keys; a single
  run passes ~40% of the time. Now splits from the left at exactly two
  separators, which is unambiguous because the spec guarantees the name
  and key ID are separator-free. Regression covered by a deterministic
  fixture (random keys were the bug's disguise) plus a 200-sample sweep.


### New commands

- **`witness-log demo`** — a zero-argument, self-contained walkthrough:
  builds a log, redacts a leaf, signs a checkpoint, gathers witnesses,
  then verifies the same bytes twice to show what changes when
  verification is anchored to something outside the file. Runs entirely
  in memory; writes nothing to disk and makes no network calls (there's
  a test asserting the empty-working-directory property, since the demo
  generates real keypairs).
- **`witness-log demo --tamper`** — builds a genuinely convincing forgery
  (attacker's own key, invented history, victim's pubkey on the label,
  self-generated "auditors", own witness directory) and shows it failing
  on identity binding despite flawless cryptography.
- **`witness-log diff <a> <b>`** — the equivocation check. Compares two
  copies of one log and reports the first divergent leaf. This closes a
  real gap: detecting equivocation is the reason witnesses exist, and
  until now there was no command for it. Deliberately refuses to cry
  wolf — two independent logs recording identical content diverge at
  leaf 0 because payload hashes are salted per instance, and that case is
  detected and explained rather than reported as a finding.
- **`witness-log explain [verdict] [--json]`** — verdict semantics as a
  queryable command, including what each verdict does NOT prove. The
  `--json` form exists so an agent that hits an unexpected verdict can
  ask why programmatically instead of fetching documentation.

### Changed

- **Exit codes are now semantic**: the verdict IS the exit status
  (`0` WITNESSED, `10` CONSISTENT-UNWITNESSED, `20` UNANCHORED,
  `30` DIVERGED, `2` usage). Gating on verification no longer requires
  parsing JSON. Codes are spaced by 10 so intermediate states can be
  added later without renumbering anything a caller depends on.
- **Progressive disclosure**: an `UNANCHORED` result now prints the exact
  anchored command to run next, with the identity filled in — and says
  plainly that reading the identity out of the dossier is fine for trying
  it out but proves nothing in real use.
- Bare `witness-log` with no arguments points at the demo rather than
  dumping usage text.
- Unrecognized flags and extra positional arguments are rejected by every
  subcommand rather than being silently ignored.

### Fixed

- `explain --json` with no topic returned nothing, because `--json` was
  being consumed as the topic name. Flags are no longer parsed as
  positional arguments — the same bug class an earlier review caught in
  `verify`, which recurred in new code and now has permanent test
  coverage.
- Diversity percentages in demo output read as self-contradictory
  ("100% diversity" printed directly above "1 of these is
  project-operated"). Both numbers were correct — the project bucket
  collapses on both sides of the fraction — but the presentation invited
  a misread, which in a security tool is a wrong trust decision. Now
  shows the collapsed bucket counts explicitly.
- `witness-log diff` printed "Leaves 0–0: identical" immediately before
  "Leaf 0: DIVERGENT".

### Notes

- Restoring from a snapshot and re-appending the same content produces a
  genuine cryptographic fork, because salts are excluded from snapshots
  by design (so a restore fails toward "can no longer redact" rather than
  toward exposure). Two branches that redo the same work will therefore
  sign different roots at the same tree size — which `diff` correctly
  reports as equivocation. This is an operational hazard worth knowing
  about: prefer the journal over snapshot-and-redo for long-lived logs.
  Pinned by a test.

## 0.2.0 — wire-format break, post-external-review remediation

**Breaking wire-format change.** A dossier, snapshot, or journal produced
by 0.1.0 will not verify against 0.2.0, and vice versa. There is no
migration path — 0.1.0 was never publicly released with real user data,
so this is treated as a clean break rather than something requiring
compatibility shims. Every change below is reflected in `spec/SPEC.md`
(now versioned to match) and in the regenerated `/corpus/*.json`.

### Wire format

- **Leaf encoding (SPEC §3)**: every variable-length field is now
  length-prefixed (4-byte BE count), and every optional field — including
  the handoff/authorization/anchor fields — is preceded by an explicit
  presence byte. Previously, adjacent unprefixed fields could concatenate
  ambiguously (two structurally different leaves could hash identically),
  and an unconditionally-assumed-present field contributed zero bytes
  when actually absent.
- **Checkpoint signing (SPEC §6)**: the signed message now includes
  `sig_alg` and `signer_pubkey` (domain separator bumped `-v1` → `-v2`).
  Previously neither was covered by the signature, leaving the
  crypto-agility algorithm selector itself unauthenticated.
- **Witness receipts (SPEC §7)**: the signed message now includes
  `witness_pubkey` and the log's own `signer_pubkey` (domain separator
  bumped `-v1` → `-v2`). Previously a receipt attested only to
  `(tree_size, root_hash, witnessed_at_ms)` with no cryptographic
  statement about who witnessed it or whose log it was.
- **Key binding (SPEC §5)**: the spec text now matches what the
  implementation always emitted — a presence byte before the optional
  `not_after_ms` field.
- **New leaf type**: `ExternalAnchor` (0x07) — commits
  `anchor_proof_hash = SHA256(anchor_proof_json)`, not just the anchor
  URL. See SPEC §3.3.
- **Dossier shape (SPEC §9)**: gained optional `key_bindings` and
  `revocations` fields.

### Trust model

- `Dossier::verify` now takes a `VerifyContext`. A dossier's own embedded
  `identity_pubkey` and `witness_directory` are never sufficient on their
  own to reach the `Witnessed` verdict — a verifier must supply
  `expected_identity_pubkey` and/or `trusted_directory` from outside the
  artifact under test. See SPEC §9.1 and `THREAT_MODEL.md`.
- Introduced the four-valued verdict (`Witnessed` / `ConsistentUnwitnessed`
  / `Unanchored` / `Diverged`), replacing a binary verified/failed result.
  See SPEC §9.2.
- Witness receipts are deduplicated by key before counting, and only
  count when the key is present in the caller's trusted directory.

### Correctness

- Leaf structural validation (`validate_sequence`) now runs on every
  ingest path — dossier verification, snapshot loading, and journal
  replay — not dossier verification alone.
- `WitnessLog::append` clamps `timestamp_ms` to be non-decreasing at
  write time. `validate_sequence` no longer treats a non-monotonic
  timestamp as a hard verification failure at all — timestamps are
  self-asserted metadata (see `THREAT_MODEL.md`), and a wall clock
  stepping backward (NTP correction, VM live-migration, suspend/resume)
  must never classify an honest log as tampered.
- Merkle inclusion proofs now require the full proof slice consumed in
  both directions, closing a malleability gap where extra leading
  elements were silently ignored.
- `u64` tree sizes and indices are no longer truncated through `usize` on
  32-bit targets.
- `silence_proof` now counts distinct, correctly-attributed witnessed
  checkpoints — not receipts, not duplicate observations of the same
  checkpoint, and not checkpoints from an unrelated log.
- Journal replay physically truncates a torn tail write before further
  appends, rather than leaving it in place to be overwritten or
  permanently misread as mid-file corruption.
- Snapshot and journal files are created at `0600`, not the default
  `0644`.

### Repository

- `SECURITY.md` added.
- CI gained clippy, rustfmt, MSRV, and release-mode test jobs.
- Fuzz coverage extended to the Merkle proof verifiers and the CLI render
  path.
- Full remediation of two rounds of external security review — see
  `crates/witness-log-network/tests/review_regressions.rs` and
  `review_regressions_round2.rs` for the regression suite each round
  produced.

## 0.1.0

Initial internal draft. Not publicly released.
