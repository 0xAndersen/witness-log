# Security review, round 2: core and the verify path (2026-10-12)

An adversarial read of the in-scope code by a reviewer who had not seen it
written, against `docs/SECURITY-AUDIT-BRIEF.md`. Every finding carried a
test that asserted the defect as it stood; the fixes in 0.4.2 flipped
those tests (`crates/witness-log-core/tests/review_round2.rs`,
`crates/witness-log-network/tests/review_round2.rs`), so each one is
pinned. Disposition per finding:

| id | severity | disposition in 0.4.2 |
|---|---|---|
| J1 | high | fixed: records are one write; an unterminated last record is kept and terminated on open |
| J2 | medium | fixed: same for the salt sidecar |
| W1 | medium | fixed: `EquivocationProof::verify` takes the key from the canonical origin; `verify_with_key` and `verify-evidence --vkey` for other origins |
| W2 | medium (design) | fixed in part: checkpoint timestamp under the cut-off; `VerifyContext::revocations` / `verify --revocations`; index cut-off is RFC-0005 |
| R1 | low | fixed for ExternalAnchor (forget refused; SPEC §8); handoff/authorization hashes documented as the commitment |
| L1 | low | fixed: inapplicable fields rejected by the Rust, Go and TypeScript verifiers (SPEC §2) |
| L2 | low | fixed: marker hash and redaction target checked |
| J3 | low | fixed: a tear inside a multi-byte character is healed |
| W3 | low | fixed: canonical `old <size>` |
| C1 | info | accepted as is (the log's own signature covers the bytes) |
| C2 | info | fixed: empty signature refused |
| I1, M1 | info | documented; pinned by tests |
| P1 | plausible → confirmed | fixed in 0.4.3: a failed journal or salt write rolls the leaf back out of memory and cuts the partial record off the file; journaled `forget` writes the tombstone first and erases second, so a failure changes nothing or leaves a recorded erasure resume completes; an injected short write proves it (`failed_append_tests`) |
| P2, P3 | plausible | documented limitations |

The review as delivered follows.

---


## Scope

Reviewed against `docs/SECURITY-AUDIT-BRIEF.md` (0.4.1 tree, 2026-10-12): `crates/witness-log-core/src/{leaf,merkle,sth,identity,redaction,journal,c2sp,log}.rs` and `crates/witness-log-network/src/{lib,tlog_witness}.rs`, read in full with adversarial intent, plus `cli/src/witness_cmd.rs` lines 130-166 to confirm how one finding is consumed. Approximately 10,500 lines read (4,500 non-test per the brief; the remainder is in-file test modules, which were also used to learn the API). Both existing suites were run first and pass. No source file was modified. Every finding below has a test in `crates/witness-log-core/tests/review_round2.rs` or `crates/witness-log-network/tests/review_round2.rs` (`cargo test -p <crate> --test review_round2`, 14 + 10 tests, all green) that asserts the defective behaviour as it stands today, so a fix flips the test. Findings I could not confirm are labelled *plausible* with the reason.

## Findings, by severity

### J1 — HIGH — Torn trailing newline is accepted as a good line; the next write merges onto it, and the following resume drops a committed leaf or refuses the journal

- **Where:** `core/src/journal.rs:85` (`read_bounded_line`: "EOF without a trailing newline -- return what we have"), `:641-643` (line counted as good, `good_byte_length = offset`), `:390-401` (`open_for_append` seeks to end without re-terminating), `:441` and `:467` (`writeln!` on an unbuffered `File`).
- **Mechanism:** `writeln!(file, "{line}")` on a `File` issues two `write(2)` calls (verified with strace: the body, then `"\n"`). A crash between them, or a power loss that persists the first page write but not the second, leaves a complete JSON line with no newline. Replay parses it, reports zero torn lines and sets `good_byte_length` to the file length. `finish_resume` then appends the new session's binding record directly after the closing brace: `{leaf N}{binding}\n`. On the next replay that merged line is unparsable. If it is the last line it is "healed" away, taking leaf N (which two sessions held in their tree and may have checkpointed and had witnessed) with it; the log silently resumes at N-1 and will fork at index N. If anything was appended after it, replay fails with "corrupted beyond a single torn tail write" and the journal is unrecoverable by the tool.
- **Attacker / failure gain:** no attacker needed. An honest agent that crashes once at the wrong instant loses a witnessed leaf (the witness will then 422 the honest log, i.e. the agent looks like a forger) or bricks its journal. The same unlinked-newline state can also be produced by anyone with write access to the file.
- **Reproduction:** `defect_j1a_torn_newline_then_resume_silently_drops_a_committed_leaf`, `defect_j1b_torn_newline_then_one_append_bricks_the_journal` (core).
- **Fix:** treat a final line without `\n` as torn (do not advance `good_byte_length` past it), *or* have `open_for_append` check the last byte and write a `\n` before any append, *and* write each record with a single `write_all` of `line + "\n"` (build the string first). Apply all three; they are independent defences. Add the "last line lacks newline" case to `fuzz_journal_replay`.

### J2 — MEDIUM — Same torn-newline pattern in the salts sidecar makes `JournaledLog::resume` fail

- **Where:** `core/src/redaction.rs:145-183` (`FileSaltStore::open` keeps a newline-less last record and sets `good_len` to the file length), `:304` (`commit` appends with `writeln!`), `core/src/journal.rs:842` (`FileSaltStore::open(...)?` in `finish_resume`).
- **Mechanism:** identical to J1. After one torn newline and two further appends the sidecar has an unparsable merged record followed by a good one, `open` returns `InvalidData`, and `resume` fails for the whole journal until the operator deletes the sidecar (losing the ability to redact anything earlier). With exactly one further append the merged record is the tail and is silently truncated, so two leaves become unforgettable with no report.
- **Reproduction:** `defect_j2_salt_sidecar_torn_newline_then_two_appends_blocks_resume` (core).
- **Fix:** as J1; additionally make the sidecar's torn-tail policy identical to the journal's and surface the truncation in `ReplayReport`.

### W1 — MEDIUM — `EquivocationProof::verify` trusts the vkey carried inside the proof; a forged proof against any victim's canonical origin verifies

- **Where:** `network/src/tlog_witness.rs:301-319`; consumed by `cli/src/witness_cmd.rs:159-161` ("PROVEN ... This identity showed two histories", exit 0).
- **Mechanism:** `verify()` parses `self.log_vkey`, checks both notes under it, and compares origins and sizes. Nothing ties `log_vkey` to `origin`. An attacker generates a key K, signs two checkpoints with different roots under origin `witness-log/<victim hex>` with key name = origin, and ships `{origin, log_vkey: vkey(K), ...}`. `verify()` returns true. The CLI's evidence checker prints PROVEN for the victim's identity. A witness's own `evidence/` directory is not affected (its proofs are built from the vkey it holds), but any proof received from a third party is.
- **Attacker gets:** a "cryptographically verified" equivocation accusation against an arbitrary identity, accepted by the project's own tool.
- **Reproduction:** `defect_w1_equivocation_proof_verifies_under_a_stranger_key` (network).
- **Fix:** in `verify()`, require `vkey.name == origin` and, when `identity_from_canonical_origin(origin)` is `Some(k)`, require `vkey.public_key == k.to_bytes()` and `vkey.sig_type == 0x01`. Expose a `verify_with_key(&VerifierKey)` for non-canonical origins so the caller must supply the trusted key. Have the CLI print NOT PROVEN when the vkey does not match a canonical origin.

### W2 — MEDIUM (design) — Revocation cut-off is enforced on a timestamp the key holder sets; the verifier has no trusted revocation input

- **Where:** `network/src/lib.rs:909-941` (`bindings_and_revocations_valid`: `l.timestamp_ms >= as_of` is the only test), `:889` (no bindings/revocations → vacuously valid), `VerifyContext` (`:767-799`, no revocation field); `core/src/identity.rs:90-103`.
- **Mechanism:** the party a revocation defends against is whoever now holds the compromised identity key. That party writes leaves with `timestamp_ms < as_of_ms`, signs a checkpoint (timestamp unchecked against the revocation) and the dossier verifies with the revocation included. Omitting the revocation entirely yields the same verdict (`bindings_asserted: false`). THREAT_MODEL.md says post-revocation leaves "should be treated as untrusted by verifiers who see the revocation"; this review's point is that the mechanism cannot deliver that even for a verifier who does see it, and `--identity` pinning gives the verifier no way to assert "this key was revoked".
- **Reproduction:** `defect_w2_revocation_cutoff_is_defeated_by_backdated_timestamps` (network): backdated leaves under a checkpoint signed after `as_of_ms` → `bindings_valid: true`, `Unanchored`; honest timestamps → `Diverged`; stripped revocation → same verdict as never revoked.
- **Fix:** add a `tree_size` ("as of index N") to `RevocationStatement` and cut by leaf index, which witnesses can pin (a witnessed checkpoint of size N before the revocation makes the cut-off unforgeable); add `VerifyContext::revocations: &[RevocationStatement]` so a verifier supplies known revocations out-of-band and a dossier that omits one is `Diverged`; refuse a checkpoint whose cosignatures (`witnessed_at_ms`) all postdate the revocation when `tree_size > N`.

### R1 — LOW — `forget` reports success on leaves whose content it does not erase

- **Where:** `core/src/log.rs:484-504` (`forget` keys off `has_salt` only), `:449` (anchor payload "salted for GDPR consistency"), `:378-381` and `:412` (unsalted `handoff_state_hash` / `authorization_scope_hash`).
- **Mechanism:** an ExternalAnchor leaf's payload is the URL, but the URL and the full `anchor_proof_json` also sit in cleartext in the leaf and are committed by `anchor_url` / `anchor_proof_hash`. `can_forget` answers true, `forget` returns true and compacts the sidecar, and nothing visible changes. Handoff and authorization leaves keep an unsalted SHA-256 of the forgotten payload, so a low-entropy payload is confirmable after redaction (leaf.rs documents this for the hash field, but the API still reports the leaf as forgettable).
- **Reproduction:** `defect_r1_forget_on_anchor_leaf_erases_nothing_visible` (core).
- **Fix:** `can_forget` → false (and `forget` → `Err`/false) for 0x05/0x06/0x07, or return a typed result that says what was and was not erased. Document in SPEC §8.

### L1 — LOW — Fields not applicable to a leaf's type are neither committed nor rejected

- **Where:** `core/src/leaf.rs:343-426` (`validate` only requires fields, never forbids), `:275-328` (type-gated encoding).
- **Mechanism:** a dossier editor can add or change `counterparty_pubkey`, `handoff_state_hash`, `authorization_scope_hash`, `anchor_url`, `anchor_proof_json`, `anchor_proof_hash` on an ActiveIntent leaf (or `authorization_*` on a handoff leaf) with no change to the signed root and no validation error. Anything that renders these fields (CLI `explain`, bindings, Python) shows attacker-controlled data as if it were part of the log.
- **Reproduction:** `defect_l1_uncommitted_fields_validate_and_hash_identically` (core).
- **Fix:** `validate` rejects any type-specific field that is `Some` on a leaf of another type.

### L2 — LOW — Redaction target and marker hash are not structurally checked

- **Where:** `core/src/leaf.rs:375-377`, SPEC §8 ("markers commit the all-zero payload_hash").
- **Mechanism:** a 0x03 leaf with `redacted_index: u64::MAX`, or equal to its own index, and a non-zero `payload_hash`, passes `validate_sequence`. `finish_resume` feeds the index to `reconcile` harmlessly, but a verifier/CLI reporting "index X was forgotten" for a non-existent X is wrong, and the spec's MUST is unenforced.
- **Reproduction:** `defect_l2_redaction_target_and_marker_hash_are_unchecked` (core).
- **Fix:** `validate(expected_index)` requires `redacted_index < expected_index` and `payload_hash == 00..00` for 0x03/0x04.

### J3 — LOW — A tear inside a multi-byte UTF-8 sequence is refused instead of healed

- **Where:** `core/src/journal.rs:118-120` (`String::from_utf8` error returned as `InvalidData` before the torn-tail logic runs).
- **Mechanism:** `anchor_url` may contain non-ASCII; a torn tail ending between the bytes of one character makes `read_bounded_line` fail and `resume` return an error rather than drop the tail.
- **Reproduction:** `defect_j3_tear_inside_multibyte_char_is_not_healed` (core).
- **Fix:** on a UTF-8 error at EOF (no trailing newline) treat the line as torn.

### W3 — LOW — `old <size>` accepts non-canonical integers

- **Where:** `network/src/tlog_witness.rs:120-124` (`u64::from_str` accepts `+5`, `005`).
- **Consequence:** none found beyond inconsistency with the strict checkpoint-size parser; recorded.
- **Reproduction:** `defect_w3_old_size_line_accepts_non_canonical_integers` (network).

### C1 — INFO — Checkpoint note text with a trailing blank line parses as the canonical checkpoint

- **Where:** `core/src/c2sp.rs:467` (`trim_end_matches('\n')`).
- A note whose text is `origin\nsize\nroot\n\n` is accepted; the log's signature covers the non-canonical bytes, the witness cosigns `note_text()` (canonical). Not exploitable without the log key; pinned in `sound_c2sp_parsers_reject_malformed_input`.

### C2 — INFO — `NoteSignature::parse` accepts an empty signature; the comment claims otherwise

- **Where:** `core/src/c2sp.rs:237-245` (`[a,b,c,d, sig @ ..]` matches a 4-byte payload with `sig` empty).
- A known-key line with an empty signature makes `SignedNote::verify` return `BadSignature` for the whole note, but so does any garbage under a known key id, which the spec mandates. Fix the comment or require `sig.len() >= 1`.

### I1 — INFO — `KeyCustody` is outside the signed binding message

- Documented in SPEC §5 as self-asserted. `info_i1_binding_custody_is_not_signed` pins it so a consumer that gates on custody can be pointed at the test.

### M1 — INFO — `verify_consistency(0, x, 0, y, [])` is true for `x != y`

- `core/src/merkle.rs:350-353`. Every caller guards this (witness checks the empty root separately, `compare_checkpoints` handles equal sizes first). Pinned in `info_m1_consistency_zero_to_zero_ignores_roots`.

### Plausible, not confirmed

- **P1 (would be MEDIUM):** an I/O error inside `JournaledLog::append_*` after the leaf is already in the in-memory tree (`journal.rs:1007-1019`: salt-store error or `journal.append` failure is returned, but the in-memory append is not rolled back and the struct is not poisoned). The next successful append journals index N+1 with N missing; replay then fails `IndexMismatch` permanently. Not demonstrated: I found no way to inject a write failure through the public API without root (`/dev/full`, ENOSPC). Fix: roll back the in-memory leaf on error, or poison the `JournaledLog` so further appends refuse.
- **P2 (LOW):** the "subject's own operator" exclusion (`lib.rs:563-567`) fires only if the log's identity key is itself listed as a witness pubkey. Operators normally use separate witness keys, so the exclusion is inert in practice; a log operator's own witnesses count as independent. This is a limitation of the data model (no operator field on the log), not a code bug; the fix is a directory-level `operator_org` for logs or an explicit `VerifyContext::subject_operator`.
- **P3 (LOW):** a journal written by a newer build whose last record is a binding with an unknown `custody` variant (or any schema-valid-but-unparsable last line) is "healed" by an older build: silently truncated and the session's leaves left uncovered. Downgrade only; not demonstrated because no such variant exists yet.

## Checked and found sound

- `leaf.rs`: `canonical_bytes` is injective over committed fields (leaf_type byte first, all strings length-prefixed, presence bytes on every optional, fixed-width integers); `validate` enforces 64 lowercase hex for `session_pubkey`/`payload_hash`, recognised tags, mandatory fields, anchor URL scheme and `anchor_proof_json` preimage. Serde rejects out-of-range `leaf_type`.
- `merkle.rs`: `verify_consistency` follows RFC 9162 §2.1.4.2 step by step (both roots rebuilt, step 6 bit logic correct, `snode == 0` guard); rejects empty/short/long proofs, `first > second`, same-size-different-root; no loop or overflow at `2^63`, `u64::MAX`. `verify_inclusion` rejects `index >= size` and requires the proof fully consumed; recursion depth is bounded by proof length (≤64 for any `u64`). `root_at`/`inclusion_proof` use checked `usize` conversions. No panic reached from attacker-chosen sizes.
- `sth.rs` / `identity.rs`: `sig_alg`, signer hex, size, root, time all under the STH signature; `verify_strict`; key binding message has a presence byte for `not_after_ms`; revocation message is tamper-evident (reason is last, fixed-width fields before it). Uppercase signer hex does not verify (string is signed), uppercase root hex does (bytes are signed) and is then rejected by the string compare in `Dossier::verify` — fail-closed.
- `redaction.rs`: `payload_hash = SHA256(len||payload||pad || salt || index)`; empty payloads salted; markers zero; `forget` physically rewrites the sidecar (0600, fsync, rename); `reconcile` drops salts for torn-away or re-forgotten indices; duplicate-index records resolve to the latest. Nothing in the tree, journal or dossier carries a salt.
- `journal.rs` (apart from J1-J3): line cap enforced before allocation grows past 16 MiB; header format version checked; sealed journals require the seed and pin the public key (case-insensitive); unsealed + supplied seed must match; unparsable line followed by content refuses replay; replayed leaves go through `validate_sequence`; lock uses `O_EXCL`, stale takeover checks `/proc`, token-guarded drop; `sync` detects unlink/replace; `forget` removes the salt before journaling the tombstone (fails toward "cannot redact").
- `c2sp.rs`: key id = SHA-256(name||0x0A||type||key)[:4]; vkey split from the left; cosignature/v1 message matches the published vector; tree size must be canonical decimal (`007`, `+7`, 2^64 rejected); root exactly 32 bytes; origin no space/`+`; control characters other than `\n` rejected; 64-signature cap; `Cosignature::from_note_signature` length-checked; `identity_from_canonical_origin` accepts exactly one spelling.
- `lib.rs` verify path: checkpoint signature, identity self-consistency and pin, structural validation, bindings, Merkle size+root all required for anything above `Diverged`; no directory → `Unanchored` regardless of receipts; receipts verified against the checkpoint's `(size, root, signer)`; counted once per key (`normalize_hex`); only keys in the *verifier's* directory count; operator labels normalised (trim, case, whitespace); project-operated collapse to one bucket and never count as independent; `min_receipts` overrides only the count gate, never the two-operator floor; C2SP receipts require canonical origin, whole-second timestamp, exact head; the log's own 0x01 note signature cannot be relabelled as a cosignature; `witness_name`, `witness_directory`, `c2sp_origin` cannot upgrade a verdict; hostile JSON variants (huge sizes, bad hex, wrong algorithm case, bad index) all land on `Diverged` or fail to parse, no panic. `compare_checkpoints` checks both signatures first, orders by `(timestamp, size)`, and requires a both-roots proof for `Extends`. `silence_proof` requires a verified write receipt, same-signer checkpoints, one trusted receipt each, and dedups by `(size, root)`.
- `tlog_witness.rs`: proof lines capped at 63 and decoded to exactly 32 bytes; checkpoint body capped at 1 KiB; log signature checked under the out-of-band key before any state is read or any 409 size leaks; `old_size > size` → 400; `old_size != held` → 409; size-0 claims checked against the empty root; `verify_consistency` with the held root (both-roots) — a fork from a non-power-of-two held size is refused and the record is unchanged; equivocation evidence only for two log-signed notes at the held size, and the stored note is the log-signed-only re-encoding; `add_log`/`enroll_canonical` never reset a known log; forged notes are never enrolled; `from_state` refuses duplicates and malformed records; `WitnessState::bind`/`check_bound_to` refuse a state restored next to another key; `cosignature_to_receipt` refuses a cosignature over any other `(origin, size, root)`.

## Tests added

- `crates/witness-log-core/tests/review_round2.rs` — 14 tests: `defect_j1a`, `defect_j1b`, `defect_j2`, `defect_j3`, `defect_r1`, `defect_l1`, `defect_l2`, `info_i1`, `info_m1`, `sound_consistency_edges`, `sound_inclusion_edges`, `sound_leaf_encoding_injective_on_committed_fields`, `sound_c2sp_parsers_reject_malformed_input` (contains C1, C2), `sound_signed_messages_bind_all_fields`.
- `crates/witness-log-network/tests/review_round2.rs` — 10 tests: `defect_w1`, `defect_w2`, `defect_w3`, `sound_receipts_counted_against_exact_head_and_trusted_directory_only`, `sound_operator_normalisation_and_project_bucket`, `sound_c2sp_receipts_bind_origin_time_and_head`, `sound_witness_refuses_forks_and_records_only_real_equivocation`, `sound_request_parser_bounds`, `sound_hostile_dossier_json_does_not_panic_or_upgrade`, `sound_compare_checkpoints`.

## Lines reviewed

Approximately 10,500 lines of Rust across the ten in-scope files (leaf 860, merkle 965, sth 268, identity 347, redaction 593, journal 1,607, c2sp 1,163, log 1,504, network lib 2,409, tlog_witness 787), plus 45 lines of `cli/src/witness_cmd.rs`. Of these roughly 4,500 are non-test code.
