# WitnessLog Wire Format Specification — v0.3 (draft)

Status: draft, pre-1.0. Breaking changes are possible until 1.0 is tagged.
Once tagged 1.0, changes to §2–§9 require a new major version and MUST NOT
silently alter the meaning of previously-issued leaves, checkpoints, or
dossiers.

This document is normative. `crates/witness-log-core` is the reference
implementation of it, not the other way around: if code and spec disagree,
that's a bug in the code (or the spec needs an errata), and either should be
filed as an issue. See `/corpus/` for the test vectors any implementation is
expected to reproduce exactly.

## 0. Scope

WitnessLog is a wire format and a verification procedure for the
execution record of an autonomous agent. It exists for one reason: a
record that the party who produced it can quietly change is not an audit
trail, whatever its retention policy says. A log in a database — the
agent operator's, a platform's, a vendor's — is mutable by whoever holds
the credentials, and "immutable" there means "no delete button", which
is a policy, not a property. When agents transact with other agents
across organisational boundaries, when a dispute turns on what an agent
actually did, or when a regulator asks, the question is not "do you have
logs" but "why should anyone believe them".

This specification makes the record a cryptographic object:

- **Append-only, with proof.** Entries are leaves of an RFC 6962 Merkle
  tree. Any entry can be proven present (inclusion), and any two
  snapshots can be proven to be the same history extended (consistency).
  Rewriting, reordering or removing an entry changes the root.
- **Non-repudiable.** Every checkpoint is signed by the log's long-lived
  Ed25519 identity key; every leaf by a session key that identity bound.
  A record a verifier accepts was signed by that identity, and only that
  identity could have produced it.
- **Witnessed.** Independent third parties cosign checkpoints and refuse
  to cosign a history that does not extend what they already signed. A
  log cannot show one history to one party and another to a second
  without contradicting a cosignature someone holds. This is the property
  that distinguishes an audit trail from a signed diary.
- **Verifiable offline, by anyone.** The record (§9) carries everything a
  verifier needs; verification needs no access to the agent, its operator
  or the witnesses.
- **Erasable without breaking.** Payloads enter the tree only as salted
  hashes (§8); forgetting a salt erases an entry's content for GDPR while
  every proof around it stays valid.

What this specification is not: it is not a runtime, an authorization
system, a consensus protocol or a ledger (§1.1); it does not make the
*content* of an entry true, only unalterable after the fact
(THREAT_MODEL.md); and it does not require a blockchain, a token or a
trusted service.

The reference implementation (Rust library, CLI, witness server, Python
bindings) is one implementation. The conformance corpus (`/corpus/`) is
what defines agreement between implementations; a second implementation
that reproduces every vector is conformant whatever language it is
written in.

## 1. Design basis

WitnessLog borrows its core primitives from RFC 6962 (Certificate Transparency)
rather than from blockchain consensus: an append-only Merkle log,
domain-separated leaf/interior-node hashing, periodic signed checkpoints,
and independent third-party witnessing of those checkpoints. See
`GOVERNANCE.md` for why, and `THREAT_MODEL.md` for exactly what this does
and does not guarantee.

WitnessLog aims for wire-format compatibility with `draft-maintainer-1f916-agent-record`
where the underlying primitive is the same (Merkle construction, checkpoint
signing). Known divergences are noted inline at the point they occur (see
§3.3's `ExternalAnchor`, which has no counterpart in that draft) rather
than centralized in one comparison section — a dedicated divergence list
is tracked as future work, not written yet. Do not treat the absence of
an inline note as confirmation of full alignment; verify against the
draft text directly for anything load-bearing.

### 1.1 Which layer this is, and which layers it deliberately isn't

Trust infrastructure for autonomous agents decomposes into separable
layers, not one monolithic system — this is the same conclusion the IETF's
proposed AUDIT working group has converged on independently (composing
RATS for attestation, SCITT for transparency, WIMSE for identity, and
OAuth for authorization, rather than inventing a single system that does
all four). WitnessLog deliberately occupies the **transparency** layer only:

- **Attestation** ("is this record authentic?") — a signature check.
  WitnessLog does this minimally, at the leaf and checkpoint level, but does
  not aim to be a general attestation framework (that's RATS' job).
- **Transparency** ("did this record exist as claimed, unaltered, at the
  claimed position?") — this is WitnessLog's actual scope: the Merkle log,
  checkpoints, and witness quorum.
- **Identity** (workload/agent identity issuance and lifecycle broadly) —
  WitnessLog's two-tier identity/session model (§5) exists to serve its own
  log, not to replace or compete with WIMSE-style workload identity.
- **Authorization** (what an agent is permitted to do, capability
  delegation, scoped tokens) — explicitly out of scope. This is the same
  reasoning already applied to payment rails (see GOVERNANCE.md): keep
  the transparency layer usable regardless of which authorization system
  (OAuth, UCAN, Macaroons, or something else) an integration already uses.

This is why WitnessLog can log *that* a delegation or authorization change
happened (§3.2, AuthorizationEvent) without becoming an authorization
system itself, the same way it can log *that* a handoff happened (§3.1)
without becoming a messaging system.

## 2. Leaf types

Every event is tagged with a single byte:

| Tag  | Name               | Meaning                                                             |
|------|--------------------|----------------------------------------------------------------------|
| 0x00 | PassiveMemory      | General contextual memory insert; non-actionable.                    |
| 0x01 | ActiveIntent       | Intercepted tool-call input / LLM action prompt.                     |
| 0x02 | ActiveResult       | Tool execution result / API response payload.                        |
| 0x03 | Redaction          | Tombstone: the salt for `redacted_index` has been deleted.           |
| 0x04 | KeyRevocation      | The identity key `revoked_identity` is revoked as of this leaf.      |
| 0x05 | HandoffAttestation | One side's independent commitment to a context/state handoff between two agents. See §3.1. |
| 0x06 | AuthorizationEvent | One side's independent, logging-only commitment to a delegation/authorization change between two agents. See §3.2. |
| 0x07 | ExternalAnchor     | A cryptographic commitment from a party entirely outside this log (Sigstore Rekor, an RFC 3161 timestamp authority, or equivalent) that this checkpoint existed at a moment in time. See §3.3. |

Implementations MUST reject leaves with an unrecognized tag rather than
silently treating them as a known type. New tags require a spec revision.

## 3. Leaf canonical encoding

A leaf's canonical byte encoding — the exact bytes that get hashed into the
tree — is defined as concatenation, in this fixed order. Every
variable-length field is **length-prefixed** (a 4-byte big-endian `u32`
byte count immediately before the field's bytes, written `lp(field)`
below), and every optional field is preceded by an explicit **presence
byte** (`0x00` absent, `0x01` present) even when the field is
byte-length-prefixed on its own — the presence byte and the length
prefix are two separate mechanisms answering two separate questions
("is this field here at all" and "how many bytes is it"). An earlier
draft of this format omitted both length-prefixing and presence bytes
for several fields; that draft is not what any implementation should
target — see the note at the end of this section.

```
leaf_type                  : 1 byte
index                      : 8 bytes, big-endian u64
timestamp_ms                : 8 bytes, big-endian u64
session_pubkey               : lp(UTF-8 bytes of the hex-encoded 32-byte Ed25519 public key — 64 ASCII bytes before length-prefixing)
payload_hash                  : lp(UTF-8 bytes of the hex-encoded 32-byte hash — 64 ASCII bytes before length-prefixing)
redacted_index_present         : 1 byte, 0x00 or 0x01
redacted_index                  : 8 bytes big-endian u64, present only if the previous byte is 0x01
revoked_identity_present         : 1 byte, 0x00 or 0x01
revoked_identity                  : lp(UTF-8 bytes of hex-encoded pubkey), present only if previous byte is 0x01
```

**If, and only if, `leaf_type == 0x05` (HandoffAttestation)**, three
further fields are appended, in this order, EACH preceded by its own
presence byte (unlike an earlier draft of this format, a HandoffAttestation
leaf's fields are not assumed unconditionally present just because the
leaf type implies they should be — `Leaf::validate` separately enforces
that a well-formed 0x05 leaf actually has all three, but the *encoding*
itself does not assume it):

```
handoff_direction_present  : 1 byte, 0x00 or 0x01
handoff_direction           : 1 byte, 0x00 (Sent) or 0x01 (Received) — present only if previous byte is 0x01
counterparty_pubkey_present  : 1 byte, 0x00 or 0x01
counterparty_pubkey           : lp(UTF-8 bytes of hex-encoded identity pubkey of the OTHER agent) — present only if previous byte is 0x01
handoff_state_hash_present     : 1 byte, 0x00 or 0x01
handoff_state_hash              : lp(UTF-8 bytes of hex-encoded SHA-256 of the raw handoff payload, UNSALTED) — present only if previous byte is 0x01
```

**If, and only if, `leaf_type == 0x06` (AuthorizationEvent)**, three
further fields are appended, in this order, each with its own presence byte:

```
authorization_event_kind_present : 1 byte, 0x00 or 0x01
authorization_event_kind          : 1 byte, 0x00-0x05 (see §3.2 for the mapping) — present only if previous byte is 0x01
counterparty_pubkey_present        : 1 byte, 0x00 or 0x01
counterparty_pubkey                 : lp(UTF-8 bytes of hex-encoded identity pubkey of the OTHER agent) — present only if previous byte is 0x01
authorization_scope_hash_present     : 1 byte, 0x00 or 0x01
authorization_scope_hash              : lp(UTF-8 bytes of hex-encoded SHA-256 of the raw scope description, UNSALTED) — present only if previous byte is 0x01
```

**If, and only if, `leaf_type == 0x07` (ExternalAnchor)**, two further
fields are appended, in this order, each with its own presence byte —
see §3.3 for what each commits and why:

```
anchor_url_present         : 1 byte, 0x00 or 0x01
anchor_url                  : lp(UTF-8 bytes of the anchor URL) — present only if previous byte is 0x01
anchor_proof_hash_present    : 1 byte, 0x00 or 0x01
anchor_proof_hash             : lp(UTF-8 bytes of hex-encoded SHA-256 of the raw anchor_proof_json, UNSALTED) — present only if previous byte is 0x01
```

Note that `counterparty_pubkey` is shared between 0x05 and 0x06 — it means
"the other agent in this leaf's cross-agent relationship" regardless of
which of the two leaf types is using it, and it is encoded independently
at each of its two possible positions (it is never emitted twice for a
single leaf, since a leaf's `leaf_type` is exactly one of 0x05/0x06/neither).

For every `leaf_type` other than 0x05, 0x06, or 0x07, none of the
handoff/authorization/anchor fields above are emitted at all — not even
their presence bytes. This is a deliberate wire-format choice: adding
leaf types 0x05, 0x06, and 0x07 did not, and must not, change the
canonical encoding or hash of any leaf type that existed before them. See
`/corpus/01_leaf_encoding.json` (the original five leaf types, hashes
unchanged by all three additions), `/corpus/07_handoff_attestation.json`,
`/corpus/08_authorization_event.json`, and `/corpus/09_external_anchor.json`
— all four are checked in CI to catch exactly this kind of accidental
cross-type interference.

**Why length-prefixing and presence bytes, when the fixed-width hex
fields (`session_pubkey`, `payload_hash`, etc.) are always exactly 64
ASCII characters by convention?** Because "by convention" is not "by
construction": nothing in the wire format itself prevented a
malformed-length value from being concatenated ambiguously with its
neighbor. A `session_pubkey` of `"aaaabbbb"` immediately followed by a
`payload_hash` of `"cccc"` produced byte-identical concatenated output to
a `session_pubkey` of `"aaaa"` followed by a `payload_hash` of
`"bbbbcccc"` — two structurally different leaves, one canonical encoding,
one Merkle leaf hash. Length-prefixing closes this unconditionally,
independent of whether every field additionally happens to be validated
as 64 hex characters elsewhere (`Leaf::validate` does this too, as
defense in depth, but the encoding does not rely on it). `Leaf::validate`
and `validate_sequence` are the structural-validity checks; the
length-prefixed, presence-byte encoding above is what makes the *hash*
itself unambiguous even before validation runs.

### 3.1 HandoffAttestation and cross-log binding

When agent A hands context or state to agent B, each side independently
appends a HandoffAttestation leaf to its *own* log — there is no
coordination protocol, no shared mutable state, and no requirement that
both sides even run WitnessLog. A appends with `handoff_direction = Sent`,
`counterparty_pubkey` = B's identity pubkey; B appends with
`handoff_direction = Received`, `counterparty_pubkey` = A's identity
pubkey. Both compute `handoff_state_hash = SHA256(raw_handoff_payload)` —
deliberately unsalted, unlike `payload_hash`, since this field's entire
purpose is to be compared across two independently-salted logs later.

The binding is established after the fact, by whoever holds both leaves
(either agent, or a later auditor), via:

```
verify_handoff_binding(a_identity, a_leaf, b_identity, b_leaf):
  require a_leaf.leaf_type == b_leaf.leaf_type == 0x05
  require a_leaf.handoff_direction == Sent, b_leaf.handoff_direction == Received
  require a_leaf.counterparty_pubkey == b_identity
  require b_leaf.counterparty_pubkey == a_identity
  require a_leaf.handoff_state_hash == b_leaf.handoff_state_hash
```

If all five hold, the two attestations bind: both agents committed, in
their own independently-witnessable logs, to the same content changing
hands between the same two identities. If any check fails — including the
common honest case where a transport genuinely delivered different bytes
than were sent — the mismatch is directly visible, not silently absorbed.

**What this does and does not prove** (see THREAT_MODEL.md for the full
row): it proves both named parties committed to the same content
identifier at some point. It does NOT prove real-time delivery, does NOT
prove the payload wasn't tampered with in a way that fooled both sides
identically before either logged it, and does NOT require the redacted
`payload_hash` to survive — `handoff_state_hash` is intentionally separate
from, and not affected by, `WitnessLog::forget` on the same leaf.

See `/corpus/07_handoff_attestation.json` for a worked matching pair and a
worked mismatch.

### 3.2 AuthorizationEvent and cross-log binding

Same pattern as §3.1, applied to delegation/authorization changes instead
of state handoffs. When agent A grants, revokes, or changes agent B's
scope, each side independently appends an AuthorizationEvent leaf to its
own log. `authorization_event_kind` is one field capturing both "which
side" and "what happened":

```
0x00 GrantedByMe        0x01 GrantedToMe
0x02 RevokedByMe        0x03 RevokedToMe
0x04 ScopeChangedByMe   0x05 ScopeChangedToMe
```

An honest pair always has A's kind and B's kind on the same row of that
table (A's `GrantedByMe` pairs with B's `GrantedToMe`, and so on).
`authorization_scope_hash = SHA256(raw_scope_description)`, unsalted, for
the same cross-log-comparison reason as `handoff_state_hash`.

```
verify_authorization_binding(a_identity, a_leaf, b_identity, b_leaf):
  require a_leaf.leaf_type == b_leaf.leaf_type == 0x06
  require b_leaf.authorization_event_kind == paired_kind(a_leaf.authorization_event_kind)
  require a_leaf.counterparty_pubkey == b_identity
  require b_leaf.counterparty_pubkey == a_identity
  require a_leaf.authorization_scope_hash == b_leaf.authorization_scope_hash
```

**This is logging-only, deliberately.** WitnessLog records that an
authorization event happened and lets both sides' logs agree on exactly
what was granted; it never mints, evaluates, or enforces a capability —
that remains the job of whatever real authorization system (OAuth, UCAN,
Macaroons, or otherwise) an integration already uses. See §1.1 on
layering. One useful, unplanned consequence of this design: if a grantee's
logged scope is *wider* than what the granter actually logged granting,
`verify_authorization_binding` fails — a cheap, free check against scope
escalation claims, even though WitnessLog has no idea what the scope strings
actually mean.

See `/corpus/08_authorization_event.json` for a worked matching pair and a
worked mismatch.

### 3.3 ExternalAnchor

A witness network takes time to bootstrap — recruiting operators
independent of the project takes coordination, trust-building, and
usually a track record the project doesn't have on day one. ExternalAnchor
is how a checkpoint gets independent existence-in-time evidence without
needing any witness recruitment at all: anchor to infrastructure nobody
in this project operates, that already has a track record (Sigstore's
Rekor transparency log, or any RFC 3161 timestamp authority).

`anchor_url` is where the anchor proof can be fetched and independently
re-verified (a Rekor entry URL, an RFC 3161 TSA response endpoint, or
equivalent). `anchor_proof_json` is the provider's full response, stored
verbatim — self-describing and version-tolerant across providers, since
different anchor services return structurally different proof formats.

**What's actually committed, and why it isn't the raw proof JSON.** An
earlier revision of this leaf type committed only `anchor_url` into
`canonical_bytes`, leaving `anchor_proof_json` itself freely swappable
after the fact — a verifier fetching the URL later could be shown
different proof content than what the log originally anchored, with no
way to detect the substitution. The committed field is instead
`anchor_proof_hash = SHA256(anchor_proof_json)`, unsalted, following the
same pattern as `handoff_state_hash` and `authorization_scope_hash`:

```
anchor_proof_hash = SHA256(raw_anchor_proof_json_bytes)
```

A verifier holding a leaf with a claimed `anchor_proof_json` recomputes
this hash and compares it against the committed `anchor_proof_hash`; a
mismatch means the proof content shown does not match what was actually
anchored at append time, regardless of what the URL currently returns.

**What this leaf type does and does not establish.** It proves a
checkpoint existed at or before a moment in time, corroborated by a
party outside this project's control. It does NOT provide equivocation
resistance the way a witness quorum does — Rekor (or any single anchor
service) is one external party, not a diverse set of independent
observers, and anchoring says nothing about operator or compute-provider
diversity. Treat ExternalAnchor and witness receipts as complementary,
not substitutes: anchoring works from day one with zero witness
infrastructure; a witness quorum is what ultimately delivers
equivocation resistance once a network exists. See GOVERNANCE.md.

See `/corpus/09_external_anchor.json` for a worked example.

## 4. Merkle tree

RFC 6962 §2.1 construction exactly:

- `leaf_hash(data) = SHA256(0x00 || data)`
- `node_hash(left, right) = SHA256(0x01 || left || right)`
- Empty tree root = `SHA256("")`.
- For `n > 1` leaves, split at `k`, the largest power of two strictly less
  than `n`; root = `node_hash(subtree(leaves[0:k]), subtree(leaves[k:n]))`.

Inclusion proofs follow RFC 6962 §2.1.1 `PATH()`. See
`/corpus/02_merkle_roots.json` and `/corpus/03_inclusion_proofs.json`.

## 5. Identity and key binding

Two key tiers:

- **Identity key**: long-lived Ed25519 keypair, persisted by the agent
  operator across process restarts. This is "who the agent is."
- **Session key**: ephemeral Ed25519 keypair, generated fresh each process
  lifecycle, used to sign individual leaves (via `session_pubkey` in each
  leaf — the leaf itself is not separately signed in this version; the checkpoint
  signature over the whole tree is what's cryptographically load-bearing).

A **KeyBindingStatement**, signed by the identity key, links a session key
to an identity for a given `session_number`, with an optional expiry:

```
message = "witness-log-key-bind-v1" || identity_pubkey (32B) || session_pubkey (32B)
           || session_number (8B BE) || timestamp_ms (8B BE)
           || not_after_ms_present (1B, 0x00 or 0x01)
           || not_after_ms (8B BE, present only if the previous byte is 0x01)
signature = Ed25519_Sign(identity_signing_key, message)
```

`not_after_ms` is optional: a binding with no expiry (`not_after_ms_present
= 0x00`) is valid indefinitely (until superseded by a later binding or a
revocation); a binding with an expiry (`resume_with_ttl`) is provably
stale once a verifier's clock — or, more meaningfully, a witness-corroborated
timestamp — passes it. The presence byte comes before the value so "no
expiry" and "expiry = 0" are never ambiguous on the wire, the same
pattern used throughout §3.

A binding also carries an unsigned `custody` field describing how the
session key's private half is held: one of the strings `self_held`,
`platform_held`, `hsm`, `kms`, `session_delegated`, `undisclosed` (the
default), or the object `{"threshold": {"k": "<k>", "n": "<n>"}}`. It is
**not** part of the signed message above, so it is a self-asserted
disclosure, not evidence: verifiers MUST surface it next to the signature
result (a valid signature under a `platform_held` key proves the operator
authorised the leaves, not the agent alone) and MUST NOT let it change the
verdict. `undisclosed` is the weakest tier, never a neutral one.

A **RevocationStatement** invalidates an identity key going forward:

```
message = "witness-log-revoke-v1" || identity_pubkey (32B) || as_of_ms (8B BE) || reason (UTF-8 bytes)
signature = Ed25519_Sign(identity_signing_key, message)
```

Leaves signed by a revoked identity's sessions after `as_of_ms` MUST be
treated as untrusted by verifiers.

## 6. Signed Tree Head (checkpoint)

```
message = "witness-log-sth-v2" || lp(sig_alg) || lp(signer_pubkey) || tree_size (8B BE) || root_hash (32B) || timestamp_ms (8B BE)
signature = Ed25519_Sign(identity_signing_key, message)
```

where `lp(field)` is the same length-prefixing used in §3: a 4-byte
big-endian `u32` byte count immediately before the field's UTF-8 bytes.
`sig_alg` is the algorithm identifier string (e.g. `"ed25519"`);
`signer_pubkey` is the hex-encoded public key, also carried as a
plaintext field on the `SignedTreeHead` struct for convenience — the
signature covers both regardless of the fact that they're also readable
without verifying anything.

**Why `sig_alg` and `signer_pubkey` are inside the signed message, not
just alongside it (this is a `-v1` → `-v2` break from an earlier draft
of this spec):** `sig_alg` is described just below as the mechanism for
introducing a future signature algorithm without breaking the format.
An unauthenticated `sig_alg` field is the textbook setup for an
algorithm-downgrade attack — nothing stopped an attacker from mutating
`sig_alg` to a claimed-weaker algorithm's identifier after signing,
since the signature itself never covered that field. `signer_pubkey`
has the same problem: a receipt or checkpoint attesting only to
`(tree_size, root_hash, timestamp_ms)` says nothing cryptographically
binding about *whose* key produced it beyond whatever field happens to
be sitting next to the signature, unauthenticated. Folding both into
the signed message closes this while the format is still pre-1.0 and
free to break.

The STH is signed by the **identity key**, not the session key, so a
checkpoint remains verifiable after the signing session's process has
ended.

`sig_alg` is carried on every STH (currently always `"ed25519"`) for
crypto-agility: this field exists specifically so a future signature
algorithm can be introduced without breaking the format or invalidating
historically-issued checkpoints. See `/corpus/04_signed_tree_head.json`.

**Verification strictness (normative):** verifiers MUST use strict Ed25519
verification — reject non-canonical scalars per RFC 8032 AND reject
signatures involving small-order or mixed-order components (the behavior
of `ed25519-dalek`'s `verify_strict`, equivalent to what "Taming the many
EdDSAs" calls the strictest verification profile). The reason is
interoperability, not any weakness in honest signatures: Ed25519
implementations historically disagree on degenerate edge-case signatures,
and two conformant WitnessLog verifiers disagreeing about whether the same
dossier is valid would be worse than either answer alone. Honestly
generated signatures are unaffected by this requirement.

**Candidate future values**, not yet implemented: `"ml-dsa-65"` (FIPS 204 /
Dilithium) and `"falcon-512"` are the two most likely near-term additions
given their standardization status as of this writing. Naming candidates
now is meant to give implementers a concrete target to plan storage and
verification-path sizing around, not a commitment to either — the actual
migration mechanism itself is still undesigned (§10).

## 7. Witness receipts

```
message = "witness-log-witness-receipt-v2" || lp(witness_pubkey) || lp(log_signer_pubkey) || tree_size (8B BE) || lp(root_hash as UTF-8 hex) || witnessed_at_ms (8B BE)
signature = Ed25519_Sign(witness_signing_key, message)
```

where `lp(field)` is the same length-prefixing used in §3 and §6, and
`log_signer_pubkey` is the `signer_pubkey` of the `SignedTreeHead` this
receipt countersigns (i.e. the log identity's own key, not the witness's).

**Why `witness_pubkey` and `log_signer_pubkey` are inside the signed
message (this is a `-v1` → `-v2` break from an earlier draft of this
spec):** a receipt attesting only to `(tree_size, root_hash,
witnessed_at_ms)` makes no cryptographically binding statement about
which witness key produced it or which log's checkpoint it actually
countersigns — both were previously readable only from unauthenticated
fields sitting alongside the signature. Folding both into the signed
message means a receipt is now a specific, verifiable claim: "this
witness key attests that this log's checkpoint had this root at this
size, as of this time" — not merely "someone signed a (size, root) pair
that happens to match."

A receipt is only meaningful in the context of a witness directory entry
associating `witness_pubkey` with an `operator_org`. Quorum evaluation MUST
report operator-diversity, not just receipt count — see
`witness-log-network::evaluate_quorum` and `THREAT_MODEL.md` §"Witness
independence." Evaluation MUST also deduplicate receipts by `witness_pubkey`
(case-insensitive hex comparison) before counting: because `witnessed_at_ms`
is part of the signed message, a single witness key can produce multiple
distinct, individually valid signatures for the same checkpoint by
resigning at different timestamps, and counting receipts rather than
distinct keys would let one witness masquerade as several.

Directory entries also carry `runtime` (`human` or `agent`) and an
optional `compute_provider`. Diversity is scored on operator identity and
compute-provider identity as two **separate, unaveraged** numbers — see
§7.1. Nothing in the protocol distinguishes a human-operated witness from
an agent-operated one at verification time; the distinction exists purely
for the diversity accounting humans and agents alike rely on to judge a
quorum.

### 7.1 Consistency proofs (RFC 6962 §2.1.2)

A witness — human or agent — MUST NOT sign a receipt for a new checkpoint
without first verifying a consistency proof against the last checkpoint it
trusted:

```
consistent = VerifyConsistency(first_size, first_root, second_size, second_root, proof)
```

This is what makes repeated, automated witnessing meaningful rather than
decorative: without it, a witness has no algorithmic way to refuse a
checkpoint whose tree quietly doesn't contain the previous one as a prefix
(i.e., rewritten or forked history). `witness-log-core::merkle::consistency_proof`
/ `verify_consistency` implement generation and verification; see
`/corpus/06_consistency_proof.json` for a worked vector. The witness in
`witness_log_network::tlog_witness::WitnessService` runs exactly this check
before every cosignature, and refuses (HTTP 422) when it fails.

On a witness's very first observation of a target (no prior trusted
checkpoint), `first_size = 0` and the consistency proof is trivially empty
— there is nothing yet to be consistent with.

`VerifyConsistency` MUST be the RFC 9162 §2.1.4.2 algorithm, which
reconstructs **both** `first_root` and `second_root` from the proof and
requires both to match (and the proof to be fully consumed). An
implementation that reconstructs only `second_root` accepts forks: when
`first_size` is not a power of two, the old root never enters its
computation. WitnessLog ≤ 0.3.0 had exactly this bug; conforming
implementations SHOULD include the exhaustive fork test in
`witness-log-core::merkle` (every `1 <= m < n <= 64`, forks at the first,
middle and last old leaf).

## 8. Redaction (salted tombstones)

```
payload_hash = SHA256(bucket_pad(payload) || salt (32B) || leaf_index (8B BE))
```

where

```
bucket_pad(payload) = len(payload) as u64 (8B BE) || payload || 0x00 * (B - len(payload))
B = (floor(len(payload) / 256) + 1) * 256
```

i.e. the payload is zero-padded to `B` bytes — 256 for payloads of 0–255
bytes, 512 for 256–511, and so on — and the 8-byte length prefix sits in
front of that bucket, so `bucket_pad` yields 264, 520, 776, … bytes. (An
earlier draft of this text described padding `len || payload` together to
a 256-byte boundary; that was never what the implementation computed, and
corpus vector `11_payload_hash.json` now pins the exact function.) The salt is stored separately from the tree and
is the only thing deleted on a "right to be forgotten" request. See
`/corpus/05_redaction_continuity.json` for a worked example showing that
forgetting a salt does not alter any previously-committed leaf hash.

Every leaf that carries a payload is salted, including a leaf whose
payload is empty (vector 11, case `empty`); only the marker types 0x03
Redaction and 0x04 KeyRevocation, which carry no payload, commit the
all-zero `payload_hash`. A redaction request appends a 0x03 leaf naming
the forgotten index, so the tree root changes because a leaf was added,
never because an existing leaf changed.

Where salts live is an implementation matter, with one normative
requirement: a forgotten salt MUST be erased from every store the
implementation controls, not merely marked. The reference implementation
keeps a journal's salts in a `<journal>.salts` sidecar (one record per
leaf, rewritten without the entry on `forget`) and treats that file as key
material.

**Explicitly out of scope for this hardening**: leaf-type visibility,
timestamp correlation, and tree-position metadata are not hidden by this
scheme. See `THREAT_MODEL.md`.

## 9. Dossier export format

A dossier is the offline-verifiable bundle a verifier actually checks:

```json
{
  "identity_pubkey": "hex",
  "leaves": [ /* Leaf objects, §3 */ ],
  "checkpoint": { /* SignedTreeHead, §6 */ },
  "witness_receipts": [ /* WitnessReceipt objects, §7 */ ],
  "witness_directory": { "witnesses": [ /* WitnessEntry */ ] },
  "key_bindings": [ /* KeyBindingStatement objects, §5 */ ],
  "revocations": [ /* RevocationStatement objects, §5 */ ]
}
```

`witness_directory`, `key_bindings`, and `revocations` are all optional
(`[]`/`{"witnesses":[]}` when absent) and, critically, **all three are
display-only when they come from the dossier itself.** None of them are
a trust input on their own — see §9.1.

`witness-log verify <dossier.json>` (see `witness-log-cli`) is the
reference verifier for this format.

**JSON Schema.** `spec/dossier.schema.json` (JSON Schema 2020-12) states
the exact shape of a dossier and of every object in it: field names,
hex lengths, enumerations, which fields are optional. The reference
implementation's test suite validates every dossier it produces, and
every leaf in `/corpus/`, against it, so the schema cannot drift from
the code. A document that validates is well-formed, not verified:
signatures, Merkle continuity, bindings and quorum are §9.1–§9.2.

### 9.1 The trust boundary: what a verifier must supply itself

A dossier's `identity_pubkey`, `witness_directory`, `key_bindings`, and
`revocations` fields are all supplied by the party being verified — the
same party a verifier who cares about authenticity is trying not to
simply trust. A verifier that scores a dossier's own embedded witness
list, or accepts its own claimed identity at face value, is checking
whether the artifact is *internally consistent*, not whether it is
*evidence about a real party*. These are different questions, and
conflating them is the single most consequential mistake this
specification is written to prevent.

A verifier reaches a stronger conclusion only by supplying inputs of its
own that the dossier's author does not control:

- **`expected_identity_pubkey`** — the identity this run is actually
  trying to confirm, obtained out-of-band (a prior conversation, a
  pinned config, a CLI flag). Checked against `checkpoint.signer_pubkey`.
- **`trusted_directory`** — a witness directory the verifier itself
  trusts, obtained out-of-band. Receipts are scored against THIS
  directory, never against the dossier's own `witness_directory` field.

`witness-log verify` exposes these as `--identity <hex>` and `--directory
<path.json>`. The Python binding's `verify_dossier_json` exposes them as
optional `expected_identity_pubkey` and `trusted_directory_json`
parameters. Omitting both is a legal, meaningful verification run — it
proves the dossier doesn't contradict itself — but the reachable verdict
is capped accordingly; see §9.2.

`key_bindings` and `revocations` are treated differently: they are
checked for internal validity (each entry's own signature verifies, and
each named identity matches `identity_pubkey`) regardless of whether any
external anchor was supplied, because the property they establish —
"every leaf's session key traces to a binding this identity issued, and
none of them fall after a revocation" — is a self-consistency property
of the dossier's own claims about itself, not an authenticity claim
about who the dossier belongs to. Supplying no bindings or revocations
at all is treated as "not asserted," not as failure, so this stays
backward-compatible with dossiers that predate the fields.

### 9.2 The verdict

Verification produces exactly one of four verdicts:

| Verdict | What it means | What it does NOT mean |
|---|---|---|
| `Witnessed` | Every cryptographic and structural check passes, AND a `trusted_directory` was supplied, AND the valid receipts from witnesses in that directory come from at least **two distinct independent operators** (project-operated witnesses all count as one bucket; witnesses sharing the subject's own operator count as none), AND the receipt count meets the caller's threshold. Diversity is reported as two separate fractions (operator, compute provider) but the gate is the absolute independent-operator count, because a fraction scales with the receipt count and a single colluding operator could satisfy any fraction with enough keys. | Proof against a colluding operator with a captured witness set — see THREAT_MODEL.md's "Witness independence" section. Only as strong as the trusted directory actually is. |
| `ConsistentUnwitnessed` | Every cryptographic and structural check passes, a `trusted_directory` WAS supplied, but witness coverage is absent, below threshold, or entirely project-operated. | Equivocation resistance. A single-node log can show different histories to different verifiers undetected. |
| `Unanchored` | Every cryptographic and structural check passes, but no `trusted_directory` was supplied at all (regardless of what the dossier's own `witness_directory` or `witness_receipts` claim). | Anything about authenticity to a party the verifier didn't already trust. This is the ceiling for a fabricated dossier — see §9.1. |
| `Diverged` | Any cryptographic, identity-binding, structural-validity, or key-binding check FAILS. | — treat as evidence of tampering, fabrication, a mismatched `expected_identity_pubkey`, or an honest artifact whose non-cryptographic metadata is inconsistent (a leaf timestamp edited after signing fails structural validation the same way); the verifier's job is to report which check failed, not to assume intent. |

`Diverged` always takes precedence over the other three — any failure
below caps the verdict there regardless of witness coverage.
`internally_consistent` (checkpoint signature, identity binding,
structural validity, key-binding validity, Merkle continuity) is
reported as a separate boolean from the verdict, deliberately: a
dossier can be internally consistent yet still `Unanchored`, and callers
that only check it without looking at the verdict are exactly the ones
exposed to §9.1's mistake. The report also states `identity_pinned`:
`Witnessed` is reachable with a trusted directory alone, and then says
that *a* log was cosigned by independent operators, not *whose*; a gate
that cares which party it is verifying supplies `expected_identity_pubkey`
and checks `identity_pinned` is true.

## 9.3 C2SP interoperability

WitnessLog checkpoints can be expressed in the Community Cryptography
Specification Project's transparency-log formats, so that witnesses
already operating in the Certificate Transparency ecosystem can cosign
them without implementing anything WitnessLog-specific:

- `c2sp.org/signed-note` — the signed message envelope
- `c2sp.org/tlog-checkpoint` — checkpoint body layout
- `c2sp.org/tlog-cosignature` — timestamped witness cosignatures (v1)

**Rationale.** The hardest problem this specification faces is not
cryptographic but social: a witness network is worthless until
independent operators actually run witnesses, and nobody wants to be
first. That problem was already solved once, over roughly a decade, by
Certificate Transparency — the operators, the protocols, and the tooling
(`github.com/transparency-dev/witness`) exist and are running now.
Speaking their protocol inherits that installed base rather than
rebuilding it.

**Checkpoint mapping.** A C2SP checkpoint note text is:

```
<origin>
<tree size, ASCII decimal, no leading zeroes>
<base64(root hash)>
[optional extension lines]
```

The `origin` is a log identifier, RECOMMENDED to be a schema-less URL.
WitnessLog identifies logs by Ed25519 identity public key, so an operator
publishing C2SP checkpoints MUST choose a stable origin string and
publish the mapping from that origin to the identity key — exactly as CT
logs do. The log's signing key name SHOULD equal the origin.

**Time is deliberately absent.** A C2SP checkpoint body carries no
timestamp. Time is supplied only by cosigners, via the `time` line in
`cosignature/v1`. This is strictly stronger than the native
`SignedTreeHead`'s `timestamp_ms`, which is self-asserted by the signer
and, per THREAT_MODEL.md, carries no evidentiary weight on its own. In
the C2SP encoding a log structurally cannot assert its own time.
Converting native → C2SP therefore drops that field, and this is an
improvement rather than a loss.

**Verifier keys.** Encoded as `<name>+<hex key ID>+<base64(sig type ||
public key)>`, where the key ID is
`SHA-256(name || 0x0A || sig type || public key)[:4]`. Note that the
base64 field routinely contains `+` characters of its own; parsers MUST
split at exactly the first two `+` separators rather than the last two.
Key names and the key ID are guaranteed separator-free, so this is
unambiguous.

**Signature types used here:** `0x01` for Ed25519 note signatures,
`0x04` for timestamped Ed25519 checkpoint cosignatures. The same key
used for both gets a different key ID for each, which is the domain
separation the signature-type byte in the key ID preimage exists to
provide.

**Unknown signatures MUST be ignored.** This is what allows witness
cosignatures to accumulate on a log's own checkpoint without breaking
verifiers that know only the log's key. A signature from a *known* key
that fails to verify SHOULD reject the whole note; if no known key
verifies, the note MUST be rejected.

**Canonical origin.** For a cosignature to count toward a WitnessLog
verdict, the checkpoint's origin MUST be the log identity's canonical
origin:

```
witness-log/<64 lowercase hex characters of the identity public key>
```

Logs MAY use other origins with witnesses, but those cosignatures do not
count. Two reasons. (1) *No key exchange.* The origin names the only key
that can sign under it, so a witness can enroll any WitnessLog agent on
first contact with nothing to trust on first use ("open enrollment"):
it verifies the checkpoint under the key the origin names and refuses
anything else. (2) *One identity, one history.* If an agent could pick
origins freely it could show one history to some witnesses and a fork to
others under a different name, and each fork could collect its own
quorum. A single canonical origin per identity puts every witness on the
same record, so a fork is refused by every witness that saw the original.

**Cosignature receipts.** A cosignature becomes a §7 receipt with one
extra field, `c2sp_origin` (absent for native receipts, so native
receipts serialize byte-identically to v0.2):

```json
{ "witness_pubkey": "<hex>", "tree_size": 9, "root_hash": "<hex>",
  "witnessed_at_ms": 1791510030000, "signature": "<hex, 64 bytes>",
  "c2sp_origin": "witness-log/<identity hex>" }
```

A verifier checks such a receipt by rebuilding exactly what the witness
signed and verifying it under `witness_pubkey` (Ed25519, strict):

```
body    = c2sp_origin "\n" tree_size "\n" base64(root_hash) "\n"
message = "cosignature/v1\ntime " (witnessed_at_ms / 1000) "\n" body
```

and MUST reject the receipt unless: `tree_size`/`root_hash` equal the
dossier checkpoint's; `c2sp_origin` equals the canonical origin of the
checkpoint's `signer_pubkey`; and `witnessed_at_ms` is a whole number of
seconds (the cosignature signs seconds; sub-second digits would be
unsigned and could mislead freshness checks). Every field a verdict
depends on is therefore either signed by the witness or checked against
the signed checkpoint. A dossier carrying such receipts verifies fully
offline, with no access to the witnesses.

**Witness transport.** `witness-log witness serve` implements
`c2sp.org/tlog-witness` (`POST /add-checkpoint`) with the statuses that
specification requires: 200 (cosignature lines, each newline-terminated),
400 (malformed, more than 63 proof lines, or old size larger than the
checkpoint — an old genuine checkpoint arriving late looks identical, so
this is never treated as evidence of misbehaviour), 403 (no valid
signature from the log's key), 404 (unknown origin), 409 (body: the
witness's size in decimal and a newline, `Content-Type:
text/x.tlog.size`), and 422 (consistency failure, a proof sent from size
0, same size with a different root, or a size-0 checkpoint without the
empty-tree root). A witness MUST persist its new record durably before
returning a cosignature, and the size check and persist MUST be atomic.
A 422 is evidence of log misbehaviour ONLY when the log has signed two
different roots for the same size; a failing proof on its own is not,
since any third party can attach a junk proof to an honest checkpoint.
Witnesses therefore keep the last log-signed checkpoint they cosigned and
publish equivocation as an `EquivocationProof` (origin, log vkey, both
notes, each carrying only the log's signature) that verifies with the
log's key alone.
It additionally serves `GET /` (its directory entry and public keys) and
`GET /health`.

**Scope.** C2SP covers checkpoints and cosignatures only. Leaf encoding
(§3), key binding (§5), redaction (§8), dossiers (§9), and
operator/compute-provider diversity scoring remain WitnessLog's own and
have no C2SP equivalent. This is an interoperability boundary, not a
replacement for the native format.

## 9.4 Write receipts and silence proofs

A log MAY issue a **write receipt** when it accepts an event: a signed
statement binding the log identity to one `payload_hash` at one
`tree_size`:

```
message = "witness-log-write-receipt-v1" || lp(sig_alg) || lp(signer_pubkey) || lp(payload_hash as UTF-8 hex) || tree_size (8B BE) || issued_at_ms (8B BE)
```

The holder of a receipt can later prove censorship-by-omission: if
witnessed checkpoints of this log advance past `tree_size` and the
event never appears, the receipt plus those checkpoints are evidence a
third party can check with the log's key alone. A plain checkpoint is
not a write receipt: it commits to no event, so it proves nothing about
one (an earlier draft of the reference implementation made that mistake).

## 10. Open questions for v1.0

- Binary/CBOR dossier encoding for size and parsing-ambiguity reasons.
- Formal alignment pass against `draft-maintainer-1f916-agent-record` once
  that draft stabilizes further — tracked as a GOVERNANCE.md milestone, not
  blocking this version.
- Per-leaf signatures (today, leaf integrity is only guaranteed
  transitively via the checkpoint over the whole tree — a leaf can't be
  individually verified without also trusting the tree it's claimed to be
  part of, which is a fine trade-off pre-1.0 but worth revisiting).

## Adoption

This specification is published to be implemented. Anyone may implement
the wire format and verification procedure described here, in any
language, for any purpose, without using, linking or deriving from the
reference implementation; a conformant implementation is one that
reproduces every vector in `/corpus/` byte for byte, which is checkable
mechanically (`witness-log conform <dir>`). Interoperability with the
wider transparency-log ecosystem is by design (§9.3): WitnessLog
checkpoints are C2SP signed notes, and any `c2sp.org/tlog-witness`
witness can cosign them.

The reference implementation is licensed AGPL-3.0-only (see `LICENSE`):
derivatives of the *code*, including ones offered as a network service,
must stay open. That license governs the code, not the format: an
independent implementation of this specification is not a derivative
work of the reference implementation. Specification changes go through
the public process in `GOVERNANCE.md`, and conformance, not origin, is
what makes an implementation a WitnessLog implementation.

## Conformance

An implementation is conformant with this specification's current version when it reproduces every value in
`/corpus/*.json` exactly, byte for byte, from the described inputs. This is
enforced in CI via `witness-log conform` (see CONTRIBUTING.md) and is the actual
gate for claiming compatibility — not this document by itself.
