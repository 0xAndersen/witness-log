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
  Ed25519 identity key, and covers every leaf. Leaves are not individually
  signed: each records the session key that wrote it, and the identity
  signs a binding for each session key (§5). A record a verifier accepts
  was committed to by that identity, and only that identity could have
  produced it.
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

WitnessLog shares its model and four of its five verdict names (all but
`Invalid`, §9.2) with
`draft-maintainer-1f916-agent-record` (individual draft, Informational),
but it is **not** wire-compatible with that draft: the draft uses
colon-delimited payloads, its own witness countersignature rather than
C2SP, shared registries rather than per-agent logs, and counts unsigned
refusals as evidence. The divergence list is maintained in the wiki's
SCITT mapping page (`docs/wiki/SCITT-Mapping.md`). Verify against the
draft text directly for anything load-bearing.

### 1.1 Which layer this is, and which layers it deliberately isn't

Trust infrastructure for autonomous agents decomposes into separable
layers, not one monolithic system — the decomposition described in
`draft-kuehlewind-audit-architecture` (an individual draft, not a working
group document), which composes RATS for attestation, SCITT for
transparency, WIMSE for identity and OAuth for authorization rather than
inventing a single system that does all four. WitnessLog deliberately occupies the **transparency** layer only:

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

Type-specific fields (`redacted_index`, `revoked_identity`,
`handoff_direction`, `counterparty_pubkey`, `handoff_state_hash`,
`authorization_event_kind`, `authorization_scope_hash`, `anchor_url`,
`anchor_proof_json`, `anchor_proof_hash`) are committed to the tree only
for the type they belong to (§3). A leaf that carries a field of another
type MUST be rejected as structurally invalid: under an unchanged root
such a field would be free to edit and would still be displayed. A 0x03
Redaction leaf's `redacted_index` MUST name a smaller index than its
own, and the marker types 0x03 and 0x04 MUST commit the all-zero
`payload_hash` (§8). Since 0.4.2; the reference, Go and TypeScript
verifiers all enforce this.

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
v1:  message = "witness-log-revoke-v1" || identity_pubkey (32B) || as_of_ms (8B BE) || reason (UTF-8 bytes)
v2:  message = "witness-log-revoke-v2" || identity_pubkey (32B) || as_of_ms (8B BE) || 0x01 || as_of_index (8B BE) || reason
signature = Ed25519_Sign(identity_signing_key, message)
```

v2 (RFC-0005, experimental since 0.4.3) adds `as_of_index`, the tree size
at which the revocation takes effect, under its own prefix so neither
version's signature verifies as the other. A statement with
`as_of_index` absent is v1 and serialises exactly as before. A verifier
that does not implement v2 MUST reject a statement carrying
`as_of_index` (its signature does not verify under the v1 message), so
the extension fails closed. Corpus vector 12 pins both messages and the
cut-off cases below.

Leaves signed by a revoked identity's sessions after `as_of_ms` MUST be
treated as untrusted by verifiers, and so MUST a checkpoint whose
`timestamp_ms` is at or after `as_of_ms`: whoever holds the key after
the revocation signed it. Both timestamps are set by the key holder, so a
verifier SHOULD apply revocations it knows about out of band (the
reference `VerifyContext::revocations`, `verify --revocations`) rather
than relying on the dossier to carry them.

With a v2 statement, a verifier MUST additionally reject every leaf
whose `index` is at or past `as_of_index` and every checkpoint whose
`tree_size` is greater than `as_of_index`, whatever their timestamps
say. When several revocations apply, the earliest `as_of_ms` and the
smallest `as_of_index` govern. The operator who revokes pairs the
statement with a witnessed checkpoint of size `as_of_index`: witnesses
refuse to cosign a different root at that size, so a holder of the
compromised key can neither rewrite the history below the cut-off nor
extend it in a way any verifier counts.

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

`sig_alg` is carried on every STH for crypto-agility: this field exists
specifically so a future signature algorithm can be introduced without
breaking the format or invalidating historically-issued checkpoints. See
`/corpus/04_signed_tree_head.json`.

**Implemented today: `"ed25519"` only.** The reference implementation
signs and verifies STHs, write receipts (§9.4), key bindings and
revocations (§5) and native witness receipts (§7) with Ed25519 and
nothing else. A verifier MUST reject any other `sig_alg` value
(`SthError::UnsupportedAlgorithm` in the reference implementation; the
value is also inside the signed message, so relabelling an Ed25519
signature fails on its own terms as well). No second value has been
assigned.

**Verification strictness (normative):** verifiers MUST use strict Ed25519
verification, the behavior of `ed25519-dalek`'s `verify_strict` after
`VerifyingKey::from_bytes`, for every signature in a dossier (checkpoints,
key bindings, revocations, receipts, signed notes): the public key A must
decode (y is read mod p, so an encoding with y ≥ p decodes, as does x = 0
with the sign bit set); s must be canonical (s < L, RFC 8032); R must
decode; A and R must not be of small order (order 1, 2, 4 or 8) in any of
their fourteen encodings; and [s]B − [k]A, with k = SHA-512(R ‖ A ‖ M)
over the encodings as given, must encode to exactly R's bytes
(cofactorless, so a non-canonical R never verifies). Mixed-order points
are not refused: `verify_strict` does not refuse them, and a signature
with one verifies when the torsion cancels. A key binding's session key
must decode as a point too, though it signs nothing there. The reason is
interoperability, not any weakness in honest signatures: Ed25519
implementations historically disagree on degenerate edge-case signatures,
and two conformant WitnessLog verifiers disagreeing about whether the same
dossier is valid would be worse than either answer alone. Honestly
generated signatures are unaffected by this requirement.
`/corpus/16_ed25519_strict.json` holds the edge cases (every small-order
encoding as A and as R, mixed-order points, non-canonical s, R and A) with
the reference's answer for each, and dossiers that embed them.

**Planned, not implemented: ML-DSA-44** (FIPS 204). This is the
post-quantum algorithm the C2SP transparency ecosystem chose:
`c2sp.org/tlog-cosignature` v1.1.0 (2026-10-07) specifies ML-DSA-44
cosignatures and says new deployments SHOULD use them, and
`c2sp.org/signed-note` v1.1.0 assigns signature type byte `0x06` to
timestamped ML-DSA-44 checkpoint cosignatures. witness-log's own
`sig_alg` identifier for ML-DSA-44 is **reserved but unassigned**: no
string value is fixed by this document, no vector exists in `/corpus/`,
and no implementation accepts one. Until a spec revision assigns the
identifier and the corpus vectors, an STH or receipt claiming any
ML-DSA value is invalid. An earlier draft of this paragraph named
`"ml-dsa-65"` and `"falcon-512"` as candidates; neither was ever
implemented and neither is planned. The migration mechanism (how a log
moves from one identity algorithm to another without breaking
historically issued checkpoints) is an open question (§10) and is the
subject of a future RFC under `docs/rfcs/`.

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

Operators and compute providers are counted by **normalised label**, so
case and spacing variants of one name are one operator. The
normalisation is exact, because two verifiers that bucket labels
differently count different numbers of independent operators and so
reach different verdicts: split the label on runs of Unicode White_Space
characters (the `White_Space` property: U+0009–U+000D, U+0020, U+0085,
U+00A0, U+1680, U+2000–U+200A, U+2028, U+2029, U+202F, U+205F, U+3000;
not U+FEFF), drop empty pieces, join the rest with one U+0020, then apply
Unicode full default lowercasing (`toLowercase(X)`, Unicode §3.13): the
`UnicodeData.txt` mapping plus the locale-independent mappings of
`SpecialCasing.txt`, so U+0130 becomes `i` U+0307 and a capital sigma
becomes final `ς` under the Final_Sigma condition and `σ` otherwise.
Nothing else is folded: no Unicode normalisation form, no confusables
(see THREAT_MODEL.md). This is Rust's `split_whitespace` then
`to_lowercase`; JavaScript's `\s` and `trim` are not White_Space, and
Go's `strings.ToLower` omits SpecialCasing. Characters whose case
properties changed between Unicode versions (U+0295 is no longer
Lowercase as of Unicode 17) and characters newer than an
implementation's Unicode tables can still normalise differently;
directory curators should not accept labels that depend on them. `/corpus/15_evidence_and_args.json` exercises the rule.

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

Erasure covers the salted payload only. A 0x07 ExternalAnchor leaf keeps
`anchor_url` and `anchor_proof_json` in cleartext in the leaf, so there
is nothing a forget can erase; implementations MUST refuse to forget it
rather than report an erasure that did not happen. 0x05 and 0x06 leaves
keep an unsalted hash of their state or scope (§3.1, §3.2) as the
cross-log commitment; forgetting them erases the payload and leaves that
hash, which is confirmable by anyone who already holds the content.

Where salts live is an implementation matter, with one normative
requirement: a forgotten salt MUST be erased from every store the
implementation controls, not merely marked. The reference implementation
keeps a journal's salts in a `<journal>.salts` sidecar (one record per
leaf, rewritten without the entry on `forget`) and treats that file as key
material.

**Explicitly out of scope for this hardening**: leaf-type visibility,
timestamp correlation, and tree-position metadata are not hidden by this
scheme. See `THREAT_MODEL.md`.

### 8.1 Worked example: checking a disclosure

A **disclosure** is the holder of a log showing a third party what one
leaf's payload was: the payload bytes and the leaf's salt. The third party
checks it by recomputing `payload_hash` and comparing with the leaf in a
dossier (or an evidence window) whose checkpoint they have already
verified. Nothing here is new wire format; it is §8 run forwards, and the
numbers below are corpus vector `11_payload_hash.json`, case `one_byte`,
so any implementation can reproduce them.

Inputs:

```
leaf_index  = 1
payload     = 0x41                                   ("A", 1 byte)
salt        = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a   (32 bytes)
```

Step 1, `bucket_pad(payload)`. `len = 1`, so `B = (floor(1/256)+1)*256 =
256` and the padded block is 8 + 256 = 264 bytes: the length as a
big-endian u64, the payload, then 255 zero bytes.

```
0000000000000001 41 00 00 … 00        (8 + 1 + 255 = 264 bytes)
```

Step 2, the preimage: `bucket_pad(payload) || salt || leaf_index as u64 BE`,
264 + 32 + 8 = 304 bytes. Its last 40 bytes are the salt and the index:

```
… 00 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a 0000000000000001
```

Step 3, `payload_hash = SHA256(preimage)`:

```
8aa14c4fa46a06fea8177b48cf682fe8636f404200b56337a82ac8868ade6c99
```

A disclosure of `("A", that salt)` for leaf 1 is accepted when the leaf's
`payload_hash` field equals this value **and** the leaf is in a verified
tree; the hash alone proves nothing about position or history. The same
payload and salt at `leaf_index = 9` hash to
`be4b3ecf8dd3c8aa6eb6c6c2605bb6c647c3b678c6fe8ce890698607357725dc` (case
`same_payload_other_index`), which is why a disclosure names the index.
The empty payload is a real payload (case `empty`:
`dc77bb84d2b2c6fa34fcefc1b99f257e2ff49031e0c3c182f656aff56e170ac0`), and
a payload of 256 bytes moves to the next bucket (520-byte padded block,
cases `exactly_one_bucket`, `bucket_plus_one`).

What a disclosure cannot do: once the salt has been forgotten (§8, a 0x03
Redaction leaf names the index), no party can produce one, including the
log's own operator. That is the erasure property. A verifier offered a
"disclosure" for a redacted index MUST treat it as unverifiable, not as
false. In Python the check is six lines of `hashlib`; the reference
implementation exposes it as `witness_log_core::redaction::payload_hash_with_salt`,
`witness_log_core::redaction::verify_disclosure(leaf, payload, salt)`
does the whole check (Python `witness_log.verify_disclosure`, wasm
`verify_disclosure`), and `witness-log log disclose <journal> <index>`
prints the leaf, payload hash and salt a verifier needs (since 0.4.0).

### 8.2 Payload bytes and canonicalisation (informative)

This specification hashes **bytes**. How an application turns a structured
value (a tool call, a JSON object, an AP2 mandate) into bytes is outside
the wire format, with one practical consequence: every field that is
compared *across* two logs (`handoff_state_hash` §3.1,
`authorization_scope_hash` §3.2, and any application-level commitment such
as a commerce mandate hash carried in a payload) only matches when both
sides hashed identical bytes. `{"a":1,"b":2}` and `{"b":2,"a":1}` are the
same JSON value and different SHA-256 inputs.

For JSON the recommended canonicalisation is RFC 8785 (JSON
Canonicalization Scheme, JCS): sorted members, no insignificant
whitespace, fixed number and string serialisation. The Python binding's
`canonical_json` is RFC 8785 since 0.4.0; the encoding it produced before
(sorted keys and no whitespace, but non-ASCII escaped as `\uXXXX` and
Python's float formatting) is kept as `sorted_json` so a verifier can
recompute the payload hash of a leaf written by an older release.
Implementations in other languages should use a JCS library rather than
their default JSON encoder when the bytes will be compared with another
party's. The commerce profiles (`docs/wiki/Commerce-Profile.md`; AP2, x402
and Verifiable Intent in `witness_log.profiles`) define
`mandate_hash = SHA256(JCS(mandate))` on this basis. None of this is normative for the tree: a leaf whose
payload was encoded differently is still a valid leaf; it just will not
bind to the counterparty's.

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

**Reading a dossier (normative).** A verifier reads a dossier exactly as
the reference deserialises one, or two verifiers can reach different
verdicts on the same bytes. The text is RFC 8259 JSON in UTF-8, without a
byte order mark. It nests at most 1000 arrays and objects deep: counting
only `[` and `{` outside strings, with the dossier object at depth 1, no
array or object anywhere in the text, an ignored key's value included, is
deeper than 1000, and a verifier stops reading at the 1001st level rather
than building anything deeper. (A dossier any implementation writes nests
at most 5 deep, and the deepest value the reference reads, a
`fleet_anchor`, 127 in all; the limit is an order of magnitude below the
10,000 of Go's `encoding/json`, so no JSON library's own limit decides.)
The dossier and every struct in it (checkpoint, leaf,
receipt, directory and directory entry, key binding, revocation, custody
threshold) is a JSON object, never an array. A key that names one of the
struct's fields appears at most once and matches the field name exactly
(case-sensitive, after unescaping); any other key is ignored. Every u64
is an integer literal with no sign, fraction or exponent, at most
2^64 − 1, and is read exactly (above 2^53 too, where JavaScript's
`JSON.parse` would round it); `leaf_type` is at most 255. String, boolean
and list fields have that JSON type; optional fields may be absent or
`null`, defaulted ones (`witness_receipts`, `witness_directory`,
`key_bindings`, `revocations`, and an entry's `runtime` and
`is_project_operated`, a binding's `custody`) may be absent but not
`null`. A unit enum value is its name or `{"<name>": null}`. A field's
string and every key of a struct contain no unpaired UTF-16 surrogate
escape. A text that breaks any of these is not a dossier: the CLI exits
`2`, and no verifier returns any verdict other than `Invalid` for it.
`/corpus/17_dossier_parsing.json` pins the cases, including u64 values
above 2^53, the case of hex in each field the verdict compares, the depth
limit at 1000 and 1001, and numbers at the edge of binary64. A message
saying why a text is not a dossier, or why a check failed, quotes at most a
bounded part of the input.

**Every input nests at most 1000 deep (normative).** The nesting limit
covers every JSON input a verifier reads, not only the dossier: a trusted
directory (`{"witnesses": [...]}` or a bare array of entries), revocations
the verifier knows of out of band (one statement or an array of them) and
each evidence item (an equivocation proof, bare or as `witness serve`
writes it, `{"kind": "equivocation", "proof": {...}}`). Each nests at most
1000 arrays and objects deep, counted as above with its own top-level
value at depth 1, wherever the nesting is, an ignored key's value
included. A deeper one is refused exactly as a malformed one is: the CLI
exits `2`, a library returns an error or raises, and no verdict is given.
Where one JSON text carries several inputs (a binding's array of evidence
items, the wasm build's options object), the limit applies to each input
in it, and the carrying text may nest only the levels it adds (the wasm
options object at most 1002: itself and the evidence list around an
item); the options object is read as a struct, its keys matched exactly.
`/corpus/17_dossier_parsing.json`'s `inputs` pin the limit for each input
at 1000, 1001 and 100,000 levels and with brackets inside strings.
(Before this rule, Go refused these inputs 10,000 levels deep while the
reference read a directory or revocations of any depth and an evidence
item only to serde_json's 128 levels.)

**Reading the other inputs (normative).** Each is UTF-8 JSON, read as the
dossier is. A trusted directory is `{"witnesses": [...]}` (a struct) or a
bare array of entries, and revocations are one statement or an array of
them; anything else, `null` included, is refused. An evidence item is an
object: the proof itself, or one that carries the proof, an object, under
`"proof"`. Unlike a dossier's structs, of a key given twice the last
counts, and only it is read: every other member (an earlier copy of a key,
and beside `"proof"` every member of the item, an `"origin"` included) is
ignored, its value only checked as JSON syntax, so it may hold `1e400` or
an unpaired surrogate escape. The proof's `origin`, `log_vkey`,
`earlier_note` and `conflicting_note` are strings, and they and every key
of the item and of the proof contain no unpaired surrogate escape, as a
dossier's field strings and struct keys. A verifier given an input as an
already-parsed value (TypeScript's options) checks the value as it is: a
parser such as `JSON.parse` has already kept only the last copy of a
repeated key and dropped whatever was nested under the others, so such a
verifier also takes the text. Corpus 17's `inputs` pin each case.

**JSON Schema.** `spec/dossier.schema.json` (JSON Schema 2020-12) states
the exact shape of a dossier and of every object in it: field names,
hex lengths, enumerations, which fields are optional. The reference
implementation's test suite validates every dossier it produces, and
every leaf in `/corpus/`, against it, so the schema cannot drift from
the code. A document that validates is well-formed, not verified:
signatures, Merkle continuity, bindings and quorum are §9.1–§9.2.

The schema also lists `fleet_anchor`, an optional field of the
experimental RFC-0001 prototype (0.6.0). It is not part of this
specification: a verifier MUST NOT let it change a verdict unless the
caller explicitly opts in, and a verifier that does not implement RFC-0001
ignores it like any unknown field, except that the reference reads its
value as a JSON value: when present and not `null`, a text whose
`fleet_anchor` holds a string with an unpaired surrogate escape, a number
that is infinite once rounded to the nearest binary64 (ties to even:
`1.7976931348623158e308` is finite, `1.7976931348623159e308` and `1e309`
are not), or nesting more than 126 levels below the dossier object is not a
dossier (corpus 17).

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
- **`subject_org`** — the organisation the verifier knows operates the
  log being checked, compared with each witness's `operator_org` after
  the same label normalisation (§7: Unicode White_Space runs collapsed
  and trimmed, then full default lowercasing; a `subject_org` that
  normalises to the empty string names nobody). Witnesses of that operator still count as receipts but
  never as independent operators. A verifier can otherwise tell that a
  witness shares the log's operator only when the trusted directory lists
  the log's own key as a witness, so an organisation that runs both an
  agent and a witness would count as independent of itself. A
  `subject_org` that names no operator in the directory changes nothing.
  It can only lower a verdict, never raise one.

`witness-log verify` exposes these as `--identity <hex>`, `--directory
<path.json>` and `--subject-org <org>`. The Python binding's
`verify_dossier_json` exposes them as optional `expected_identity_pubkey`,
`trusted_directory_json` and `subject_org` parameters; the TypeScript,
Node and wasm verifiers take `subjectOrg` / `subject_org`, and the Go
library `Options.SubjectOrg`. Omitting both is a legal, meaningful verification run — it
proves the dossier doesn't contradict itself — but the reachable verdict
is capped accordingly; see §9.2.

A verifier may also bring evidence it already holds about the same
identity. Neither input raises a verdict; each can only make a valid
dossier `Diverged` (§9.2):

- **`known_heads`** — zero or more `(tree_size, root_hash)` pairs the
  verifier already trusts for this identity (a checkpoint it kept, a
  cosignature it saw). A dossier whose first `tree_size` leaves do not
  reproduce `root_hash` contradicts it. A known head larger than the
  dossier's tree cannot be checked against it and is reported in
  `known_heads_unchecked`, not treated as an error. Written as
  `<size>:<root hex>`, the size is any unsigned 64-bit integer in
  canonical decimal (no sign, no leading zero) and the root 64 hex
  digits; Unicode White_Space around either is ignored (U+FEFF is not
  White_Space). Anything else is the caller's error, not a verdict.
- **`evidence`** — zero or more witness equivocation proofs (§9.3). A
  proof counts only if its origin is this identity's canonical origin
  `witness-log/<identity hex>` and both of its notes verify under the
  verifier key built from that origin: name the origin, key the
  identity, key ID computed from the two (§9.3, "Verifier keys"). The
  proof's own `log_vkey` must equal that key field for field, key ID
  included, and is never used to choose which signature lines count. Then
  the identity signed two different roots for one tree size.

`witness-log verify` exposes these as `--known-head <size>:<root hex>`
and `--evidence <file>`, both repeatable. An evidence item is a JSON
object: either the proof itself or, as `witness serve` writes it, an
object carrying the proof under `"proof"`
(`{"observed_unix":…,"kind":"equivocation","proof":{...}}`). The proof is
an object whose `origin`, `log_vkey`, `earlier_note` and
`conflicting_note` are strings; other keys are ignored. Any other item (an
array, a `null` proof, a missing or non-string field) is the caller's
error (exit 2, an exception from a library), never a proof that silently
fails to count. `/corpus/15_evidence_and_args.json` pins these rules.

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

Verification produces exactly one of five verdicts:

| Verdict | What it means | What it does NOT mean |
|---|---|---|
| `Witnessed` | Every cryptographic and structural check passes, AND a `trusted_directory` was supplied, AND the valid receipts from witnesses in that directory come from at least **two distinct independent operators** (project-operated witnesses all count as one bucket; witnesses sharing the subject's own operator count as none, where the subject's operator is the `operator_org` of a directory entry whose key is the log's identity key, and also the verifier's `subject_org` when supplied, §9.1), AND the receipt count meets the caller's threshold. Diversity is reported as two separate fractions (operator, compute provider) but the gate is the absolute independent-operator count, because a fraction scales with the receipt count and a single colluding operator could satisfy any fraction with enough keys. | Proof against a colluding operator with a captured witness set — see THREAT_MODEL.md's "Witness independence" section. Only as strong as the trusted directory actually is. |
| `ConsistentUnwitnessed` | Every cryptographic and structural check passes, a `trusted_directory` WAS supplied, but witness coverage is absent, below threshold, or entirely project-operated. | Equivocation resistance. A single-node log can show different histories to different verifiers undetected. |
| `Unanchored` | Every cryptographic and structural check passes, but no `trusted_directory` was supplied at all (regardless of what the dossier's own `witness_directory` or `witness_receipts` claim). | Anything about authenticity to a party the verifier didn't already trust. This is the ceiling for a fabricated dossier — see §9.1. |
| `Diverged` | Every check passes, AND the dossier contradicts evidence the verifier supplied about the same identity (§9.1): a known head whose root its first `tree_size` leaves do not reproduce, or an equivocation proof that verifies for this identity. | That this file is the false copy. Divergence is a relation between two histories of one identity, this dossier and the one the evidence commits to; which one a counterparty was shown is a separate question. |
| `Invalid` | Any cryptographic, identity-binding, structural-validity, key-binding or revocation, or Merkle-continuity check FAILS. | — treat as evidence of tampering, fabrication, a mismatched `expected_identity_pubkey`, or an honest artifact whose non-cryptographic metadata is inconsistent (a leaf timestamp edited after signing fails structural validation the same way); the verifier's job is to report which check failed, not to assume intent. An invalid file establishes nothing about the identity, including that it equivocated. |

Precedence: `Invalid` takes precedence over the other four — any failed
check caps the verdict there regardless of witness coverage or other
evidence, and contradictions are only evaluated for a dossier that passes
every check. `Diverged` takes precedence over `Witnessed`,
`ConsistentUnwitnessed` and `Unanchored`: cosignatures on one history do
not cancel proof of a second. A verifier given neither known heads nor
evidence cannot return `Diverged`; two valid, conflicting copies of one
log are compared with `witness-log diff`, which exits `30` for them. Before 0.5.0 every failed check was reported as `Diverged`
(RFC-0002).

The report states why: `failures` lists the failed checks of an
`Invalid` dossier and `contradictions` the known heads or proofs a
`Diverged` one contradicts (both empty otherwise; their wording is not
normative), and `known_heads_unchecked` lists known heads larger than the
dossier as `"<size>:<root hex>"`.

**Split-view safety.** The report also states `split_view_unsafe`: true
when the verdict is `Witnessed` but the valid receipts from distinct
trusted witnesses are not a strict majority of the trusted directory
(`2 × valid_receipts ≤` the number of witnesses in it). A conflicting
history for the same identity could then have been cosigned by the rest
of the directory without any witness seeing both. The verdict stays
`Witnessed`, because the receipts did verify; what is unsafe is the
inference that no conflicting history exists. The reference CLI exits
`11` for it by default, and a caller that accepts a sub-majority gate
says so explicitly (`--allow-sub-majority`).

**Exit codes.** `witness-log verify` returns the verdict as its exit
status: `0` Witnessed (split-view safe, or accepted under
`--allow-sub-majority`), `11` Witnessed with `split_view_unsafe`, `10`
ConsistentUnwitnessed, `20` Unanchored, `30` Diverged, `40` Invalid, `2`
a usage error or unreadable input. `/corpus/13_verdicts.json` is a
verification vector: whole dossiers, a trusted directory, equivocation
proofs, and for each case the expected verdict, exit code and report
fields.

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

### Machine-readable result

`witness-log verify --json` (and the Go CLI's `--json`) prints one object
described by `spec/verify-output.schema.json`: the verdict, the exit code,
the inputs that were pinned (`identity_pinned`, `directory_pinned`,
`subject_org`, the gates) and `report`, which is also the report object
every binding returns (Python `verify_dossier_json`, wasm, Node,
TypeScript). Fields are only ever added; an existing field keeps its name,
type and meaning, and consumers MUST ignore fields they do not know. The
wording of `failures` and `contradictions` entries is not part of the
contract; whether each list is empty is. The process exit status equals
`exit_code`. A test in the Python suite validates the reference CLI's
output and the binding's report against the schema on every CI run.

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
first. Certificate Transparency built that community over roughly a
decade, and the protocols and tooling that came out of it
(`c2sp.org/tlog-witness`, `github.com/transparency-dev/witness`) are what
this section adopts. Speaking their protocol lets an existing witness
cosign a witness-log checkpoint without implementing anything specific
to this specification; `witness-log witness serve` can in turn cosign
any `tlog-checkpoint` log it is configured for.

**What that does and does not give a witness-log today** (state of
<https://witness-network.org> as checked on 2026-10-12): the shared
witness configuration service is labelled experimental; it publishes
`testing` and `staging` log lists and states that a `production` list is
"not available yet"; every log is admitted by a community maintainer
after an application that names the origin, an Ed25519 (type `0x01`)
vkey, the expected checkpoint rate and a contact. Logs are configured by
origin, one at a time. A witness-log identity is one origin, so a fleet
of agents is a fleet of applications; the realistic path onto existing
operators is one aggregate log per organisation, which is RFC-0001 under
`docs/rfcs/` (a proposal, not part of this specification; 0.6.0 ships an
experimental prototype, `witness-log fleet` and `verify
--accept-fleet-anchor`, described in the RFC). Until then,
the witnesses that cosign witness-log checkpoints are the ones operators
run with `witness-log witness serve` (open enrollment) or configure by
hand.

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
provide. `c2sp.org/signed-note` v1.1.0 also assigns `0x06` to timestamped
ML-DSA-44 cosignatures; witness-log does not produce or verify those
yet (§6), and a verifier treats such a line as an unknown signature
(ignored, not counted) until a spec revision adds it.

**Unknown signatures MUST be ignored.** This is what allows witness
cosignatures to accumulate on a log's own checkpoint without breaking
verifiers that know only the log's key. A signature from a *known* key
that fails to verify SHOULD reject the whole note; if no known key
verifies, the note MUST be rejected.

**Malformed lines are not unknown signatures.** Every witness-log
verifier parses a note the same way before deciding which keys it knows,
and rejects the whole note when any signature line is malformed: a line
that does not start with an em dash and a space; a key name that is
empty or contains `+` or any Unicode White_Space character (the
signed-note rule for key names, applied to every line as
`golang.org/x/mod/sumdb/note` applies it); a payload that is not
canonical base64 (padding bits zero, so one value has one encoding) or
is shorter than a key ID plus one byte; or more than 64 signature lines
(signed-note requires accepting at least 16). The root hash line of a
checkpoint is canonical base64 too. U+FEFF and U+007F are not
White_Space: a key name containing them is merely unknown.

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

The receipt's `tree_size` is the index the event is due at: the log
promises that every checkpoint larger than `tree_size` has the leaf with
this `payload_hash` at index `tree_size`. (The payload hash itself commits
to its index, §8. The reference implementation issues a receipt only for a
leaf it already holds, with `tree_size` set to that leaf's index.)

The holder of a receipt can later prove censorship-by-omission. The
evidence is the receipt, the later checkpoints of the same log with their
witness receipts, and the log's leaves. A checkpoint *counts* when its
`tree_size` is greater than the receipt's, it verifies under the
receipt's key, and it was cosigned by witnesses in the verifier's trusted
directory from at least two distinct independent operators (the bar of
`Witnessed`, §9.2: project-operated witnesses and the log's own operator
never count). A verifier concludes *censored* only when all of these hold:

1. the write receipt verifies under the log's key, and the verifier knows
   of no revocation of that key (§5): a receipt's `issued_at_ms` and
   `tree_size` are its signer's own claims, so nothing shows it was signed
   before the key was revoked, or by whoever stole it;
2. at least the required number of distinct checkpoints count;
3. no two of them commit to different roots for one size (that is
   equivocation, a different finding);
4. the supplied leaves reproduce the root of every one of them, up to the
   largest: so they are exactly the log's leaves, and an accuser cannot
   remove the event from them. Leaves that reproduce the largest but not
   a smaller one show the log signed two histories (a fork), which is
   equivocation too;
5. the event's `payload_hash` is not among those leaves, up to the largest
   counted checkpoint (leaves beyond it are not witnessed and are not
   looked at).

The event is *present* when 1, 3 and 4 hold for at least one counted
checkpoint and the leaf at index `tree_size` carries its `payload_hash`.
The `payload_hash` at another index among those leaves is neither: the log
broke the position it signed for, but did not leave the event out.
Anything less is inconclusive, never an accusation, and an unwitnessed
copy of the leaves can neither accuse nor acquit. A third party holding
the same bundle reaches the same conclusion. A plain checkpoint is not a
write receipt: it commits to no event, so it proves nothing about one (an
earlier draft of the reference implementation made that mistake). Before
0.6.1 the reference implementation checked 1, 2 with a single trusted
receipt, and 5 against the caller's leaf list without 3 and 4, so a list
with the event removed produced an accusation against an honest log
(review III, H1 and M1). Until the review of `witness-log prove-silence`
it also called an event present wherever it was in the supplied leaves,
witnessed or not and at any index, and applied no revocations.

## 10. Open questions for v1.0

- Binary/CBOR dossier encoding for size and parsing-ambiguity reasons.
- Formal alignment pass against `draft-maintainer-1f916-agent-record` once
  that draft stabilizes further — tracked as a GOVERNANCE.md milestone, not
  blocking this version.
- Per-leaf signatures (today, leaf integrity is only guaranteed
  transitively via the checkpoint over the whole tree — a leaf can't be
  individually verified without also trusting the tree it's claimed to be
  part of, which is a fine trade-off pre-1.0 but worth revisiting).
- Algorithm migration: assigning the ML-DSA-44 `sig_alg` identifier (§6)
  and defining how a log's identity moves to it.

Proposals that would change §2–§9 are written up as RFCs under
`docs/rfcs/` before any code or corpus change (`docs/rfcs/README.md`
describes the process). Open at the time of writing: RFC-0001 (per
organisation fleet checkpoint log), RFC-0003 (DNS TXT self-registration
of witnesses), RFC-0004 (SCITT receipts). An RFC is not part of this
specification until its text lands here with corpus vectors. RFC-0002
(verdict strictness and an INVALID verdict) landed in 0.5.0 as §9.1–§9.2
with corpus vector 13.

## Adoption

This specification is published to be implemented. Anyone may implement
the wire format and verification procedure described here, in any
language, for any purpose, without using, linking or deriving from the
reference implementation; a conformant implementation is one that
reproduces every encoding vector in `/corpus/` byte for byte, which is
checkable mechanically (`witness-log conform <dir>`), and reaches the
decisions in its verification vector (Conformance, below). Interoperability with the
wider transparency-log ecosystem is by design (§9.3): WitnessLog
checkpoints are C2SP signed notes, and any `c2sp.org/tlog-witness`
witness can cosign them.

The reference implementation is licensed Apache-2.0 (see `LICENSE` and
`NOTICE`; releases through 0.3.4 were AGPL-3.0-only). That license governs
the code, not the format: an independent implementation of this
specification is not a derivative work of the reference implementation,
and this specification may be implemented by anyone under any license. Specification changes go through
the public process in `GOVERNANCE.md`, and conformance, not origin, is
what makes an implementation a WitnessLog implementation.

## Conformance

An implementation is conformant with this specification's current version when it reproduces every value in
the encoding vectors `/corpus/01_*.json` to `/corpus/12_*.json` exactly, byte for byte, from the described inputs,
and, if it verifies dossiers, returns the expected verdict, exit code and report fields for every case in the
verification vectors `/corpus/13_verdicts.json`, `/corpus/15_evidence_and_args.json` (which also says which
inputs a verifier must refuse), `/corpus/16_ed25519_strict.json` (whose signatures must also each get the stated
answer from the implementation's Ed25519 check) and `/corpus/17_dossier_parsing.json` (which also says which texts
are not dossiers, and which directory, revocations and evidence texts a verifier must refuse). The encoding vectors are enforced in CI via `witness-log conform`
(see CONTRIBUTING.md); the verification vectors are run by each verifier's own test suite. Together they are the actual gate for
claiming compatibility — not this document by itself. `/corpus/14_fleet_anchor.json` pins the experimental RFC-0001
prototype for the verifiers that implement its opt-in and is not part of conformance.
