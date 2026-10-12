# SCITT mapping

How witness-log's objects correspond to the SCITT architecture
([RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html), Standards Track,
June 2026) and COSE Receipts ([RFC 9942](https://www.rfc-editor.org/rfc/rfc9942.html)),
where the two line up, where they do not, and a concrete proposal for
emitting SCITT-compatible objects. witness-log does **not** emit SCITT
objects today; everything under "Proposal" is a design for discussion, not a
shipped feature.

Short version: witness-log is the same shape of primitive as a SCITT
Transparency Service (an append-only RFC 6962 log, signed tree heads,
inclusion and consistency proofs, offline verification), but it collapses
two SCITT roles into one (each agent is both the Issuer and the operator of
its own log) and gets non-equivocation from independent witnesses instead of
from a separate service operator.

See also: [Comparison: SCITT](Comparison-SCITT) · [Spec and interop](Spec-and-Interop) ·
`spec/SPEC.md` §3–§9.

## Concept map

| witness-log | SCITT (RFC 9943 §3) | fit |
|---|---|---|
| agent identity key; canonical origin `witness-log/<hex>` | **Issuer** (CWT `iss` claim, `kid`) | good: one stable key-named identity |
| leaf (`0x01` intent, `0x02` result, …) with salted `payload_hash` | **Statement** (any serialisable information; may be a hash of the payload, §6.2) | partial: a leaf is a statement about an action, but it is **not individually signed** |
| — | **Signed Statement** (COSE_Sign1 by the Issuer) | gap: witness-log signs the tree, not each leaf (SPEC §5, §10) |
| the agent's own journal and tree | **Verifiable Data Structure** of a **Transparency Service** | good structurally: RFC 6962 tree = `RFC9162_SHA256` |
| the agent's process appending to its own log | **Transparency Service** (maintains the VDS and endorses its state) | divergent: the Issuer runs its own single-Issuer service |
| checkpoint (STH), signed by the identity key (§6) | the service's signed view of its log | good |
| checkpoint + inclusion proof for leaf *i* | **Receipt** (signed proof of inclusion, §3; RFC 9942) | good in content: "leaf *i* is at position *i* under this signed root" |
| write receipt (§9.4): "I accepted this hash at size N" | Receipt returned at **Registration** | close: same promise, different envelope |
| witness cosignature (`cosignature/v1`, §7, §9.3) | none; the nearest role is **Auditor** (checks consistency, §3, §4) | gap: SCITT has no third-party signature over tree heads |
| equivocation proof file (two log-signed roots, one size) | **Equivocation** (§3), detected by Auditors (§9.7) | concept matches; no SCITT evidence format |
| dossier (identity, leaves, checkpoint, receipts, bindings) | a set of **Transparent Statements** plus consistency evidence | no SCITT container |
| verifier's `--directory` and `--identity` | the Relying Party's trust anchors for services and Issuers (§9.3) | good |
| verdict (WITNESSED / CONSISTENT-UNWITNESSED / UNANCHORED / DIVERGED) | Relying Party validation policy (§7) | SCITT leaves policy to the RP; witness-log fixes four outcomes |
| `forget(i)`: delete salt, append `0x03` tombstone | §8: services can keep only hashes; the log "cannot be modified, deleted, or reordered" (§5.1.3) | compatible in spirit; SCITT specifies no erasure pattern |
| `HandoffAttestation` / `AuthorizationEvent` pairs + `bind` | two Issuers' Signed Statements about the same subject | expressible; no binding rule in SCITT |
| `ExternalAnchor` leaf (`0x07`) | a Receipt from someone else's service | good: a SCITT Receipt is exactly the kind of proof this leaf records |

## Where they align

1. **The data structure.** SPEC §4 is RFC 6962 §2.1 exactly (`0x00` leaf
   prefix, `0x01` node prefix, split at the largest power of two), and §7.1
   makes the RFC 9162 §2.1.4.2 consistency algorithm normative. That is the
   `RFC9162_SHA256` verifiable data structure (value `1` in RFC 9943's
   example) that COSE Receipts already profile.
2. **Offline verification.** RFC 9943 §4: a Receipt "is universally
   verifiable without online access to the TS". witness-log's verifier never
   touches the network.
3. **Trust inputs belong to the Relying Party.** RFC 9943 §9.3: Relying
   Parties should not accept statements without Receipts "issued by a TS
   they trust". witness-log §9.1: receipts are scored only against the
   verifier's own directory; the dossier's embedded list is display-only.
4. **Hash-only statements for privacy** (§6.2, §8) match witness-log's rule
   that only commitments leave the machine.
5. **Layering.** Both stay in the transparency layer and leave attestation,
   identity and authorization to RATS, WIMSE and OAuth, the decomposition
   used by [draft-kuehlewind-audit-architecture](https://datatracker.ietf.org/doc/draft-kuehlewind-audit-architecture/).

## Where they diverge

1. **Who operates the log.** SCITT separates Issuer and Transparency
   Service; the service's independence from Issuers is part of the trust
   model. In witness-log the agent is both, and independence comes from
   witnesses. A SCITT Relying Party that trusts "the TS" would, in a naive
   mapping, be trusting the very party it is auditing.
2. **Per-statement signatures.** SCITT requires each Signed Statement to be
   a COSE_Sign1 by its Issuer. witness-log leaves are unsigned and integrity
   is transitive through the identity-signed checkpoint (SPEC §10 lists
   per-leaf signatures as an open question). A single witness-log leaf
   cannot be shown as a standalone Signed Statement.
3. **Non-equivocation mechanism.** SCITT states non-equivocation as a VDS
   requirement (§5.1.3) and relies on Auditors with read access to detect
   violations (§4, §9.7); it defines no witness role, cosignature, or
   evidence format. witness-log's central mechanism is exactly that role,
   using `c2sp.org/tlog-witness`.
4. **Erasure.** RFC 9943 does not discuss erasure. witness-log's salted
   commitment + tombstone pattern keeps every Receipt valid after the
   content becomes unrecoverable; SCITT is compatible with it but does not
   say so.
5. **Encoding.** SCITT is CBOR/COSE throughout. witness-log uses
   length-prefixed binary for signed messages, C2SP signed notes for
   checkpoints and cosignatures, and JSON for dossiers.
6. **Time.** SCITT Statements carry Issuer-asserted claims; witness-log's
   C2SP form drops the log's own timestamp entirely and takes time only
   from witness cosignatures (§9.3).

## Proposal: two steps toward SCITT compatibility

### Step 1: anchor checkpoints in a SCITT Transparency Service (no spec change)

The agent registers its checkpoint as a Signed Statement with any SCITT
Transparency Service and records the returned Receipt as an `ExternalAnchor`
leaf, which already exists (SPEC §3.3):

- **Signed Statement**: COSE_Sign1, `alg` EdDSA, signed by the agent
  identity key; CWT claims `iss` = `witness-log/<identity hex>` (the
  canonical origin), `sub` = the same origin; payload = the C2SP checkpoint
  note body (origin, size, base64 root) as produced by
  `witness-log c2sp show`.
- **Receipt**: stored verbatim as `anchor_proof_json` (or its CBOR in a
  JSON wrapper), with `anchor_proof_hash = SHA-256(...)` committed in the
  leaf, `anchor_url` = the service's entry URL.

What this buys: a third party outside the witness set, with a standard
Receipt, attesting that this checkpoint existed by that time. What it does
not: today `verify` records anchors and checks the hash binding but does not
verify the anchor proof against the provider (CHANGELOG 0.3.4). Verifying an
RFC 9942 Receipt offline (given the service's key in the verifier's own
trust inputs) is a bounded piece of work and the natural first verifier
extension.

### Step 2: a witness-log receipt profile (needs discussion)

Export, for any leaf *i*, an RFC 9942 COSE Receipt for the `RFC9162_SHA256`
verifiable data structure:

- protected header: `alg` EdDSA, `kid` = identity key, `vds` =
  `RFC9162_SHA256`, CWT claims `iss` = canonical origin;
- verifiable data proof: the RFC 6962 inclusion proof for leaf *i*
  (tree size, index, audit path); `inclusion_proof(i)` already returns
  `(tree_size, root_hex, path)`;
- detached payload: the root of the checkpoint, so the Receipt verifies
  against the same root the identity signed in its STH;
- the leaf's canonical bytes (§3) supplied alongside, so the Relying Party
  recomputes `leaf_hash = SHA256(0x00 || bytes)`.

Two decisions this forces, which is why it is a proposal:

- **The signer.** The identity key would sign a COSE `Sig_structure` in
  addition to `witness-log-sth-v2`. Domain separation between the two is
  inherent (different message formats), but it is a second signing context
  for a long-lived key and should be specified, not improvised.
- **Carrying witness cosignatures.** A Receipt signed by the agent proves
  inclusion under the agent's root and nothing about independence. The
  witnesses' `cosignature/v1` signatures over the same checkpoint are what
  carry the independence; they need a place to travel with the Receipt
  (COSE countersignatures, an unprotected header holding C2SP cosignature
  lines, or a separate statement). This is a question for the SCITT and
  C2SP communities, below.

Until both are settled, the dossier remains the verification unit, and a
SCITT-facing deployment should use Step 1.

## Divergence list: draft-maintainer-1f916-agent-record

`spec/SPEC.md` §1 says witness-log aims for wire compatibility with
[`draft-maintainer-1f916-agent-record`](https://datatracker.ietf.org/doc/draft-maintainer-1f916-agent-record/)
"where the underlying primitive is the same" and that a divergence list was
future work. This is that list, against **-01** (12 August 2026,
individual draft, Informational, "1F916 Maintainer, The 1F916 Protocol
Project"). The draft and witness-log share a model (a CT-style per-agent
record, witnesses that check consistency before countersigning, a
verifier-supplied anchor rule, the same four verdict names, a key-custody
taxonomy). **They are not wire-compatible today**, and the divergences are
in exactly the places a second implementation would need to agree on.

| # | topic | draft -01 | witness-log (SPEC v0.3) |
|---|---|---|---|
| 1 | who signs checkpoints | registries; agents write to a registry | the agent's own identity key; no registry |
| 2 | checkpoint encoding | colon-delimited UTF-8: `1f916.checkpoint.v1:<log>:<tree_size>:<root_hex>:<created_at_ms>` | length-prefixed binary `witness-log-sth-v2` with `sig_alg` and signer key inside the signed bytes (§6); C2SP `tlog-checkpoint` note (§9.3) with no log timestamp |
| 3 | witness countersignature | `1f916.witness.v1:<registry_origin>:<log>:<tree_size>:<root_hex>`; C2SP not referenced | C2SP `cosignature/v1` (timestamped, Ed25519) or native `witness-log-witness-receipt-v2` (§7) |
| 4 | witness transport | fetch checkpoint, verify, verify consistency, countersign, publish | `c2sp.org/tlog-witness` `POST /add-checkpoint`, persist-before-cosign |
| 5 | refusals | unsigned refusal records count as evidence against a head | a refusal is never evidence; only two **log-signed** roots for one size are (§9.3, THREAT_MODEL "Accusations") |
| 6 | "witnessed" | a caller-pinned witness countersignature covers the checkpoint | receipts from ≥2 distinct independent `operator_org` in the verifier's directory, plus a count gate; majority gate advised against split views |
| 7 | "diverged" | includes "a refusal covers the head" and conflicting witnessed heads | any failed cryptographic, binding, structural or continuity check; equivocation is shown by `diff` / evidence files |
| 8 | entry types | key bind/rotate/revoke, seals, attestations, disputes/retractions, checkpoints, witness records | intent, result, memory, redaction, revocation, handoff, authorization, external anchor (§2) |
| 9 | linkage | predecessor hash per event plus Merkle tree | Merkle tree only |
| 10 | erasure | not addressed | salted `payload_hash`, `forget`, `0x03` tombstone (§8) |
| 11 | key model | Ed25519 identity bound to a handle; custody taxonomy incl. `household_held`; recovery requires a prior commitment | identity + per-run session keys with signed bindings (§5); custody field is unsigned and surfaced, never changes the verdict |
| 12 | canonical JSON | JCS (RFC 8785) for attestations and the dossier core | binary canonical leaves (§3); dossier is JSON with a schema, not hashed as a whole |

The draft also states its own two-implementation gate is not yet met. A
useful next step for both projects would be a small set of shared test
vectors for the parts that *are* the same primitive (RFC 6962 roots,
inclusion and consistency proofs), so that agreement there is checked
rather than assumed. The -01 text cites the SCITT architecture under a
reference that should be checked against RFC 9943.

## Questions for the IETF SCITT list and the C2SP community

Final, post-ready versions with venues and subjects:
`docs/launch/community-questions.md`. Posting is the maintainer's step;
answers get folded back into this page with the thread as the source.

1. **To the SCITT list.** RFC 9943 separates the Issuer from the
   Transparency Service and states non-equivocation as a property of the
   service's VDS, detected by Auditors. For a deployment where each Issuer
   (an AI agent) operates its own single-Issuer log and non-equivocation is
   instead provided by independent witnesses that verify a consistency
   proof before cosigning each tree head, does the working group see that
   as within the architecture's intent, and if so, is there an expected way
   to carry third-party cosignatures of the tree head alongside a COSE
   Receipt (for example COSE countersignatures, or a separate statement
   type)?
2. **To the SCITT list.** Statements about people's actions sometimes have
   to become unreadable later (for example GDPR Article 17). Has the group
   discussed a recommended pattern in which the Statement is a salted hash,
   the salt is held only by the Issuer, and erasure is a deleted salt plus a
   registered tombstone statement, so that every Receipt stays valid? Would
   guidance like that belong in a profile or BCP?
3. **To the C2SP community.** When a `tlog-witness` witness holds two
   checkpoints signed by the same log key for the same size with different
   roots, is there interest in (or existing work on) a common format for
   that evidence, so that equivocation proofs written by different witness
   implementations can be checked by the same tools? Relatedly, is there
   guidance on witnesses enrolling logs on first contact when the origin
   string itself names the log's verifying key?

## If this is wrong

Mapping errors are worth more than most bugs here. Open a PR against
`docs/wiki/SCITT-Mapping.md` with the RFC section or draft text.

## Sources (checked 2026-10-12)

- RFC 9943, An Architecture for Trustworthy and Transparent Digital Supply Chains: <https://www.rfc-editor.org/rfc/rfc9943.html>
- RFC 9942, CBOR Object Signing and Encryption (COSE) Receipts: <https://www.rfc-editor.org/rfc/rfc9942.html>
- draft-maintainer-1f916-agent-record-01: <https://datatracker.ietf.org/doc/html/draft-maintainer-1f916-agent-record-01>
- draft-kuehlewind-audit-architecture-01: <https://www.ietf.org/ietf-ftp/internet-drafts/draft-kuehlewind-audit-architecture-01.html>
- C2SP: <https://c2sp.org/tlog-witness>, <https://c2sp.org/tlog-checkpoint>, <https://c2sp.org/tlog-cosignature>
