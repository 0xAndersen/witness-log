# RFC-0004: SCITT receipts for leaves (RFC 9942 COSE Receipts)

Status: Draft
Target: `witness-log receipt <dossier> <index>` and `verify-receipt` behind a Cargo feature in 0.5.x; spec text only after the signing-context question is answered
Related: `docs/wiki/SCITT-Mapping.md` (Step 2), SPEC §5 (identity key), §6 (STH), §9.3 (cosignatures)

## Motivation

SCITT (RFC 9943, architecture) and COSE Receipts (RFC 9942, June 2026,
Standards Track) standardise the artefact "this statement is included in
a transparent log": a COSE_Sign1 whose protected header names a
verifiable data structure and whose unprotected header carries an
inclusion proof. witness-log's tree is RFC 6962, which RFC 9942 names as
VDS `1`, `RFC9162_SHA256`, with proof types inclusion (`-1`) and
consistency (`-2`). A witness-log leaf and its inclusion proof are
therefore already the right shape; what is missing is the envelope.

Why bother, when the dossier already verifies offline: a dossier is
everything (every leaf). A **receipt** is one leaf plus the proof that it
is in a signed tree, which is what a counterparty wants to keep for one
transaction, what a SCITT-speaking relying party can verify with existing
libraries, and what the per-leaf disclosure (SPEC §8.1) needs to travel
with. `SCITT-Mapping.md` Step 2 describes this and lists the two decisions
it forces; this RFC proposes answers so they can be argued with.

## Design

### The receipt

For leaf `i` of a log with identity key `K` and checkpoint `(size, root)`:

```
COSE_Sign1 {
  protected: {
    1   (alg):  -8 (EdDSA)
    4   (kid):  bstr  — the 32-byte identity public key
    395 (vds):  1     — RFC9162_SHA256
    15  (CWT claims): { 1 (iss): "witness-log/<identity hex>",
                        6 (iat): witnessed_at or checkpoint time, seconds }
  },
  unprotected: {
    396 (vdp): { -1: [ inclusion proof: tree_size, leaf_index, [audit path hashes] ] },
    <witness-log private label, to be registered>: [ C2SP cosignature lines over the same (size, root) ]
  },
  payload: detached — the 32-byte root (the "signed tree head" of RFC 9942's RFC9162_SHA256 profile)
  signature: Ed25519 over Sig_structure("Signature1", protected, external_aad = <leaf canonical bytes, §3>, payload = root)
}
```

The relying party is given the receipt and the leaf's canonical bytes
(§3). It recomputes `leaf_hash = SHA256(0x00 || bytes)`, walks the
inclusion proof to the root, checks the root is the detached payload, and
verifies the signature under `kid`. Then, separately, it checks each
cosignature line in the unprotected header under keys in its own
directory, exactly as §9.3 verifies a `c2sp_origin` receipt, counting
distinct `operator_org` values. The verdict vocabulary is the dossier's
(WITNESSED / CONSISTENT-UNWITNESSED / UNANCHORED / INVALID per RFC-0002).

### The two decisions, answered

**1. A second signing context for the identity key.** The identity key
today signs four message families, each with a distinct ASCII prefix
(`witness-log-sth-v2`, `witness-log-key-bind-v1`, `witness-log-revoke-v1`,
`witness-log-write-receipt-v1`) plus the C2SP note signature (whose
message begins with the origin line). A COSE `Sig_structure` begins with
the CBOR text string `"Signature1"`. None of the existing prefixes can be
a valid CBOR encoding of that string, and `"Signature1"` cannot be a valid
start of any of the length-prefixed native messages, so the contexts are
disjoint by construction. The proposal: state that in SPEC §5 as a rule
("every message the identity key signs begins with a distinct,
fixed-length, mutually non-prefix tag; the table is …") so that adding a
context is a spec edit with a check, not an accident.

**2. Carrying witness cosignatures.** Proposed: as C2SP cosignature lines,
verbatim, in an unprotected header parameter under a private-use label
until IANA registration. They are over `(origin, size, root)` and so bind
to the detached payload and the issuer; they are not COSE
countersignatures (RFC 9338), which would require every witness to speak
COSE. Witnesses stay unchanged. A relying party with no witness-log code
can still verify the COSE_Sign1 and ignore the unknown header, reaching
UNANCHORED, which is the right ceiling for a verifier with no directory.

### Redaction interaction

A receipt for a leaf whose salt has been forgotten remains valid: it
commits to the leaf bytes (which contain only `payload_hash`), not the
payload. A receipt plus a disclosure (§8.1) proves content; a receipt
alone proves position and history. The receipt does not say whether the
leaf has since been redacted; a `0x03` leaf later in the tree does, and
the dossier is where to look.

## Wire changes

- Leaf encoding, STH, native receipts, redaction, dossier: **none**.
- New optional artefact (the receipt) and one new signing context for the
  identity key, documented in §5 under the rule above. No existing
  signature changes meaning.
- `kid` is the public key itself rather than a hash of it; RFC 9942 does
  not constrain `kid`, and witness-log's identity *is* the key.

## Corpus vectors needed

- `14_cose_receipt.json`: for the tree in `02_merkle_roots.json`, leaf 2
  of a 5-leaf tree: the protected header bytes (deterministic CBOR), the
  `Sig_structure` bytes, the receipt in hex, the leaf canonical bytes, and
  the expected verification result; a second case with one cosignature
  line in the unprotected header and the directory that makes it count.
- A negative vector: an inclusion proof for a different leaf index (MUST
  fail), and a receipt whose `iss` does not match `kid` (MUST fail).
- The "no two signing contexts share a prefix" property as a vector: the
  first bytes of each of the six message families, for a second
  implementation to assert disjointness mechanically.

## Backward compatibility

Additive. No dossier, verifier or witness changes behaviour. A log that
never issues receipts is unaffected. The feature is behind a Cargo
feature (`cose-receipts`) because it adds a CBOR dependency to a crate
that today has none, and `cargo deny` reviews it like any other.

## Open questions

1. Is the detached payload the root (as proposed, matching RFC 9942's
   RFC9162_SHA256 profile) or the leaf hash? The root lets one checkpoint's
   cosignatures cover every receipt issued against it; the leaf hash would
   make each receipt self-contained but puts the cosignature binding on
   the inclusion proof rather than the signed payload. The proposal is the
   root; the question has been drafted for the SCITT list
   (`SCITT-Mapping.md`, question 1).
2. Private-use header label for cosignature lines, or ask the C2SP
   community for a COSE registration of "C2SP note signature lines"? The
   second is better for everyone and slower.
3. Should the receipt be issued by the identity key (as proposed) or by
   the session key with the key binding attached? The identity key keeps
   receipts verifiable after the session ends and matches how the STH
   works; the cost is one more use of the long-lived key per receipt,
   which argues for batching (one receipt per checkpoint per requested
   leaf, not per append).
4. `iat`: the checkpoint's self-asserted time carries no evidentiary
   weight (THREAT_MODEL); the cosignatures' times do. Should `iat` be
   omitted and relying parties told to read the cosignature times?
   Proposed: omit it.

## How to comment

Open a thread in GitHub Discussions titled `RFC-0004` (or comment on the
pull request that added this file). Once questions 1 and 2 have a
proposal the project is comfortable with, the text goes to the IETF SCITT
list and the C2SP repository as drafted in `SCITT-Mapping.md`.
