# Three questions for the SCITT and C2SP communities (final drafts)

Ready to post as written. Each is self-contained, names what we built
only as context, asks one thing, and links to the artefact that lets the
reader check the claim instead of taking it. Post from the maintainer's
own account; do not post from automation.

Venues:

- SCITT working group list: `scitt@ietf.org` (subscribe at
  https://www.ietf.org/mailman/listinfo/scitt). Plain text, one topic
  per mail, subject prefixed with the draft name when one applies.
- C2SP: a discussion on https://github.com/C2SP/C2SP (the specs repo;
  `tlog-witness` and `tlog-cosignature` issues live there), cross-posted
  to the transparency-dev community channel if the maintainer has access.

Post 1 and 2 to SCITT as two separate mails on different days; post 3 to
C2SP. Reply to every answer within a day; fold corrections into
`docs/wiki/SCITT-Mapping.md` and the RFCs with the mail archived as the
source.

---

## 1. SCITT list: single-Issuer logs with witness cosignatures

Subject: `[scitt] Single-Issuer logs with third-party tree-head cosignatures: within the architecture's intent?`

Hello,

I maintain witness-log (https://github.com/0xAndersen/witness-log), a
per-agent transparency log for autonomous software agents: each agent is
its own Issuer and runs its own RFC 6962 Merkle log, and non-equivocation
comes from independent witnesses that verify a consistency proof before
cosigning each tree head over c2sp.org/tlog-witness, rather than from a
shared Transparency Service plus Auditors.

RFC 9943 states non-equivocation as a property of the Transparency
Service's verifiable data structure, detected by Auditors. Two questions:

1. Does the working group see a deployment where every Issuer operates a
   single-Issuer log, with non-equivocation supplied by witness
   cosignatures, as within the architecture's intent, or as a different
   trust model that should not call itself SCITT-compatible?
2. If it is within intent, is there an expected way to carry third-party
   cosignatures of a tree head alongside a COSE Receipt: COSE
   countersignatures on the receipt, a separate statement type registered
   in the same log, or something the group has already discussed?

Our current mapping, with the places we think we diverge from
draft-maintainer-agent-record listed, is here:
https://github.com/0xAndersen/witness-log/wiki/SCITT-Mapping. A draft of
how we would emit COSE Receipts is RFC-0004 in the repository. Corrections
to the mapping are more useful to us than agreement.

Thanks,
[name]

---

## 2. SCITT list: erasure with receipts intact

Subject: `[scitt] Erasable statements: salted hash + Issuer-held salt + tombstone. Prior discussion?`

Hello,

Follow-up to my earlier mail about per-agent logs. A practical problem
for any log of actions taken on people's behalf is that some statements
must later become unreadable (GDPR Article 17 and similar), while every
Receipt already issued must stay valid.

The pattern we use: the registered Statement is
SHA-256(pad(payload) || salt || index) with a fresh 32-byte salt held
only by the Issuer; erasure deletes the salt and registers a tombstone
statement naming the index. Receipts, inclusion and consistency proofs
are untouched; the payload is unrecoverable; the erasure itself is on the
record. Vector 11 in our conformance corpus pins the bytes.

Has the group discussed a recommended erasure pattern, and if this one
(or a better one) were written up, would it belong in a profile, a BCP,
or nowhere in SCITT because it is an Issuer-side concern? Pointers to
prior threads welcome.

Thanks,
[name]

---

## 3. C2SP: a common equivocation-evidence format, and enrollment by origin

Title: `tlog-witness: common format for equivocation evidence; enrolling logs whose origin names their key`

When a tlog-witness witness holds two checkpoints signed by the same log
key for the same tree size with different roots, it has proof the log
equivocated. Our witness writes that as a small JSON object: origin, the
log's vkey, and the two signed notes re-encoded with only the log's
signature, so anyone with the key checks both and sees the conflict
without trusting the witness. Example and checker:
https://github.com/0xAndersen/witness-log/blob/main/crates/witness-log-network/src/tlog_witness.rs
(`EquivocationProof`).

Two questions:

1. Is there interest in, or existing work on, a common format for this
   evidence so proofs written by different witness implementations can
   be checked by the same tools? If there is appetite, I would draft a
   short spec in the C2SP style with test vectors.
2. Our logs' origins are `witness-log/<hex of the log's Ed25519 key>`, so
   a witness can verify a log's signature from the origin alone and
   enroll it on first contact without configuration. Is there guidance on
   whether a tlog-witness witness should ever enroll a log that way, and
   on how such self-naming origins should be treated in witness policy
   (rate limits, state growth, listing)?

Our checkpoints and cosignatures verify with golang.org/x/mod's note
package and transparency-dev/formats' cosignature/v1 verifier unchanged
(`clients/go/interop` in the repository runs that check in CI), so the
format questions above are the only interop gap we know of.

[name]
