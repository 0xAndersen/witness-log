# Concepts

Ten terms cover the whole system. Section numbers refer to `spec/SPEC.md`.

**Leaf (§2–3).** One event. Eight types: PassiveMemory (0x00),
ActiveIntent (0x01), ActiveResult (0x02), Redaction (0x03), KeyRevocation
(0x04), HandoffAttestation (0x05), AuthorizationEvent (0x06),
ExternalAnchor (0x07). A leaf carries its index, type, timestamp, the
session key that wrote it, and `payload_hash`; the payload itself is never
stored in the tree.

**payload_hash (§8).** `SHA256(bucket_pad(payload) || salt || index)`.
The salt is random per leaf and lives outside the tree. Forgetting the
salt is how an entry is erased: the hash stays, the content is
unrecoverable, every proof still verifies.

**Merkle tree (§4).** RFC 6962 construction over leaf hashes. The root
commits to every leaf and their order. Inclusion proofs show one leaf is in
a root; consistency proofs show a newer root extends an older one without
rewriting anything.

**Identity key and session key (§5).** The identity key is the agent's
name: generated once, kept forever, signs checkpoints. Each process run
gets a fresh session key; a signed *key binding* ties it to the identity.
Restart = new session, same identity, provably continuous.

**Checkpoint / Signed Tree Head (§6).** `(tree_size, root, timestamp)`
signed by the identity key. This is what witnesses cosign and what a
verifier rebuilds the tree against.

**Journal.** The persistence format: one JSON line per leaf, header holds
the identity key, `<journal>.salts` holds the salts. Append-only, torn
tails healed on resume, locked against double writers.

**Witness (§7, §9.3).** A separate process, ideally run by a separate
organisation, that cosigns checkpoints over `c2sp.org/tlog-witness`. It
remembers the last head per log, demands a consistency proof, and refuses
forks. Its cosignatures become *receipts* in a dossier.

**Dossier (§9).** The portable, offline-verifiable file: identity, leaves,
checkpoint, key bindings, revocations, receipts, and a display-only copy
of the directory. JSON Schema in `spec/dossier.schema.json`.

**Directory.** The list of witnesses *the verifier* trusts, obtained
out-of-band (the public `registry/` is one source). Receipts are scored
only against it, never against the dossier's own list.

**Verdict (§9.2).** Exactly one of WITNESSED (0; 11 when the cosigners
are not a strict majority of the directory), CONSISTENT-UNWITNESSED (10),
UNANCHORED (20), DIVERGED (30: valid, but contradicts a head or an
equivocation proof the verifier brought), INVALID (40: a check failed).
See [Verification and verdicts](Verification-and-Verdicts).

## The flow, end to end

```
agent process                          witnesses (≥2 operators)        anyone, later
─────────────                          ────────────────────────        ─────────────
intent leaf ─┐
result leaf ─┼─► journal + salts
   …         ┘
checkpoint (signed) ──► POST /add-checkpoint + consistency proof ──► cosignature
                                                                    │
dossier.json  ◄────────────────────── receipts ─────────────────────┘
      │
      └──────────────────────────────────────────────────────────────► witness-log verify
                                                                        --identity <key> --directory <trusted>
                                                                        → WITNESSED / exit 0
```
