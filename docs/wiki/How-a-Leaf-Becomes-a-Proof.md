# How a leaf becomes a proof

One event, followed from the moment an agent calls a tool to the moment a
stranger's verifier prints `WITNESSED`. Every hash on this page is pinned by
a vector in `corpus/`, so an implementation in any language can check itself
against the same bytes. Spec sections are in brackets.

We will follow a single event: an agent calls `transfer_funds(amount_usd=250)`.

---

## Stage 1: the payload

The Python decorator (or your own code) produces a payload: deterministic
JSON bytes (RFC 8785 canonical JSON: sorted keys, no whitespace, fixed
number and string forms).

```
{"args":{"amount_usd":250},"tool":"transfer_funds"}
```

This is the *content*. Nothing about it is special to witness-log; it could
be protobuf, a string, or 40 MB of PDF. witness-log never stores it: your
application keeps the content wherever it already lives. The tree (and the
journal) are about to commit to it without containing it.

## Stage 2: the salt and the payload hash [§8]

A 32-byte random salt is drawn and appended to `agent.jsonl.salts`. Then:

```
B            = (floor(len(payload) / 256) + 1) * 256        # 256 here: the payload is 50 bytes
bucket_pad   = len(payload) as u64 BE  ||  payload  ||  0x00 × (B − len)
payload_hash = SHA256( bucket_pad || salt || leaf_index as u64 BE )
```

Three things are happening:

- **The salt** makes the hash unguessable even for a payload with tiny
  entropy (`"yes"`, an email address). Without it, anyone holding the tree
  could confirm a guess. It also gives the erasure story later: delete the
  salt and the preimage is gone.
- **Bucket padding** hides the payload's exact length from anyone who
  sees only the tree. They learn "0–255 bytes", not "50".
- **The index** inside the hash binds the content to its position, so the
  same payload at two positions produces two different hashes and a leaf
  cannot be silently moved.

Corpus vector `11_payload_hash.json` pins this function exactly, including
the empty payload case.

## Stage 3: the leaf [§2–§3]

The leaf is the metadata record that enters the tree:

| field | value for our event |
|---|---|
| `leaf_type` | `0x01` ActiveIntent |
| `index` | 0 (this is the first leaf) |
| `timestamp_ms` | wall clock, self-asserted |
| `session_pubkey` | the hex of this process's session key |
| `payload_hash` | the 64-hex result of stage 2 |
| optional fields | absent (`redacted_index`, `revoked_identity`, handoff/authorization/anchor fields) |

Its **canonical encoding**, the exact bytes that will be hashed, is a fixed
concatenation where every variable-length field carries a 4-byte length
prefix and every optional field a presence byte:

```
01                              leaf_type
00 00 00 00 00 00 00 00         index
00 00 01 99 3f 2a 6b 10         timestamp_ms
00 00 00 40 <64 ASCII hex>      lp(session_pubkey)
00 00 00 40 <64 ASCII hex>      lp(payload_hash)
00                              redacted_index absent
00                              revoked_identity absent
```

Why so pedantic? Because two different leaves must never share one
encoding. Without length prefixes, `session_pubkey="aaaabbbb", payload_hash="cccc"`
and `session_pubkey="aaaa", payload_hash="bbbbcccc"` concatenate to the same
bytes and therefore the same Merkle hash: two structurally different events,
one commitment. Fixed widths "by convention" are not fixed widths "by
construction". Vector `01_leaf_encoding.json` pins the encoding of every
leaf type, and the three leaf types added later (0x05–0x07) append their
extra fields *only when present*, so adding them did not change the hash of
a single pre-existing leaf.

## Stage 4: the Merkle tree [§4]

```
leaf_hash  = SHA256( 0x00 || canonical_leaf_bytes )
node_hash  = SHA256( 0x01 || left || right )
```

The `0x00`/`0x01` prefixes are RFC 6962 domain separation: a leaf hash can
never be confused with an interior node, which closes the classic
second-preimage attack on naive Merkle trees.

After our intent leaf and its result leaf, the tree has two leaves and the
root is `node_hash(leaf_hash(L0), leaf_hash(L1))`. For sizes that are not a
power of two, RFC 6962 defines how the right-hand subtree is built from the
largest power of two that fits; `02_merkle_roots.json` pins roots for sizes
1 through 64.

The root is 32 bytes that commit to **every leaf and their order**. Change
one byte of one payload: its salt no longer matches, its payload hash
changes, its leaf hash changes, every node above it changes, the root
changes. Swap two leaves: both their `index` fields are now wrong *and* the
node order is wrong.

## Stage 5: the checkpoint [§6]

The identity key signs:

```
"witness-log-sth-v2" || lp("ed25519") || lp(identity_pubkey_hex) || tree_size (8B BE) || root (32B) || timestamp_ms (8B BE)
```

This `SignedTreeHead` is the log saying: *at this moment I had exactly these
N leaves in this order*. Note what is inside the signature: the algorithm
name (so it cannot be relabelled to a weaker one) and the signer's own key
(so the statement is about *whose* tree, not just a size and a root). The
identity key, not the session key, signs it, so the statement outlives the
process. `04_signed_tree_head.json` pins a vector.

Verifiers use strict Ed25519 (`verify_strict`): reject non-canonical
scalars and small-order components. Not because honest signatures are
affected but because two conformant verifiers must never disagree about one
dossier.

## Stage 6: the inclusion proof [§4]

To prove our leaf 0 is in a root of size N without revealing the other
leaves, the log emits the sibling hashes along the path from leaf 0 to the
root: `ceil(log2 N)` hashes. The verifier recomputes upward and compares
with the root in the signed checkpoint. `03_inclusion_proofs.json` pins
proofs for every leaf at every size up to 64.

This is what `evidence_window` uses to hand a regulator leaves 100–199 and
nothing else, each with its own proof to one checkpoint.

## Stage 7: the consistency proof and the witness [§7, §7.1, §9.3]

The agent now wants someone else to remember this checkpoint. It builds a
C2SP checkpoint note:

```
witness-log/<identity pubkey hex>        origin: the key IS the name, so no key exchange is needed
2                                        tree size
<base64 root>
— witness-log/<key> <base64 signature>   the log's own signature line
```

and POSTs it to each witness's `/add-checkpoint`, together with the
witness's last-known size and a **consistency proof** from that size to the
new one: the hashes needed to show the old tree is a prefix of the new one.
On first contact the old size is 0 and the proof is empty.

The witness verifies the proof with the RFC 9162 §2.1.4.2 algorithm, which
reconstructs **both** the old root and the new root from the proof and
demands both match. (The weaker variant that reconstructs only the new root
accepts forks whenever the old size is not a power of two; `06_consistency_proof.json`
and an exhaustive test over every `1 ≤ m < n ≤ 64` guard against that.)

If the proof verifies, the witness persists its new memory of this log
(size 2, this root) to disk, fsyncs, and *only then* returns a
`cosignature/v1` line: its signature over the checkpoint plus a timestamp
it asserts. Three organisations do this; the agent now holds three
receipts. The full protocol with its failure paths is in
[Witness protocol walkthrough](Witness-Protocol-Walkthrough).

## Stage 8: the dossier [§9]

Everything is assembled into one JSON file:

```
identity_pubkey        whose log this claims to be
leaves[]               index, type, timestamp, session key, payload_hash (never the payload itself)
checkpoint             the STH from stage 5
key_bindings[]         identity-signed statements vouching for each session key
revocations[]          if any
receipts[]             the cosignatures from stage 7
witness_directory      display only; never used for scoring
```

Schema: `spec/dossier.schema.json`, validated in CI.

## Stage 9: verification [§9.1–§9.2]

A verifier anywhere, offline, runs `witness-log verify dossier.json --identity <hex> --directory mine.json`:

1. **Checkpoint signature**: strict Ed25519 over the stage-5 message, with the key the checkpoint names.
2. **Identity pinned**: that key equals the `--identity` *the verifier* supplied. A forged dossier with flawless cryptography fails here, because the forger cannot sign with a key they do not have.
3. **Leaf structure**: every leaf parses; types are known; indices are 0..N dense.
4. **Key bindings**: every `session_pubkey` on a leaf has a binding signed by the identity; revocations honoured.
5. **Merkle continuity**: recompute stages 3–4 for all N leaves; the root must equal the checkpoint's root. One flipped bit anywhere fails here.
6. **Receipts**: each cosignature is verified against a public key found in *the verifier's* directory; receipts from unknown keys are ignored; duplicates by key are collapsed (a single witness re-signing at different timestamps counts once).
7. **Quorum**: count distinct `operator_org` values among valid receipts; apply the fraction threshold and `--min-witnesses`; report compute-provider diversity separately.

Then exactly one verdict:

- any of 1–5 fails → **DIVERGED** (30)
- no directory supplied → **UNANCHORED** (20): consistent, nothing external checked
- directory supplied, < 2 operators or gate not met → **CONSISTENT-UNWITNESSED** (10)
- otherwise → **WITNESSED** (0)

## What the proof actually says

When the verifier prints `WITNESSED`, the precise claim is:

> The holder of identity key K committed to a tree of exactly N leaves with
> root R; at least two organisations I trust independently saw that
> commitment and had verified it extended what they had seen before; the
> leaves in this file reproduce R exactly; and leaf 0, `transfer_funds(250)`,
> was in that tree at position 0 before the result at position 1.

It does **not** say the transfer happened, that the timestamp is accurate,
or that the agent's reasoning was sound. It says the record has not changed
since independent parties saw it, and that nobody can now produce a
different record under that key for that size without creating evidence of
having done so. That is what an audit trail is for.

Next: [Witness protocol walkthrough](Witness-Protocol-Walkthrough) ·
[Redaction explained](Redaction-Explained) · [Verification and verdicts](Verification-and-Verdicts)
