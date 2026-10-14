# Glossary

Every term used in the wiki, the CLI output and the spec, in one place.
Spec section numbers refer to `spec/SPEC.md`.

**Agent.** Any autonomous process whose actions you want on the record. To
witness-log an agent is simply the holder of an identity key writing to one
journal.

**Binding (key binding).** A statement signed by the identity key saying
"session key S is mine, as session number N, from time T [until T']". One
per process run. Lets a verifier trace every leaf back to the identity even
though each run used a different session key. §5. See
[Keys and identity](Keys-and-Identity).

**Bucket padding (`bucket_pad`).** Zero-padding a payload to the next
256-byte bucket, with its real length prefixed, before hashing. Hides the
exact payload length from anyone who sees only the tree. §8.

**C2SP.** The Community Cryptography Specification Project; publisher of
`tlog-checkpoint`, `signed-note`, `tlog-cosignature` and `tlog-witness`,
the transparency-log formats and witness protocol witness-log speaks. §9.3.

**Canonical origin.** `witness-log/<64 lowercase hex of the identity
public key>`. The C2SP log name for a witness-log; the name *is* the key, so
witnesses can verify without key exchange. §9.3.

**Checkpoint / Signed Tree Head (STH).** `(tree_size, root_hash,
timestamp_ms)` signed by the identity key. The log's statement "at this
moment I had exactly these N leaves in this order". What witnesses cosign.
§6.

**Consistency proof.** RFC 6962 proof that a tree of size N is a prefix of a
tree of size M: nothing before N was rewritten. Witnesses demand one before
cosigning. §7.1.

**CONSISTENT-UNWITNESSED.** Verdict, exit 10: the dossier verifies
internally and a directory was supplied, but witness coverage fell short
of the gate (fewer than two operators, or below `--min-witnesses`/threshold).

**Cosignature.** A witness's signature over a checkpoint, with a timestamp
the witness asserts (`cosignature/v1`). Becomes a *receipt* in a dossier.

**Custody.** Self-asserted, unsigned field on a binding saying how the
session key is held (`self_held`, `kms`, `hsm`, `platform_held`,
`session_delegated`, threshold, `undisclosed`). Shown beside the verdict,
never folded into it. §5.

**Directory (witness directory).** The list of witness entries (key,
`operator_org`, URL, compute provider) that *a verifier* trusts, obtained
out of band. Receipts are scored only against it. The public `registry/` is
one source for building yours.

**DIVERGED.** Verdict, exit 30: the dossier passes every check but
contradicts evidence the verifier brought about the same identity, a
`--known-head` it does not reproduce or a verifying equivocation proof
(`--evidence`). `diff` reports it for two valid, conflicting copies. The
identity has signed two histories. Before 0.5.0 this name also covered
failed checks, which are now INVALID.

**Dossier.** The portable, offline-verifiable JSON file: identity, leaves,
checkpoint, bindings, revocations, receipts, display-only directory copy.
`spec/dossier.schema.json`. §9.

**Equivocation.** Presenting two different histories under one key: two
signed checkpoints for one tree size with different roots. By a log: the
thing witnesses exist to catch (422 + evidence file). By a witness: the
thing persist-before-cosign and the backup rule prevent.

**Evidence file.** `evidence/<sha256(origin)>.json` written by a witness
when a log provably equivocated: two log-signed checkpoints, same size,
different roots. Self-contained; `witness verify-evidence` checks it, and
`verify --evidence <file>` makes a valid dossier of that identity DIVERGED.

**Evidence window.** A range of leaves each carrying an inclusion proof to
one checkpoint, for handing a reviewer a slice of the log without the rest.

**ExternalAnchor (0x07).** A leaf recording that a party entirely outside
the log (Sigstore Rekor, an RFC 3161 TSA) committed to a checkpoint at a
moment in time. Corroborated time without a witness network. §3.3.

**Fleet.** Several witnesses on one host under one operator (`fleet.py`).
Adds capacity and availability, not independence: one `operator_org`.

**Identity key.** The agent's long-lived Ed25519 keypair. Signs
checkpoints, bindings, revocations, write receipts. Its public half is the
agent's name. Lives in the journal header. §5.

**Inclusion proof.** RFC 6962 proof that one leaf is in a root: the sibling
hashes up the path. `ceil(log2 N)` hashes. §4.

**Independence.** Scored by distinct `operator_org` among valid receipts,
deduplicated by witness key. WITNESSED requires ≥2. Project-operated
witnesses share one bucket. Compute-provider diversity is a second,
separately reported axis. §7.

**Intent / Result.** The two leaf types (0x01, 0x02) the decorator and MCP
server write around every tool call: what the agent decided, before; what
happened, after.

**INVALID.** Verdict, exit 40: a concrete check failed (checkpoint
signature, identity, leaf structure, key bindings or revocations, Merkle
continuity). The file was altered after signing, fabricated, or is not the
log of the identity you pinned; it establishes nothing about the identity.
Takes precedence over every other verdict. Reported as DIVERGED (30)
before 0.5.0.

**Journal.** `agent.jsonl`: header with the identity seed, then one JSON
line per leaf and per binding. Plus `agent.jsonl.salts` (salts) and
`agent.jsonl.lock` (writer lock). The persistence format of a log.

**Known head.** A `(tree_size, root)` the verifier already trusts for an
identity, from a receipt it kept or a cosignature it saw:
`verify --known-head <size>:<root hex>`. A dossier whose first `size`
leaves give a different root is DIVERGED; one larger than the dossier is
listed in `known_heads_unchecked` and changes nothing.

**Leaf.** One event's metadata: index, type, timestamp, session key,
payload hash, and type-specific fields. Canonically encoded (§3) and hashed
into the tree. Eight types (§2). The payload itself is never in a leaf.

**Memory (PassiveMemory, 0x00).** A leaf for something the agent observed
or was told, neither intent nor result.

**Merkle tree.** RFC 6962 binary hash tree over leaf hashes with
domain-separated leaf (`0x00`) and node (`0x01`) prefixes. The root commits
to every leaf and their order. §4.

**`min_witnesses` / `--min-witnesses`.** Absolute floor on the number of
valid receipts for WITNESSED, alongside the fraction threshold. Use it with
directories of more than a handful of entries. A floor at or below half
the directory is allowed; a WITNESSED result below a majority exits 11.

**Open enrollment.** Witness mode accepting any log whose canonical origin
verifies its own checkpoint. No registration; the key is the name.

**`operator_org`.** The directory field naming the organisation that
controls a witness's machine and key. The independence label. `unspecified`
shares a bucket with every other unspecified witness.

**Payload.** The content of an event (tool arguments, a result, a memory).
Hashed into the leaf; stored by *your* application, never by witness-log.

**`payload_hash`.** `SHA256(bucket_pad(payload) || salt || index)`. What
the tree commits to. §8.

**Persist-before-cosign.** The witness rule: write and fsync the new
remembered head *before* returning the cosignature, so a crash can never
make the witness contradict itself.

**Receipt.** A witness cosignature carried in a dossier, verifiable against
the witness's public key. Meaningful only when that key is in the
verifier's directory. §7.

**Redaction (0x03).** The tombstone leaf appended when a salt is erased,
naming the forgotten index. Carries no payload; its hash is all zeros. §8.

**Registry.** `registry/witnesses/` in the repo: validated directory
entries contributed by operators. A source for building a directory, not a
directory in itself.

**Retry-After.** HTTP header a witness sends with 429/503. All witness-log
clients honour it up to 60 s.

**Revocation.** Identity-signed statement that the identity is invalid from
a time; leaves after it are untrusted. Forward-only. Also a leaf type (0x04).
§5.

**Salt.** 32 random bytes per leaf, stored in the `.salts` sidecar outside
the tree. Makes payload hashes unguessable; deleting one is how an entry is
erased. §8.

**Session key.** Ephemeral Ed25519 keypair for one process run, recorded
on each leaf it writes, vouched for by a binding. §5.

**Split view.** A log showing one history to some witnesses and another
to the rest, so two conflicting dossiers each reach WITNESSED and no
witness saw both. Ruled out among honest witnesses when the cosigners are
a strict majority of the directory. The report's `split_view_unsafe` is
true for a WITNESSED dossier whose cosigners are not; `verify` exits 11
for it by default.

**Tree size.** Number of leaves. With the root, the whole state of a log.

**UNANCHORED.** Verdict, exit 20: internally consistent, but no trusted
directory was supplied so nothing external was checked. An attacker can
produce this at will; it is not a trust verdict.

**Verdict.** Exactly one of WITNESSED (0, or 11 when split-view unsafe),
CONSISTENT-UNWITNESSED (10), UNANCHORED (20), DIVERGED (30), INVALID (40).
§9.2. See [Verification and verdicts](Verification-and-Verdicts).

**`VerifyContext`.** The verifier's inputs: expected identity, trusted
directory, minimum receipts, revocations it knows of, known heads and
equivocation proofs. The trust boundary; nothing in it comes from the
dossier.

**Witness.** A service with one key and a memory of the last head it
cosigned per log. Verifies a consistency proof, then cosigns; refuses forks.
Speaks `c2sp.org/tlog-witness`. See [Witness protocol walkthrough](Witness-Protocol-Walkthrough).

**WITNESSED.** Verdict, exit 0: proofs verify, identity pinned, and at
least two independent operators from the verifier's directory cosigned the
checkpoint. Exit 11 instead when those witnesses are not a strict majority
of the directory (`split_view_unsafe`), unless `--allow-sub-majority`.

**Write receipt.** Identity-signed statement "I accepted this
`payload_hash` at this `tree_size`". With later witnessed checkpoints,
proves censorship-by-omission if the leaf never appears. §9.4.
