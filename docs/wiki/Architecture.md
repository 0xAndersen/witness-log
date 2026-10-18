# Architecture

This page explains how witness-log is put together and, more importantly,
*why* each piece is where it is. If you are deciding whether to build on it,
audit it, or implement it in another language, start here.

## The one-paragraph version

An agent appends events to a local, append-only log. Each event is hashed
with a private salt into an RFC 6962 Merkle tree. Periodically the agent's
long-lived **identity key** signs a **checkpoint**: the tree's size and
root. The agent sends that checkpoint, with a consistency proof from the
last one, to several **witnesses**: small services run by other
organisations that remember the last head they saw for each log and refuse
to cosign a contradicting one. The checkpoint plus the witnesses'
cosignatures plus the leaves go into a **dossier**, one JSON file. Anyone
with the dossier, the agent's public key and their *own* list of trusted
witnesses can verify, offline, that the history is unaltered since
independent parties saw it. Any single entry can later be erased by
deleting its salt, without disturbing a single proof.

## Layers

```
┌───────────────────────────────────────────────────────────────────────┐
│  5. Integrations    Python decorator · MCP server · framework guides   │
│                     CLI (any language via exit codes)                  │
├───────────────────────────────────────────────────────────────────────┤
│  4. Verification    Dossier · VerifyContext · DossierReport · verdicts │
│     (network)       quorum: operator & compute-provider diversity      │
├───────────────────────────────────────────────────────────────────────┤
│  3. Witnessing      c2sp.org/tlog-witness client + WitnessService      │
│     (network)       directories · selection · receipts · evidence      │
├───────────────────────────────────────────────────────────────────────┤
│  2. Durability      JournaledLog: JSONL journal · .salts sidecar ·     │
│     (core)          lock · torn-tail healing · dead-PID recovery       │
├───────────────────────────────────────────────────────────────────────┤
│  1. Commitment      WitnessLog: leaves · salted payload hashes ·       │
│     (core)          RFC 6962 tree · identity/session keys · STH        │
└───────────────────────────────────────────────────────────────────────┘
```

Each layer only depends on the ones below it, and each is useful alone:

- **Layer 1** is a pure data structure. No I/O. This is what the
  conformance corpus (`corpus/`) pins down byte for byte, and what an
  independent implementation must reproduce. Everything load-bearing in
  the cryptography lives here.
- **Layer 2** makes layer 1 survive processes dying. It adds nothing to
  the trust model; it exists so an agent that crashes mid-write resumes with
  a tree that still matches its file.
- **Layer 3** is how a history becomes *anchored* in someone else's memory.
  The client side submits; the server side (`WitnessService`) is a
  state machine with no I/O that any embedder can host.
- **Layer 4** is the only place verdicts are decided. It takes a dossier
  and a `VerifyContext` and returns a report. Nothing in layers 1–3 ever
  says "trusted".
- **Layer 5** is sugar. The Python decorator and MCP server are thin; the
  CLI is the reference embedding of everything.

The split between `core` and `network` is also a split in *who needs to
read the code*: a cryptographer auditing the construction reads `core`
(a few thousand lines); a security team deciding whether to trust a verdict
reads `network::verify`.

## Data flow

```
   agent process                    disk                   witnesses (other orgs)       verifier (anyone, later)
   ─────────────                    ────                   ──────────────────────       ────────────────────────
   tool call ──► intent leaf ──┐
   tool runs                   ├─► agent.jsonl   (leaf metadata + payload hashes, bindings)
   return    ──► result leaf ──┘    agent.jsonl.salts (one 32-byte salt per leaf)
                                         │
   identity key signs ◄──────────────────┘ tree_size, root
   checkpoint (STH)
        │  POST /add-checkpoint: checkpoint + consistency proof from last cosigned size
        ├─────────────────────────────────────────────► witness A (org 1)  ─┐
        ├─────────────────────────────────────────────► witness B (org 2)   ├─ remember head, verify
        └─────────────────────────────────────────────► witness C (org 3)  ─┘  proof, cosign
                                                              │ cosignatures
   dossier.json ◄─────────────────────────────────────────────┘
   (identity, leaves, checkpoint, bindings, receipts)
        │
        └───────────────────────────────────────────────────────────────────► verify(dossier,
                                                                                 expected identity,
                                                                                 MY directory)
                                                                               → WITNESSED / exit 0
```

Three arrows never exist, and their absence is the design:

1. **No arrow from the dossier into the verifier's trust inputs.** The
   expected identity and the trusted directory come from the verifier's
   own configuration. The dossier can *display* a directory; it cannot
   *supply* one. This is why a fabricated dossier cannot reach WITNESSED.
2. **No arrow from a witness to any server.** A witness is self-contained
   and talks to nobody but clients. There is no coordinator, no consensus
   round, no chain to sync. Witnesses do not even know about each other.
3. **No arrow from the verifier to the network.** Verification is a
   function of a file and two local inputs. It works on an air-gapped
   machine in ten years.

## The trust boundary, precisely

A verdict is computed from three inputs. Only one comes from the party
being audited.

| input | supplied by | if it is wrong |
|---|---|---|
| the dossier | the agent (or whoever holds its journal) | internal checks fail → INVALID; or it is simply a different, self-consistent log → caught by the next two, or DIVERGED if it contradicts a head or equivocation proof the verifier also brings |
| the expected identity public key | the verifier, out of band | you verify *some* agent's honest log, not the one you meant; `identity_pinned=false` tells you so |
| the trusted witness directory | the verifier, out of band | you count receipts from witnesses you have no reason to trust; the fix is to curate the directory |

The second and third inputs are deliberately *not* automated by
witness-log. There is no "fetch the official directory" step, because an
official directory would be the single point of trust the whole design
avoids. The public `registry/` is a convenience for building your own.

## What is different about this design

Each of these is a specific choice with a specific reason; together they
are the argument for treating witness-log as the standard shape of an agent
audit trail.

**Intent before result.** Two leaves per action, the first written before
the tool runs. A log that only records outcomes cannot distinguish "decided
and failed" from "never decided"; this one can. Frameworks get it for free
from the decorator or MCP server.

**Salted erasure that preserves proofs.** `payload_hash = SHA256(bucket_pad(payload) || salt || index)`,
salt stored outside the tree. Deleting the salt erases the content
permanently; the hash, the root, every inclusion proof and every witness
cosignature remain valid. A Redaction leaf records that the erasure
happened. This is the property GDPR Article 17 needs and hash chains and
blockchains structurally cannot provide. ([Redaction explained](Redaction-Explained))

**Two-tier keys with signed bindings.** A permanent identity key signs
checkpoints and vouches for ephemeral per-process session keys. A restart
is a new session on the same identity, provably continuous, and a
checkpoint stays verifiable after the process that produced it is gone.
Key custody is disclosed per binding (`self_held`, `kms`, `platform_held`,
…) and surfaced, never silently averaged into the verdict. ([Keys and identity](Keys-and-Identity))

**Witness independence is scored, not assumed.** WITNESSED requires
cosignatures from at least two distinct `operator_org` values in *the
verifier's* directory, deduplicated by key; compute-provider diversity is
reported as a separate axis; project-operated witnesses collapse into one
bucket so the project cannot vouch for itself. Many systems count
signatures; this one counts organisations.

**Persist-before-cosign and equivocation evidence.** A witness writes its
new memory to disk, fsyncs and renames *before* the cosignature leaves the
process, so a crash can never make it contradict itself. When a log sends
two signed roots for one size, the witness refuses (422) and stores both
signatures as a self-contained evidence file anyone can verify with the
log's public key. Misbehaviour becomes a portable artefact, not an
allegation. ([Witness protocol walkthrough](Witness-Protocol-Walkthrough))

**Correct consistency verification.** Witnesses verify RFC 9162 §2.1.4.2
consistency proofs that reconstruct *both* roots. Implementations that
reconstruct only the new root accept forks when the old size is not a power
of two; witness-log ≤0.3.0 had that bug, found it, fixed it, and pinned it
with an exhaustive test and a corpus vector. The spec now requires the
strict algorithm.

**Signed-message hygiene.** Algorithm identifier, signer key and (for
receipts) the log's key are *inside* the signed bytes, not alongside them,
closing algorithm-downgrade and receipt-reattribution attacks. Every
variable-length field in the canonical leaf encoding is length-prefixed and
every optional field has a presence byte, so two different leaves can never
share one encoding.

**C2SP interoperability.** Checkpoints are expressible as
`c2sp.org/tlog-checkpoint` notes with `cosignature/v1`, and the witness
speaks `c2sp.org/tlog-witness`. The witnesses already running for the Go
checksum database and Sigstore could cosign a witness-log without learning
anything new. The hardest problem in transparency is social, not
cryptographic; speaking the existing protocol inherits an installed base.
([Spec and interop](Spec-and-Interop))

**Write receipts.** A log can hand back a signed statement "I accepted
this payload hash at size N". If witnessed checkpoints later pass N and the
log's leaves, which must reproduce those checkpoints' roots, lack the
event, that is portable proof of censorship-by-omission, something a
plain checkpoint cannot provide.

**Offline, file-shaped verification with exit codes.** The proof is a
file; the verifier is a static binary; the verdict is an integer. No
account, no API, no uptime dependency between the audited party and the
auditor.

**Deliberately only the transparency layer.** Attestation (RATS),
identity (WIMSE) and authorization (OAuth, UCAN, …) are other layers.
witness-log logs *that* a delegation or handoff happened without becoming an
authorization or messaging system, which is why it composes with whatever
stack an integration already has.

## What it is not

- Not a blockchain: no consensus, no tokens, no global ordering, no
  replication of your data to strangers. Only 40-byte checkpoints leave the
  machine. ([Comparison](Comparison))
- Not a data store: the journal and tree hold salted *commitments* to
  payloads, never the payloads. You keep the content where you already
  keep it and can prove, with the salt, that it matches. Leaf types,
  timestamps and tree positions are visible metadata ([Threat model](Threat-Model)).
- Not an authority on time: a log's own `timestamp_ms` is self-asserted.
  Corroborated time comes from witness cosignatures and, optionally,
  `ExternalAnchor` leaves (Rekor, RFC 3161).

## Reading order for a deep review

1. `spec/SPEC.md` §2–§4 and `crates/witness-log-core/src/{leaf,merkle,redaction}.rs` with `corpus/` open alongside.
2. §5–§6 and `identity.rs`, `sth.rs`.
3. `journal.rs` for the durability invariants (torn tail, lock).
4. §7, §9.3 and `crates/witness-log-network/src/tlog_witness.rs`.
5. §9 and `network/src/lib.rs::verify` for how a verdict is decided.
6. `THREAT_MODEL.md`, then `examples/swarm/reports/` to see what 3,000 concurrent agents did to it.
