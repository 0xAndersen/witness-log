# Witness protocol walkthrough

What actually travels between an agent and a witness, every response the
witness can give, and the two invariants a witness must never break. The
wire protocol is `c2sp.org/tlog-witness`; witness-log adds nothing to it,
which is why witnesses built for Certificate Transparency and the Go
checksum database could cosign a witness-log without modification.

Read [How a leaf becomes a proof](How-a-Leaf-Becomes-a-Proof) first if
"checkpoint" and "consistency proof" are new.

---

## What a witness is, and is not

A witness is a key plus a memory. For every log it has seen it remembers one
fact: *the last (size, root) I cosigned*. On each request it checks that the
new head extends the remembered one and, if so, replaces its memory and
signs. That is the entire service. It does not store your leaves, your
payloads, or your dossiers; it stores about 200 bytes per log.

It is not a notary of truth: it cannot tell whether your agent really
transferred $250. It is a notary of *history*: once it has cosigned size 7,
you cannot later present a different size-7 history to anyone who checks
with that witness, because the witness will refuse and keep the proof that
you tried.

## The request

```http
POST /add-checkpoint HTTP/1.1
Content-Type: text/plain

old 5
<base64 hash>          ← consistency proof, zero or more lines (at most 63)
<base64 hash>

witness-log/f7809c16…0506b3be
7
<base64 root>

— witness-log/f7809c16…0506b3be <base64 log signature>
```

Line by line:

- **`old 5`**: the size the client believes this witness last cosigned. On
  first contact: `old 0`.
- **proof lines**: the RFC 6962 consistency proof from size 5 to size 7.
  Empty when `old 0`.
- **blank line**: separates the preamble from the note. The note contains
  blank lines of its own, so the witness splits on the *first* one.
- **the checkpoint note** (`c2sp.org/tlog-checkpoint` inside a
  `c2sp.org/signed-note`): origin, size, base64 root, then signature lines.
  The origin `witness-log/<identity hex>` is the **canonical origin**: the
  log's name *is* its public key, so a witness can verify the signature
  with no key exchange and no trust on first use. That is what makes
  `--open-enrollment` safe.

Limits the reference witness enforces: 8 KiB head, 64 KiB body, 10 s per
request, chunked bodies refused, 63 proof lines (per spec).

## The six responses

| status | body | meaning | what the client does |
|---|---|---|---|
| **200** | one `cosignature/v1` signature line | cosigned; memory updated | store the receipt |
| **409** | the witness's current size, decimal, `text/x.tlog.size` | "I remember a different size than your `old`" | resend with `old <that size>` and a proof from it |
| **422** | text | the consistency proof failed | see "Equivocation" below |
| **400** | text | the submitted size is *smaller* than the witness's size | the client is behind (restored from backup?); do not retry blindly |
| **403** | text | the checkpoint's signature did not verify under its own origin key | a bug or a forgery; nothing to retry |
| **404** | text | unknown log and enrollment is closed | ask the operator to `add-log`, or use a witness with `--open-enrollment` |

Also, from the HTTP layer rather than the protocol: **429** / **503** with
`Retry-After` when per-address limits are hit. All witness-log clients honour
`Retry-After` up to 60 s. This path mattered: the 1,000-agent test produced
356 of them before clients learned to wait, and three honest logs were
briefly mis-flagged because a 429'd head was never recorded.

## The happy path, as a sequence

```
agent                                   witness (org A)
  │  POST old 0, note(size 3, root R3)     │
  │ ───────────────────────────────────►   │  origin → key; verify log signature
  │                                        │  no memory of this log; old 0 → enrol (canonical origin)
  │                                        │  write logs/<sha256(origin)>.json {size 3, R3}; fsync; rename
  │  200  cosignature/v1 line              │
  │ ◄───────────────────────────────────   │
  │                                        │
  │  …agent appends leaves 3..6…           │
  │                                        │
  │  POST old 3, proof(3→7), note(7, R7)   │
  │ ───────────────────────────────────►   │  verify signature
  │                                        │  recompute R3 and R7 from proof; both must match
  │                                        │  write {size 7, R7}; fsync; rename
  │  200  cosignature/v1 line              │
  │ ◄───────────────────────────────────   │
```

## The 409 path (normal, not an error)

A client that lost its `agent.jsonl.witnesses.json` cache, or that talks to
a witness from two machines, will guess `old` wrong:

```
  │  POST old 0, note(7, R7)               │
  │ ───────────────────────────────────►   │  I hold size 3 for this log
  │  409  "3\n"                            │
  │ ◄───────────────────────────────────   │
  │  POST old 3, proof(3→7), note(7, R7)   │
  │ ───────────────────────────────────►   │
  │  200                                   │
```

`witness submit`, the MCP server and the Python helpers do this loop
automatically. The witness never cosigns on a 409; it only tells you where
it is.

## Why both roots must be reconstructed

The witness verifies the proof with RFC 9162 §2.1.4.2: it rebuilds the
*old* root and the *new* root from the proof hashes and requires both to
equal what it remembers and what was submitted. A tempting shortcut
reconstructs only the new root. That shortcut accepts forks whenever the
old size is not a power of two, because the old root never enters the
computation. witness-log ≤0.3.0 had this bug; it is now pinned by an
exhaustive test (every `1 ≤ m < n ≤ 64`, forks at first, middle and last
old leaf) and by corpus vector `06_consistency_proof.json`. The spec makes
the strict algorithm normative.

## Equivocation: the 422 path

Suppose the agent (or someone with its key) restores from a stale backup,
appends different leaves, and submits a *different* size-7 root `R7'`:

```
  │  POST old 3, proof(3→7'), note(7, R7') │
  │ ───────────────────────────────────►   │  I hold size 7, R7. Submitted size 7, root R7' ≠ R7.
  │                                        │  Both notes are signed by the log's key.
  │                                        │  write evidence/<sha256(origin)>.json {note(7,R7), note(7,R7')}
  │  422                                   │
  │ ◄───────────────────────────────────   │
```

The evidence file holds two log-signed checkpoints for one size with two
roots. `witness-log witness verify-evidence <file>` checks it, and so can
anyone, with nothing but the log's public key. The witness has turned an
accusation into a portable artefact.

Two refinements matter:

- **Only provable equivocation is recorded.** A failed consistency proof by
  itself is *not* evidence: anyone can attach a junk proof to an honest
  log's genuine checkpoint. Treating that as misbehaviour would let a third
  party smear any log, and fill the evidence store so real evidence is
  dropped. Since 0.3.1, `is_misbehaviour_evidence()` is true only when two
  *signed* roots for one size exist.
- **The client side protects you from yourself.** `witness submit`
  remembers each witness's last cosigned size and refuses to publish a
  smaller or conflicting head, so a restored backup fails locally with a
  clear message instead of creating permanent evidence against your
  identity.

## Invariant 1: persist before cosign

The witness writes its new memory to a temp file, fsyncs, renames it over
the old record, and *only then* signs. If it crashes anywhere before the
reply, the worst case is a cosignature that was never delivered; the
witness's memory is already the new head. If it instead signed first and
crashed before writing, it would restart remembering size 3, happily cosign
a conflicting size 7, and have equivocated *itself*. A witness that
equivocates is removed from directories, correctly and permanently.

This is also why the backup rule exists: `witness.key` and `logs/` are one
object. Restoring a key with an older `logs/` is indistinguishable from a
brand-new witness and produces exactly this failure. See
[Running a witness](Running-a-Witness).

## Invariant 2: one memory per key

Two witness processes serving one state directory would race on the memory.
`witness.lock` prevents it; a stale lock from a dead PID is reclaimed on
Linux with one log line. Run many witnesses on one host with `fleet.py`
(one directory each), never two on one directory.

## Open enrollment

With `--open-enrollment` the witness accepts any log whose origin is the
canonical `witness-log/<hex>` and whose note verifies under that key. There
is no registration, no API key, no allowlist. The key is the name, and the
signature proves possession of it. Per-address enrollment is rate-limited
(default 600/min; raise it behind a proxy) and the total is capped
(`--max-logs`, default 100,000). Without the flag, `witness add-log <dir>
<origin> <vkey>` enrols explicitly.

## What the receipt proves

A `cosignature/v1` line is the witness's Ed25519 signature over the
checkpoint plus a timestamp *the witness* asserts. In a dossier it becomes a
receipt. The verifier:

1. finds the witness's public key in **the verifier's own directory** (receipts from unknown keys are ignored, not counted);
2. verifies the signature over the checkpoint;
3. deduplicates by key (one witness re-signing at several timestamps is one witness);
4. counts distinct `operator_org` values.

A receipt is therefore the statement: *this organisation's key saw this
exact (size, root) for this log at this time and had verified it extended
what that organisation saw before.* Two such statements from two
organisations are what WITNESSED means.

Next: [Running a witness](Running-a-Witness) · [Getting witnessed](Getting-Witnessed) · [Threat model](Threat-Model)
