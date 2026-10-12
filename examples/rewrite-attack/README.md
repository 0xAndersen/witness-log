# The rewrite attack, reproduced

An agent's operator holds the agent's identity key. After an incident it
would prefer the record to say something else, so it rewrites the agent's
history and signs the new version with the same key. Every signature in the
rewritten log is valid; the leaves rebuild the signed root; a verifier that
checks signatures, or a hash chain, or a signed receipt per action, accepts
it. That is not a hypothetical: an independent evaluation of witness-log
0.3.3 ran this attack against several agent audit tools and reported that
the others accepted the rewritten log as valid (see `CHANGELOG.md`, 0.3.4).

This folder reproduces what happens when the log is witnessed.

```sh
pip install witness-log            # the Python package
cargo install witness-log-cli      # the CLI (or put a release binary on PATH)
python3 examples/rewrite-attack/run.py
```

One command, localhost only (0.4 s on the two-core host it was written on). It exits 0 only if
every step below behaved as described. `--keep DIR` keeps the journals,
dossiers, witness state and evidence files for inspection;
`WITNESS_LOG_BIN=/path/to/witness-log` picks a specific binary.

## What it does

1. **Two witnesses, two organisations.** `witness-log witness init` +
   `witness serve --open-enrollment`, on free localhost ports, with
   `operator_org` "Example Org A" and "Example Org B". The verifier's own
   `trusted.json` lists both.
2. **The agent works.** Four leaves: read an invoice for $250 (intent,
   result), then transfer $25,000 (intent, result). The identity key comes
   from a fixed seed, so it is the same on every run.
3. **Witnessed.** `witness-log witness submit` gets size 4 cosigned by both
   witnesses over `c2sp.org/tlog-witness`; `witness-log verify` with
   `--identity` and `--directory` exits **0, WITNESSED**.
4. **The rewrite.** The operator copies the journal, cuts it back to two
   leaves (exactly what restoring an old backup does; leaves 0 and 1 stay
   byte-identical, salts included) and appends a different leaf 2 saying
   $250, then leaf 3. Same identity key, same size, different root.
   Verified on its own it is internally consistent: **exit 20, UNANCHORED**,
   every check ✓. Signatures alone cannot tell it from the original.
5. **The witnesses refuse.** Each witness answers the first submission with
   `409` and its remembered size (4), then the rewritten head with
   **`422`**: it already cosigned a different root for size 4.
6. **Evidence.** Each witness writes `evidence/<sha256(origin)>.json`
   (980 bytes here): both checkpoint notes, each carrying only the log's own
   signature. `witness-log witness verify-evidence` exits **0**: "both notes
   are signed by the log's key, name the same origin and size, and commit
   different roots." Anyone can check it with the log's public key alone;
   the witness's honesty is not an input.
7. **Two copies in hand.** `witness-log diff honest.json rewritten.json`:
   leaves 0–1 identical, leaf 2 divergent, both validly signed by one
   identity, **EQUIVOCATION DETECTED**, exit 30.
8. **No way to WITNESSED.** The rewritten dossier with `--directory` is
   **exit 10, CONSISTENT-UNWITNESSED** (no receipts). Pasting the honest
   dossier's receipts into it changes nothing (receipts sign the honest
   root; 0 of 2 count). The honest dossier still verifies WITNESSED.

What varies between runs: ports, witness keys, roots and leaf hashes (every
payload is salted with 32 fresh random bytes; that is what makes erasure
possible). What does not: the agent key, the evidence filename, every HTTP
status, every exit code and every verdict.

## What this shows, and what it does not

Shows: once two witnesses have cosigned size N, the operator cannot get a
different size-N history cosigned by them, cannot make the rewrite reach
WITNESSED against a directory containing them, and leaves a portable proof
of having tried.

Does not show:

- **Real independence.** Both witnesses run on your machine. The property
  is only as strong as the independence of the witnesses *you* put in your
  directory. The public registry of witness operators (`registry/`) is
  currently empty; that is the main limit of the project today.
- **Split views.** A log that shows history A to one set of witnesses and
  history B to a disjoint set never meets a witness that saw both. Only a
  majority gate (`2 × receipts > directory`, the default `--threshold
  0.66`) rules that out; see `THREAT_MODEL.md`.
- **A rewrite before the first cosignature.** Witnesses remember heads they
  cosigned. Anything rewritten before any witness saw it is just a log.
- **Growing forks.** A rewritten history submitted at a *larger* size (with
  a consistency proof that cannot verify) is also refused with 422, but one
  witness then holds no two signed roots for one size, so no evidence file
  is written; it is caught when two copies are compared with `diff`.
- **Truth of content.** A witness is a notary of history, not of facts. If
  the agent logged a lie at the time, the lie is faithfully preserved.

Related: [Witness protocol walkthrough](../../docs/wiki/Witness-Protocol-Walkthrough.md) ·
[Verification and verdicts](../../docs/wiki/Verification-and-Verdicts.md) ·
[Threat model](../../THREAT_MODEL.md)
