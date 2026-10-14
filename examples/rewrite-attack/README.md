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
9. **A verifier that already holds something** (0.5.0). One copy is
   enough when the verifier kept the honest head from earlier:
   `witness-log verify rewritten.json --identity <key> --known-head
   4:<honest root>` is **exit 30, DIVERGED**: the rewritten dossier is
   internally valid, but its four leaves do not reproduce the head the
   verifier saw. And with a witness's evidence file in hand, `witness-log
   verify honest.json --identity <key> --directory trusted.json --evidence
   witness-a/evidence/<file>.json` is **exit 30, DIVERGED** for the honest
   copy too: the identity provably signed two histories, so neither copy
   is WITNESSED any more.

What varies between runs: ports, witness keys, roots and leaf hashes (every
payload is salted with 32 fresh random bytes; that is what makes erasure
possible). What does not: the agent key, the evidence filename, every HTTP
status, every exit code and every verdict.

## Sample output

A real run against the published v0.3.5 CLI and wheel. It predates step
9, which needs a 0.5.0 CLI; with an older one that step fails on the
unknown flags.

<details><summary>full output</summary>

```text
$ python3 examples/rewrite-attack/run.py
witness-log rewrite-attack demo  (witness-log 0.3.5, Python witness_log 0.3.5)
An operator rewrites its agent's history with the agent's own key. What do witnesses do?

── 1. Start two witnesses run by two different organisations (localhost)
   ✓ witness init witness-a
   ✓ witness init witness-b
   Example Org A  http://127.0.0.1:49297  key 5e4cc659b8a50ca5…
   Example Org B  http://127.0.0.1:33173  key c6e6d5f16b8e71a2…
   trusted.json = the verifier's own directory of witnesses it trusts

── 2. The agent works: 4 leaves (intent, result, intent, result)
   leaf 0 intent {"tool":"read_invoice","args":{"invoice":"INV-0042"}}
   leaf 1 result {"supplier":"acct_supplier_17","amount_due_usd":250}
   leaf 2 intent {"tool":"transfer_funds","args":{"to":"acct_supplier_17","amount_usd":25000}}
   leaf 3 result {"status":"ok","tx_id":"tx_7ac31"}
   agent identity key 76e47218f35dbcf6…  tree size 4  root 1b2b2e4346481696…

── 3. Get the head cosigned (c2sp.org/tlog-witness), then verify offline
     │   ✓ witness-a.example/w              cosigned size 4
     │   ✓ witness-b.example/w              cosigned size 4
     │ 2/2 witnesses cosigned size 4 for witness-log/76e47218f35dbcf65f60bbcc43352a92de6953952e3e49fb23b28dbd2204e06c
     │ wrote honest.json. Verify with:
     │   witness-log verify honest.json --identity 76e47218f35dbcf65f60bbcc43352a92de6953952e3e49fb23b28dbd2204e06c --directory <directory YOU trust>
   ✓ witness submit: both witnesses cosigned size 4
     │ ✓ Independent operators: 2 cosigned (example org a, example org b); 2 of 2 known operators represented (100%)
     │ Verdict: WITNESSED — proofs verify and at least 2 independent operators from your trusted directory cosigned this checkpoint
   ✓ honest dossier: exit 0 (0 = WITNESSED)

── 4. The operator rewrites history with the SAME key: leaf 2 now says $250
   ✓ same identity key as the honest log
   leaves 0-1 kept byte for byte; leaf 2 intent {"tool":"transfer_funds","args":{"to":"acct_supplier_17","amount_usd":250}}
   tree size 4  root 028fa60edca047f5…  (honest root was 1b2b2e4346481696…)
     │ ✓ Checkpoint signature valid
     │ ✓ Identity bound to --identity 76e47218...2204e06c
     │ ✓ Leaf structure valid
     │ ✓ Key bindings valid (2 bindings, 0 revocations)
     │ ✓ Merkle continuity verified (4 leaves)
     │ Verdict: UNANCHORED — internally consistent only: no --directory was supplied, so receipts cannot be scored against anything you trust
   ✓ by signatures alone the rewrite is valid: exit 20 (20 = UNANCHORED, internally consistent)

── 5. Ask the same witnesses to cosign the rewritten head
   Example Org A: POST old 0 → 409 4
   Example Org A: POST old 4 → 422 consistency proof failed: witness holds size 4, submitted 4
   ✓ Example Org A refused the rewritten head with 422
   Example Org B: POST old 0 → 409 4
   Example Org B: POST old 4 → 422 consistency proof failed: witness holds size 4, submitted 4
   ✓ Example Org B refused the rewritten head with 422

── 6. Each witness wrote a self-contained evidence file; anyone can check it
   ✓ witness-a/evidence/ holds 1 file(s)
   witness-a/evidence/955ae208b0fb4a24d299a65f248602c8cad0b1c29a7bdd72704e55395db5162e.json  (980 bytes)
     │ origin:  witness-log/76e47218f35dbcf65f60bbcc43352a92de6953952e3e49fb23b28dbd2204e06c
     │ log key: witness-log/76e47218f35dbcf65f60bbcc43352a92de6953952e3e49fb23b28dbd2204e06c+6bc1d85f+AXbkchjzXbz2X2C7zEM1KpLeaVOVLj5J+yOyjb0iBOBs
     │ note A:  size 4 root 1b2b2e43464816967550e769b5f9bb6a118e1815d77c51b0ab979e5b26bd76f0
     │ note B:  size 4 root 028fa60edca047f5315a6980a0c70dd32d7069ac2131c462ebe65b7f38f30f2f
     │ PROVEN: both notes are signed by the log's key, name the same origin and size, and commit different roots. This identity showed two histories.
   ✓ witness verify-evidence: exit 0 (0 = proves two signed roots for one size)
   ✓ witness-b/evidence/ holds 1 file(s)
   witness-b/evidence/955ae208b0fb4a24d299a65f248602c8cad0b1c29a7bdd72704e55395db5162e.json  (980 bytes)
     │ origin:  witness-log/76e47218f35dbcf65f60bbcc43352a92de6953952e3e49fb23b28dbd2204e06c
     │ log key: witness-log/76e47218f35dbcf65f60bbcc43352a92de6953952e3e49fb23b28dbd2204e06c+6bc1d85f+AXbkchjzXbz2X2C7zEM1KpLeaVOVLj5J+yOyjb0iBOBs
     │ note A:  size 4 root 1b2b2e43464816967550e769b5f9bb6a118e1815d77c51b0ab979e5b26bd76f0
     │ note B:  size 4 root 028fa60edca047f5315a6980a0c70dd32d7069ac2131c462ebe65b7f38f30f2f
     │ PROVEN: both notes are signed by the log's key, name the same origin and size, and commit different roots. This identity showed two histories.
   ✓ witness verify-evidence: exit 0 (0 = proves two signed roots for one size)

── 7. Two copies of the log in hand: `witness-log diff`
     │   Both claim identity 76e47218…2204e06c
     │   A checkpoint signature: valid   B checkpoint signature: valid
     │   A leaves match root: yes   B leaves match root: yes
     │   Leaves 0–1: identical
     │   Leaf 2: DIVERGENT
     │   ⚠ EQUIVOCATION DETECTED
   ✓ diff: exit 30 (30 = equivocation, both copies signed by one key)

── 8. Can the rewritten dossier ever reach WITNESSED?
     │ ⚠ No witness receipts present — this dossier proves tamper-evidence but NOT equivocation-resistance.
     │ Verdict: CONSISTENT-UNWITNESSED — cryptography is sound; no receipt in this dossier is from a witness in your trusted directory; do NOT treat as fully verified
   ✓ rewritten, no receipts: exit 10 (10 = CONSISTENT-UNWITNESSED)
     │ Verdict: CONSISTENT-UNWITNESSED — cryptography is sound; 0/2 directory witnesses cosigned, below the count gate (fraction >= 0.66); do NOT treat as fully verified
   ✓ rewritten + the honest log's receipts pasted in: exit 10 (receipts sign the honest root; none count)
   ✓ the honest dossier still verifies: exit 0 (WITNESSED)

Result: the rewrite was signed by the right key and is internally consistent, so a signature
check accepts it. Both witnesses refused it (422), each kept a file proving the operator signed
two different histories at size 4, and no rearrangement of receipts makes the rewrite WITNESSED.
(0.3 s)
```

</details>

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
  0.66`) rules that out; since 0.5.0 `verify` exits 11 for a WITNESSED
  dossier whose cosigners are not a majority. See `THREAT_MODEL.md`.
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
