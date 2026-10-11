# Verification and verdicts

`witness-log verify` (and `Dossier::verify`, `verify_dossier_json`) runs
one computation and reports one of four verdicts. The exit code is the
verdict, so a shell gate needs no parsing.

## What is checked, in order

1. **Checkpoint signature** — the signed tree head verifies under the key it names (Ed25519, strict).
2. **Identity binding** — the dossier's `identity_pubkey` equals the checkpoint signer; if you passed `--identity`, that too.
3. **Leaf structure** — recognised types, well-formed hex, contiguous indices, non-decreasing timestamps.
4. **Key bindings** — every leaf's session key is bound to the identity by a valid signed binding, within its validity window, before any revocation. "Not asserted" (no bindings shipped) is reported, not failed.
5. **Merkle continuity** — the leaves rebuild exactly the signed root.
6. **Quorum** — only with `--directory`: receipts from witnesses in *your* directory, deduplicated by key, scored for count and for distinct independent operators.

## The four verdicts

| verdict | exit | meaning | does not mean |
|---|---|---|---|
| **WITNESSED** | 0 | 1–5 pass, AND receipts from **≥ 2 distinct independent operators** in your directory, AND the count gate is met | that the content is true; anything about operators your directory does not contain |
| **CONSISTENT-UNWITNESSED** | 10 | 1–5 pass, a directory was supplied, but coverage fell short; the output names which gate | equivocation resistance: a lone log can show different histories to different people |
| **UNANCHORED** | 20 | 1–5 pass, no directory supplied | anything about authenticity to someone who does not already trust the author; a fabricated dossier reaches exactly this |
| **DIVERGED** | 30 | any of 1–5 failed; the ✗ line says which | necessarily malice: a mismatched `--identity` or a truncated file produce it too |

## The two inputs you control

- `--directory` lifts the ceiling above UNANCHORED. Receipts are scored only
  against it, never against the dossier's own embedded list (that list is
  attacker-controlled and display-only).
- `--identity` ties the verdict to a party. Without it, WITNESSED means
  "independent operators cosigned *a* log", not "*this party's* log"; the
  output warns. A gate passes both.

## The count gate

`--threshold 0.66` (default) is a fraction of the directory: fine for a
hand-picked directory of ten, wrong for a registry of hundreds (66
cosignatures per checkpoint). Use `--min-witnesses N` for an absolute
count; the report shows `count_gate: "count >= N"`. The independence
rule (two operators) applies either way and is the gate that matters.

**Split views and the majority rule.** A witness refuses a second history
only for a log it has already seen. If your gate can be satisfied by fewer
than half the directory, a log can send history A to one half and history
B to the other, and both dossiers reach WITNESSED without any witness
seeing both. A strict majority (`2 × receipts > directory size`) makes
that impossible among honest witnesses, because any two passing sets share
a witness. The default 0.66 is a majority; `--threshold 0.5` or
`--min-witnesses 2` against a directory of four is not. The report carries
`quorum.split_view_resistant` for the dossier in hand, and the CLI warns
both when this dossier's cosigners are not a majority and when the gate
you chose would let a sub-majority pass. The verifier cannot see the other
dossier; `witness-log diff` is how two copies are compared, and a split
view is still equivocation under one key once both copies are in hand.
([Threat model](Threat-Model) has the full row.)

## Reading `--json`

```json
{ "verdict": "WITNESSED",
  "identity_pinned": true, "directory_pinned": true, "min_witnesses_used": 3,
  "report": {
    "checkpoint_signature_valid": true, "identity_bound": true, "leaves_structurally_valid": true,
    "bindings_valid": true, "bindings_asserted": true, "merkle_continuity_valid": true,
    "internally_consistent": true, "externally_anchored": true, "identity_pinned": true,
    "leaf_count": 6, "claimed_tree_size": 6,
    "quorum": { "valid_receipts": 3, "total_directory_witnesses": 4,
                "distinct_independent_operators": 2, "independent_operators_represented": ["example-infra-co","example-university"],
                "project_operated_receipts": 1, "meets_count_threshold": true, "count_gate": "count >= 3", "split_view_resistant": true,
                "diversity_fraction": 0.75, "compute_diversity_fraction": 0.75, "newest_trusted_witness_ms": 1759000000000 },
    "verdict": "witnessed" } }
```

`newest_trusted_witness_ms` is the timestamp a staleness policy should use:
it comes from independent parties, unlike the checkpoint's own self-asserted time.

## Equivocation: `diff`

Two copies of one log that disagree are either tampering (one copy's
leaves no longer reproduce its signed root → DIVERGED, "tampered, not
equivocation") or equivocation (both copies verify, same identity signed
two histories → provable misbehaviour). `witness-log diff a.json b.json`
tells them apart and never accuses on an edited input. Witnesses record
the same proof under `evidence/`; `witness verify-evidence <file>` checks it.
