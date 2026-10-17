# Verification and verdicts

`witness-log verify` (and `Dossier::verify`, `verify_dossier_json`) runs
one computation and reports one of five verdicts. The exit code is the
verdict, so a shell gate needs no parsing.

## What is checked, in order

1. **Checkpoint signature** — the signed tree head verifies under the key it names (Ed25519, strict).
2. **Identity binding** — the dossier's `identity_pubkey` equals the checkpoint signer; if you passed `--identity`, that too.
3. **Leaf structure** — recognised types, well-formed hex, contiguous indices, non-decreasing timestamps.
4. **Key bindings** — every leaf's session key is bound to the identity by a valid signed binding, within its validity window, before any revocation. "Not asserted" (no bindings shipped) is reported, not failed.
5. **Merkle continuity** — the leaves rebuild exactly the signed root.
6. **Quorum** — only with `--directory`: receipts from witnesses in *your* directory, deduplicated by key, scored for count and for distinct independent operators.
7. **Contradictions** — only with `--known-head` or `--evidence`, and only for a dossier that passed 1–5: does it reproduce every head you already trust, and is there a verifying proof that this identity signed two roots for one size?

## The five verdicts

| verdict | exit | meaning | does not mean |
|---|---|---|---|
| **WITNESSED** | 0, or 11 | 1–5 pass, AND receipts from **≥ 2 distinct independent operators** in your directory, AND the count gate is met. Exit 11 when those witnesses are not a strict majority of your directory (below) | that the content is true; anything about operators your directory does not contain |
| **CONSISTENT-UNWITNESSED** | 10 | 1–5 pass, a directory was supplied, but coverage fell short; the output names which gate | equivocation resistance: a lone log can show different histories to different people |
| **UNANCHORED** | 20 | 1–5 pass, no directory supplied | anything about authenticity to someone who does not already trust the author; a fabricated dossier reaches exactly this |
| **DIVERGED** | 30 | 1–5 pass, AND the dossier contradicts evidence you brought: a `--known-head` its first `<size>` leaves do not reproduce, or an `--evidence` proof that verifies for this identity; the ✗ line says which | that this copy is the false one: the identity signed two histories, and which one a counterparty saw is a separate question |
| **INVALID** | 40 | any of 1–5 failed; the ✗ line says which | necessarily malice: a mismatched `--identity` or a truncated file produce it too |

INVALID wins over everything: a file that fails a check is not compared
with anything else. DIVERGED wins over the other three: cosignatures on
one history do not cancel proof of a second. Before 0.5.0 a failed check
was DIVERGED (30); it is INVALID (40) since, and DIVERGED is reachable
from `verify` only with `--known-head` or `--evidence`
([RFC-0002](https://github.com/0xAndersen/witness-log/blob/main/docs/rfcs/RFC-0002-verdict-strictness-and-INVALID.md)).

## The inputs you control

- `--directory` lifts the ceiling above UNANCHORED. Receipts are scored only
  against it, never against the dossier's own embedded list (that list is
  attacker-controlled and display-only).
- `--identity` ties the verdict to a party. Without it, WITNESSED means
  "independent operators cosigned *a* log", not "*this party's* log"; the
  output warns. A gate passes both.
- `--subject-org <org>` names who operates the log. That operator's
  witnesses still count as receipts but never as independent operators.
  The verifier can work this out by itself only when your directory lists
  the log's own key; an organisation that runs both an agent and a
  witness is otherwise counted as independent of itself. A name your
  directory does not contain changes nothing. Since 0.6.0; the libraries
  take it as `subject_org` (Python, wasm), `subjectOrg` (TypeScript,
  Node) and `SubjectOrg` (Go).

Two more inputs bring evidence you already hold about the same identity.
Neither can raise a verdict; each can only make a valid dossier DIVERGED:

- `--known-head <size>:<root hex>` (repeatable): a head you trust from
  earlier, such as a receipt you kept or a cosignature you saw. A dossier
  whose first `<size>` leaves give a different root was rewritten after you
  saw that head. A known head larger than the dossier cannot be checked; it
  is listed in `report.known_heads_unchecked` and the verdict is unchanged.
- `--evidence <file>` (repeatable): a witness equivocation proof, as
  `witness serve` writes it under `evidence/`, or a bare proof. It counts
  only if it verifies under the key named by the canonical origin
  `witness-log/<identity hex>`; a proof about another identity, or signed
  by another key under this origin, is ignored.

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
`quorum.split_view_resistant` for the dossier in hand and
`split_view_unsafe` (WITNESSED, but not by a majority), and the CLI warns
both when this dossier's cosigners are not a majority and when the gate
you chose would let a sub-majority pass.

Since 0.5.0 `verify` exits **11** for a WITNESSED dossier whose cosigners
are not a strict majority of your directory; the verdict word stays
WITNESSED, because the receipts did verify. A gate that accepts a
sub-majority says so with `--allow-sub-majority` (exit 0, warning still
printed). `--min-witnesses N` with 2N at or below the directory size is
allowed, not a usage error; a sub-majority result simply exits 11.
`--no-strict` restores the 0.4 reading (exit 0) for one release, and
`--strict` is accepted and does nothing.

The verifier cannot see the other dossier; `witness-log diff` is how two
copies are compared, and a split view is still equivocation under one key
once both copies are in hand. ([Threat model](Threat-Model) has the full
row.)

## Reading `--json`

```json
{ "verdict": "WITNESSED", "exit_code": 0, "strict": true, "allow_sub_majority": false,
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
    "split_view_unsafe": false, "failures": [], "contradictions": [], "known_heads_unchecked": [],
    "verdict": "witnessed" } }
```

`newest_trusted_witness_ms` is the timestamp a staleness policy should use:
it comes from independent parties, unlike the checkpoint's own self-asserted time.

`report.verdict` is one of `"witnessed"`, `"consistent_unwitnessed"`,
`"unanchored"`, `"diverged"`, `"invalid"`. `failures` says why a dossier
is INVALID and `contradictions` why it is DIVERGED; both are empty
otherwise, and their wording is not part of the contract. `exit_code` is
what the CLI returns for this run, 11 included.

`corpus/13_verdicts.json` pins these decisions for any verifier: whole
dossiers, a trusted directory, three equivocation proofs and 20 cases,
each with the expected verdict, exit code, `split_view_unsafe`,
`internally_consistent`, whether `failures` is empty, and the counts of
`contradictions`, `known_heads_unchecked` and valid receipts. The Rust,
Go, TypeScript, Node and wasm verifiers run it.

## Equivocation: `diff`

Two copies of one log that disagree are either tampering (one copy's
leaves no longer reproduce its signed root → INVALID, exit 40, "tampered,
not equivocation") or equivocation (both copies verify, same identity
signed two histories → DIVERGED, exit 30, provable misbehaviour).
`witness-log diff a.json b.json` tells them apart and never accuses on an
edited input. Witnesses record the same proof under `evidence/`;
`witness verify-evidence <file>` checks it (exit 0 PROVEN, 40 NOT
PROVEN), and `verify <dossier> --evidence <file>` makes any valid dossier
of that identity DIVERGED. With only one copy and a head you saw earlier,
`verify <dossier> --known-head <size>:<root>` is the same check.
