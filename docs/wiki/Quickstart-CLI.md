# Quickstart: CLI

One static binary, no runtime. Linux x86_64/aarch64, macOS Intel/Apple
Silicon, Windows.

```sh
cargo install witness-log-cli            # from crates.io
# or download from https://github.com/0xAndersen/witness-log/releases/latest and verify SHA256SUMS
witness-log demo                         # zero arguments, writes nothing, shows every verdict
witness-log demo --tamper                # a flawless forgery, caught
```

| command | does |
|---|---|
| `verify <dossier.json> [--identity <hex>] [--directory <dir.json>] [--min-witnesses N] [--json] [--explain]` | offline verification; the exit code **is** the verdict |
| `diff <a.json> <b.json>` | two copies of one log: equivocation vs tampering |
| `explain [verdict] [--json]` | what each verdict proves and does not |
| `witness init/serve/info/add-log/submit/verify-evidence` | run a witness, or get a journal cosigned |
| `c2sp show/verify` | C2SP checkpoint bodies and signed notes |
| `conform <dir>` | check another implementation against the corpus |

## Exit codes

```
0   WITNESSED               cryptography sound AND ≥2 independent operators cosigned
10  CONSISTENT-UNWITNESSED  cryptography sound, witness coverage short of the gate
20  UNANCHORED              internally consistent; no trusted directory supplied
30  DIVERGED                a check failed: altered, fabricated, or not the identity you pinned
2   usage / unreadable input
```

So a deployment gate is one line:

```sh
witness-log verify dossier.json --identity "$AGENT_KEY" --directory trusted.json --min-witnesses 3 || exit 1
```

## Get a journal witnessed

```sh
witness-log witness submit agent.jsonl --directory trusted.json --out dossier.json
witness-log verify dossier.json --identity $(jq -r .identity_pubkey dossier.json) --directory trusted.json
```

`submit` remembers what each witness has cosigned (`agent.jsonl.witnesses.json`)
and refuses to publish a history that contradicts it, so a journal restored
from an old backup cannot get your identity recorded as equivocating.

## Read a verify report

```
✓ Checkpoint signature valid
✓ Identity bound to --identity f7809c16...0506b3be
✓ Leaf structure valid
✓ Key bindings valid (2 bindings, 0 revocations)
✓ Merkle continuity verified (6 leaves)
✓ 3/4 witness signatures valid (gate: at least 3 witnesses)
✓ Independent operators: 2 cosigned (example-infra-co, example-university); 3 of 4 known operators represented (75%)
✓ Compute-provider diversity: 3 of 4 known providers represented (75%)

Verdict: WITNESSED — proofs verify and at least 2 independent operators from your trusted directory cosigned this checkpoint
```

`--json` gives the same as a structured report (`report.verdict`,
`report.identity_pinned`, `report.internally_consistent`, `report.quorum.*`).

## From any language

The CLI is the integration for languages without bindings: write the
dossier JSON (its schema is `spec/dossier.schema.json`), shell out to
`verify`, branch on the exit code. See [Other languages](Other-Languages).
