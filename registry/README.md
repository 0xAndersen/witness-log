# Witness registry

The public list of witnesses anyone may add to the directory they trust.
One JSON file per witness under `witnesses/`, exactly as `witness-log
witness init` printed it (or `GET /` returns under `directory_entry`):

```json
{
  "name": "witness.example/w1",
  "operator_org": "Example Org",
  "url": "https://witness.example",
  "pubkey": "<64 hex>",
  "runtime": "human",
  "compute_provider": "hetzner",
  "is_project_operated": false
}
```

## Register

1. Run a witness: `deploy/witness/OPERATORS.md` (one) or
   `deploy/witness/AGENT_OPERATOR.md` (an agent does it for you).
2. Open a pull request adding `witnesses/<org>-<name>.json`. CI runs
   `registry/validate.py`: well-formed, 64 lowercase hex key, a real
   `operator_org` (not `unspecified`), an `https://` URL that is not a
   loopback address, no duplicate key or name, and, when the URL is
   reachable, that `GET /` serves the same `pubkey_hex` **and** the same
   `directory_entry.operator_org`. The live check is skipped with a note
   when the URL cannot be reached from CI (`--offline` skips it entirely;
   `--require-live` makes unreachable an error, which is what the
   `register-witness` workflow uses). `python -m pytest registry` runs the
   validator's own tests.
3. Keep it running. A verifier who adds your entry and sees cosignatures
   from it is the only thing that makes your witness count.

`is_project_operated` MUST be `true` for witnesses run by this project;
`operator_org` MUST be the organisation that actually controls the key.
Mislabelling is the one thing the protocol cannot detect; it is what gets
an entry removed.

**`operator_org` in the registry is case-sensitive and must match the
witness exactly.** The label in the registry file must be byte for byte
what the witness was initialised with (`witness init --org`), which is what
`GET /` shows under `directory_entry.operator_org`; `validate.py` refuses an
entry whose label differs from the served one, including by case or
whitespace. This is a registration rule, not a scoring rule: the verifier
folds case and collapses whitespace before counting operators (`verify`
prints labels lowercased, e.g. `example org`), so two spellings of one
organisation never count as two operators. The exact-match rule exists so
that what the registry says, what the witness says, and what the operator
typed are one string, and so a label cannot be quietly edited in a PR. Use
the same `--org` string on every machine one organisation operates.

## Use

```sh
python registry/build_directory.py > directory.json     # every registered witness
python registry/build_directory.py --exclude-project    # independents only
witness-log verify dossier.json --identity <hex> --directory directory.json
```

A verifier is free to use a subset. WITNESSED needs cosignatures from at
least two distinct `operator_org` values in the directory *you* pass, so
the registry is only as useful as the number of organisations in it. It
starts empty on purpose: the first two independent operators are the
network's first real milestone.

## Status

`registry/status.py` probes every entry here (`GET /` and `GET /health`,
and checks the served key against the entry) and keeps 7 days of samples.
The `status` workflow runs it every 10 minutes and publishes the result to
the orphan branch `status` (never to main):

- page: <https://github.com/0xAndersen/witness-log/blob/status/STATUS.md>
- data: <https://raw.githubusercontent.com/0xAndersen/witness-log/status/status.json>
- samples: <https://raw.githubusercontent.com/0xAndersen/witness-log/status/history.jsonl>

Uptime is a count over `history.jsonl` (probes where `/health` answered
`ok` and `GET /` served the registered key, divided by probes), so anyone
can recompute it. Run it yourself: `python3 registry/status.py --out-dir /tmp/status`.

## The first independent WITNESSED

`registry/witnessed_report.py` (run by the manual `witnessed-report`
workflow) claims the first WITNESSED verdict against this registry or
claims nothing: with fewer than two distinct independent `operator_org`
values it stops without writing anything. Otherwise it submits a fresh
journal to the independent witnesses, verifies with
`--min-witnesses 2`, and on WITNESSED commits
`examples/swarm/reports/first-independent-witnessed.md` with the
commands, operators, cosignatures and verify output.
