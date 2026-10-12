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
   `registry/validate.py`: well-formed, 64-hex key, a real `operator_org`
   (not `unspecified`), no duplicate key, and the URL answers `GET /` with
   the same `pubkey_hex` when it is reachable.
3. Keep it running. A verifier who adds your entry and sees cosignatures
   from it is the only thing that makes your witness count.

`is_project_operated` MUST be `true` for witnesses run by this project;
`operator_org` MUST be the organisation that actually controls the key.
Mislabelling is the one thing the protocol cannot detect; it is what gets
an entry removed.

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
