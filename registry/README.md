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
   loopback or other non-public address, no invisible or control
   characters in the name or organisation, no duplicate key or name, and, when the URL is
   reachable, that `GET /` serves the same `pubkey_hex` **and** the same
   `directory_entry.operator_org`. The live check is skipped with a note
   when the URL cannot be reached from CI (`--offline` skips it entirely;
   `--require-live` makes unreachable an error, which is what the
   `register-witness` workflow uses). `python -m pytest registry` runs the
   script's own tests.
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
witness-log directory build --out directory.json        # the same, independents only
witness-log directory build --include-project --out directory.json   # every registered witness
witness-log verify dossier.json --identity <hex> --directory directory.json
```

The directory is the trust anchor of every verdict computed against it,
so both builders refuse to write one unless every entry passes the offline
checks of `validate.py`: only the known fields, all required ones present,
a 64 lowercase hex `pubkey`, a real `operator_org` with no leading,
trailing or repeated whitespace, `runtime` `human` or `agent`,
`is_project_operated` a boolean, every text field a JSON string, an
`https://` URL that is not a loopback address (an IP-address host must be
a public address written in ordinary dotted or IPv6 notation, so
`2130706433`, `127.1`, `[::ffff:127.0.0.1]` and `169.254.169.254` are
refused), a C2SP key name, no invisible or control characters (zero-width
spaces, bidi controls, fillers, variation selectors, private use) in
`name`, `operator_org` or `compute_provider`, since labels are compared
exactly and two that look the same must be the same, and no duplicate
key or name. A failing build
prints every problem on stderr, writes nothing (`build_directory.py`
prints nothing on stdout) and exits 1. `--allow-insecure` accepts
`http://` and loopback URLs, for tests and local fleets.

The live check (`GET /` serves the entry's key and organisation) needs the
network, so builds skip it by default: CI and offline verifiers still
work. `build_directory.py --live` runs it (an unreachable URL is a note;
`--require-live` makes it an error). `witness-log directory build --url`
fetches a directory document instead of reading the registry; it must be
`https://` (or `--allow-insecure`), and its entries get the same checks.
`build_directory.py` keeps project-operated entries unless
`--exclude-project`; `witness-log directory build` leaves them out unless
`--include-project`. Either way they are checked.

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
