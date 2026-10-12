# CLI reference

Every `witness-log` subcommand, its flags, and its exit codes. The
narrative version is [Quickstart: CLI](Quickstart-CLI); this page is the
lookup table. Every subcommand also answers `--help`.

```
witness-log <command> [args]
witness-log --help | --version
```

Install: `cargo install witness-log-cli`, or the prebuilt archive for your
platform from the releases page.

---

## Exit codes

The verdict is the exit status, so a script gates with `&&` or `||` and
never parses output.

| code | meaning | produced by |
|---|---|---|
| `0` | WITNESSED (verify); success (everything else) | all commands |
| `10` | CONSISTENT-UNWITNESSED: cryptography sound, witness coverage below the gate or from fewer than two independent operators | `verify`, `submit --allow-partial` |
| `11` | `verify --strict` only: anything weaker than WITNESSED by a strict majority of the directory | `verify --strict` |
| `20` | UNANCHORED: internally consistent, no trusted directory supplied (verify); a witness refused the history with 422, or fewer than `--min` cosigned (submit) | `verify`, `submit` |
| `30` | DIVERGED: a check failed (verify); the notes do not prove equivocation (`verify-evidence`); mismatch (`bind`); a supplied key did not verify or none did (`c2sp verify`); nothing to export (`c2sp export`) | `verify`, `diff`, `bind`, `c2sp verify`, `c2sp export`, `witness verify-evidence` |
| `2` | usage error: unknown flag, missing argument, unreadable or unparseable input | all commands |
| `1` | the operation itself failed: a file could not be written, a journal is locked, a witness would not start, a lock is held | `log`, `witness init/serve/add-log/info`, `testnet`, `directory` |

Codes 10/20/30 are spaced so `-ge 20` means "do not trust this" without
reading text. `2` is kept for usage so a typo is never mistaken for a
verdict. `11` exists only under `--strict`; without that flag `verify`'s
codes are unchanged from every earlier release.

---

## verify

```
witness-log verify <dossier.json> [--identity <hex>] [--directory <trusted.json>]
                   [--threshold 0.0-1.0 | --min-witnesses N] [--strict] [--json] [--explain]
```

Offline. Checks the checkpoint signature, identity binding, leaf
structure, key bindings, Merkle continuity, and, when `--directory` is
given, witness receipts against *that* directory (never the dossier's
own).

| flag | effect |
|---|---|
| `--identity <hex>` | the identity you expect, from outside the file; without it the verdict says nothing about *whose* log this is |
| `--directory <path>` | the directory you trust, `{"witnesses":[...]}` or a bare array; without it the best verdict is UNANCHORED |
| `--threshold f` | count gate as a fraction of the directory (default 0.66) |
| `--min-witnesses N` | count gate as an absolute number; use for large directories |
| `--strict` | exit 11 unless WITNESSED **and** the cosigning witnesses are a strict majority of the directory (`split_view_resistant`) |
| `--json` | one JSON object: `verdict`, `report`, `strict`, the inputs used |
| `--explain` | one line under each check: what it proves and does not |

Exit: 0 / 10 / 20 / 30, or 11 with `--strict`; 2 usage.

## explain

```
witness-log explain [verdict | <name>] [--json]
```

What each verdict means, does not mean, and how to reach the next one.
Exit 0; 2 for an unknown topic.

## diff

```
witness-log diff <a.json> <b.json>
```

Two dossiers of one identity: honest growth (one is a prefix of the
other), equivocation (two histories under one key), or tampering. Exit 0
consistent, 30 diverged, 2 usage or different identities.

## bind

```
witness-log bind <a.json> <b.json> [--json]
```

Two *different* agents' dossiers: match their handoff and authorization
leaves. Exit 0 bound, 30 mismatch, 10 nothing to bind, 2 usage.

---

## testnet

```
witness-log testnet up [--witnesses 3] [--dir ./.witness-testnet] [--out trusted.json]
witness-log testnet status [--dir DIR]
witness-log testnet down [--dir DIR]
```

Starts N `witness serve` processes (children of this binary) with
distinct keys, operator names `testnet-a`, `testnet-b`, ..., and loopback
ports, and writes the directory file listing them (`--out`, default
`DIR/trusted.json`). `status` prints each witness's pid, URL, log count
and cosignatures since start; exit 1 if any is down. `down` stops them
(SIGTERM, then SIGKILL after 5 s; `taskkill` on Windows) and removes the
pid files; keys and state stay, so a later `up` continues with the same
identities.

Under `DIR`: `testnet.json` (what is up), `testnet-a/` (witness state),
`testnet-a.pid`, `testnet-a.log` (its stderr). `up` while one is running
is refused (exit 1).

A testnet is three witnesses you run; a verifier who trusts that
directory trusts you three times. It proves the mechanism and the
tooling, not independence.

---

## log

An agent's journal from the shell. Every subcommand accepts
`--identity-seed-env NAME` or `--identity-seed-file F` for a sealed
journal; the seed is never taken from the command line.

```
witness-log log init <journal> [--sealed] [--identity-seed-env NAME | --identity-seed-file F]
```

Creates `<journal>` (mode 0600) and its salt sidecar `<journal>.salts`.
Without flags: a new identity, seed stored in the journal header. With a
seed source: that identity. `--sealed`: the header holds only the public
key and the seed must come from the env var or file on every later
command; `--identity-seed-file F` naming a file that does not exist yet
generates a seed into it (0600). Prints one JSON object: `journal`,
`identity`, `sealed`, `salts`, `seed_file`.

```
witness-log log append <journal> (--intent | --result | --memory) <payload | @file | -> [--outcome ok|error] [--json]
```

Appends one leaf and fsyncs. The payload is the argument's bytes, the
contents of `@file`, or stdin (`-`). `--outcome` (results only) commits
`{"outcome":"ok","value":"<payload>"}` as compact canonical JSON, the
shape the Python `step` decorator and the MCP server write; the exact
bytes committed are printed as `committed_payload`. Prints `index`,
`leaf_type`, `payload_hash`, `tree_size`, `root`. Payloads are hashed,
never stored: keep them if you will need to disclose them.

```
witness-log log forget <journal> <index>
```

Erases the salt for leaf `<index>` from the sidecar and appends a
Redaction leaf. Every existing proof stays valid. Exit 1 when there is
nothing to erase (already forgotten, a marker leaf, out of range).

```
witness-log log export <journal> --out dossier.json
```

Writes an unwitnessed dossier (0644): leaves, checkpoint signed by the
identity key, every key binding. `verify` on it reaches UNANCHORED, or
CONSISTENT-UNWITNESSED with a directory.

```
witness-log log disclose <journal> <index>
```

Prints the leaf, its `payload_hash`, and its `salt` so a verifier
holding the payload recomputes `SHA256(bucket_pad(payload) || salt ||
index)` (SPEC §8; `bucket_pad` is an 8-byte big-endian length, the
payload, and zero padding to the next 256-byte bucket). Only that leaf's
salt leaves the sidecar. Exit 1 if the salt is gone.

```
witness-log log info <journal>
```

Identity, canonical origin, tree size, root, leaf counts by type, key
bindings, salts held, sealed or not. For a sealed journal without its
seed, the public facts from the header.

---

## submit

```
witness-log submit <journal> --directory <trusted.json> [--out dossier.json] [--state <file>]
                   [--min N] [--allow-partial] [--identity-seed-env NAME | --identity-seed-file F]
```

Same command as `witness submit`. Signs the journal's head as a C2SP
checkpoint, POSTs it to every witness in the directory in parallel
(following 409 resyncs and `Retry-After`), collects cosignatures into
receipts, writes the dossier (0644) and the client state
(`<journal>.witnesses.json`, 0600). Refuses to publish a history that
contradicts a head witnesses already cosigned for this identity.

Fail-closed:

- `--min` defaults to `max(2, N/2 + 1)` for a directory of N witnesses: a
  strict majority, never below the two independent operators WITNESSED
  needs. A one-witness directory needs an explicit `--min 1`.
- Any witness answering **422** (your history does not extend what it
  cosigned) makes the exit status **20**, whatever `--min` says. A 422 is
  a fork or a corrupted journal, not a partial result.
- Fewer than `--min` cosignatures: exit 20.
- `--allow-partial`: instead of the two rules above, verify the dossier
  just written against the directory with the count gate at `--min` and
  exit by that verdict (0 / 10 / 20 / 30).

The verdict against the directory is printed on stderr either way.

## journal serve

```
witness-log journal serve <journal> [--listen 127.0.0.1:7390] [--directory trusted.json]
                          [--state <file>] [--allow-remote] [--identity-seed-env NAME | --identity-seed-file F]
```

Holds the journal open (its lock is taken; `log append` on the same file
is refused meanwhile) and serves JSON over HTTP/1.1 for agents in any
language. Loopback only unless `--allow-remote`: there is no
authentication. Bodies up to 64 KiB.

| method | path | body | response |
|---|---|---|---|
| POST | `/append` | `{"kind":"intent"\|"result"\|"memory","payload":<string or JSON value>,"outcome":"ok"\|"error"?}` | `index`, `leaf_type`, `payload_hash`, `committed_payload`, `tree_size`, `root` |
| POST | `/forget` | `{"index":N}` | `forgotten`, `tombstone_index`, `tree_size`, `root`; 404 out of range, 409 nothing to erase |
| POST | `/submit` | `{"directory_path":"..."?,"want":N?,"min":N?}` | `ok`, `cosigned`, `contacted`, `refused_422`, `min`, `verdict`, `witnesses`; 200 ok, 422 a witness refused, 503 below min |
| GET | `/dossier` | | the witnessed dossier while the head is unchanged since the last successful submit, else the current unwitnessed one |
| GET | `/info` | | `identity`, `origin`, `tree_size`, `root`, `directory`, `witnessed_size`, `witnessed_cosignatures` |
| GET | `/health` | | `ok` |

A string `payload` is committed as its UTF-8 bytes; any other JSON value
as compact JSON. `directory_path` defaults to `--directory` and may only
be set by a loopback client. `want` contacts a diversity-aware subset
(`select_diverse_witnesses`) instead of the whole directory; `min`
defaults to `max(2, contacted/2 + 1)`. Errors are `{"error":"..."}` with
400 for bad input.

---

## directory

```
witness-log directory build [--registry DIR | --url URL] [--include-project] --out trusted.json
```

Collects `DIR/*.json` (one directory entry per file, sorted by file name;
default `DIR` is `./registry/witnesses`) or a directory document fetched
from an `http://` URL into `{"witnesses": [...]}`, the schema
`registry/build_directory.py` prints and `verify`/`submit` read.
Project-operated entries are left out unless `--include-project`. A
malformed entry or a duplicate key fails the build and names the file.
Exit 1 on failure, 2 usage.

```
witness-log directory add <trusted.json> --vkey <c2sp vkey> --org ORG --url URL [--compute PROVIDER] [--project-operated]
```

Adds one witness by its C2SP cosignature verifier key (what `witness
init` prints and `GET /` serves as `vkey`). Creates the file if needed;
refuses a key already listed (exit 1), a log key instead of a witness
key, a non-http URL, an empty org (exit 2).

---

## witness

```
witness-log witness init <dir> --name <key-name> [--org <operator>] [--url <public-url>] [--compute <provider>] [--json]
witness-log witness serve <dir> [--listen 127.0.0.1:7380] [--open-enrollment] [--max-logs N] [--max-conns N] [--max-conns-per-ip N] [--enroll-rate N]
witness-log witness add-log <dir> <origin> <log-vkey>
witness-log witness info <http://witness-url>
witness-log witness submit <journal> --directory <trusted.json> [--out dossier.json] [--state F] [--min N] [--allow-partial] [--identity-seed-env NAME | --identity-seed-file F]
witness-log witness verify-evidence <evidence.json>
```

`init` creates a key (0600) and state directory and prints the directory
entry; `--json` prints one object instead (`identity`, `vkey`, `org`,
`name`, `url`, `data_dir`, `entry`) and nothing else on stdout. `serve`
runs a `c2sp.org/tlog-witness` witness: persists every cosigned head
before replying, refuses forks with 422, records proven equivocation
under `evidence/`. `submit` is documented above. `verify-evidence` checks
an equivocation file independently: exit 0 proven, 30 not, 2 unreadable.

## c2sp

```
witness-log c2sp show <dossier.json> --origin <name> [--raw] [--sign-with <journal>] [--identity-seed-env NAME | --identity-seed-file F]
witness-log c2sp export <dossier.json> [--directory trusted.json] [--sign-with <journal>] --out note.txt [--identity-seed-env NAME | --identity-seed-file F]
witness-log c2sp verify <note.txt> --vkey <vkey> [--vkey <vkey>...]
```

`show` renders the checkpoint as a C2SP body (or, with `--sign-with`, a
signed note). `export` writes the signed note under the log's canonical
origin with every C2SP cosignature in the dossier attached; the witness
key names come from `--directory` or from the receipts' `witness_name`;
`--sign-with` adds the log's own signature. `verify` checks a note
against the keys you supply: exit 0 when every supplied key that matches
a line verifies and at least one does; 30 when a supplied key fails or
none verified; 2 usage.

## conform

```
witness-log conform <candidate-corpus-dir> [--reference <corpus-dir>]
```

Compares another implementation's vectors against the reference corpus.
Exit 0 conformant, 1 not, 2 unreadable reference.

## demo

```
witness-log demo [--tamper]
```

The worked example; writes nothing, needs no network. Exit 0, or 30 for
the forgery in `--tamper`.

---

## Files the CLI writes

| file | mode (Unix) | written by |
|---|---|---|
| `<journal>` | 0600 | `log init` (holds the seed unless `--sealed`) |
| `<journal>.salts` | 0600 | `log init`, `log append`, `log forget` |
| `<journal>.lock` | | while a `log` command or `journal serve` has it open |
| `<journal>.witnesses.json` | 0600 | `submit` (last cosigned size per witness) |
| `dossier.json`, `trusted.json`, `note.txt` | 0644 | `submit`, `log export`, `directory`, `testnet up`, `c2sp export` |
| `<witness dir>/witness.key` | 0600 | `witness init` |
| `<witness dir>/witness.json`, `logs/`, `evidence/` | 0600 | `witness init`, `witness serve` |
