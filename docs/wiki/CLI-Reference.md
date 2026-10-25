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
| `0` | WITNESSED, cosigned by a strict majority of the trusted directory, or accepted under `--allow-sub-majority` (verify); PRESENT: the event is in the log's witnessed history (`prove-silence`); success (everything else) | all commands |
| `10` | CONSISTENT-UNWITNESSED: cryptography sound, witness coverage below the gate or from fewer than two independent operators (verify); nothing to bind (`bind`) | `verify`, `submit --allow-partial`, `bind` |
| `11` | WITNESSED, but the cosigning witnesses are not a strict majority of the trusted directory: a conflicting history could have been cosigned by the rest (split view). The default since 0.5.0; `--allow-sub-majority` accepts it as 0 | `verify` |
| `20` | UNANCHORED: internally consistent, no trusted directory supplied (verify); a witness refused the history with 422, or fewer than `--min` cosigned (submit); INCONCLUSIVE: not enough witnessed evidence either way (`prove-silence`) | `verify`, `submit`, `prove-silence` |
| `30` | DIVERGED: the dossier is valid but contradicts a `--known-head` its leaves do not reproduce, or an `--evidence` equivocation proof that verifies for this identity (verify); two valid, conflicting copies of one log (`diff`); mismatch (`bind`); CENSORED: the log signed a write receipt for an event its witnessed history omits (`prove-silence`) | `verify`, `diff`, `bind`, `prove-silence` |
| `31` | MISPLACED: the log signed a write receipt promising an event at one index, and its witnessed history has the event at another: a broken signed promise, not an omission | `prove-silence` |
| `40` | INVALID: a check failed: checkpoint signature, identity (including a wrong `--identity`), leaf structure, key bindings or revocations, or Merkle continuity, as for tampered, reordered, dropped or appended leaves (verify); either copy is invalid or tampered (`diff`); a supplied key did not verify or none did (`c2sp verify`); nothing to export (`c2sp export`); the file does not prove equivocation (`witness verify-evidence`) | `verify`, `diff`, `c2sp verify`, `c2sp export`, `witness verify-evidence`, `submit --allow-partial` |
| `2` | usage error: unknown flag, missing argument, unreadable or unparseable input; a write receipt, or a `--revocations` statement for its key, that does not verify, or a receipt not signed by `--identity` (`prove-silence`); an index the journal does not hold (`log receipt`) | all commands |
| `1` | the operation itself failed: a file could not be written, a journal is locked, a witness would not start, a lock is held | `log`, `witness init/serve/add-log/info`, `testnet`, `directory` |

Codes 10/20/30/40 are spaced so `-ge 20` means "do not trust this"
without reading text. 30 and 40 are different facts: 40 is a failed check
(the file is not valid evidence about the identity); 30 is a valid file
that contradicts other evidence about the same identity (the identity has
signed two histories). A script that read 30 as "tampered" before 0.5.0
should read `-ge 30` as "do not trust this" now. `2` is kept for usage so
a typo is never mistaken for a verdict.

Before 0.5.0 every failed check exited 30, and `11` was reachable only
with `verify --strict`. Since 0.5.0 strict is the default: a script that
gates on `== 0` also rejects a sub-majority WITNESSED (11) unless it
passes `--allow-sub-majority`. `--no-strict`, which restored the 0.4
reading for 0.5.x, was removed in 0.6.0 and is a usage error (exit 2).
`--strict` is still accepted and does nothing.

---

## verify

```
witness-log verify <dossier.json> [--identity <hex>] [--directory <trusted.json>]
                   [--threshold 0.0-1.0 | --min-witnesses N] [--allow-sub-majority]
                   [--revocations <path>] [--known-head <size>:<root hex>] [--evidence <file>]
                   [--subject-org <org>] [--accept-fleet-anchor] [--json] [--explain]
```

Offline. Checks the checkpoint signature, identity binding, leaf
structure, key bindings and revocations, Merkle continuity, and, when
`--directory` is given, witness receipts against *that* directory (never
the dossier's own). Any failed check is INVALID (40). A valid dossier that
contradicts a `--known-head` or an `--evidence` proof is DIVERGED (30);
INVALID wins over DIVERGED, and DIVERGED over every other verdict.

| flag | effect |
|---|---|
| `--identity <hex>` | the identity you expect, from outside the file; without it the verdict says nothing about *whose* log this is |
| `--directory <path>` | the directory you trust, `{"witnesses":[...]}` or a bare array; without it the best verdict is UNANCHORED |
| `--subject-org <org>` | the organisation that operates this log. Its witnesses still count as receipts but never as independent operators, so an organisation that runs both an agent and a witness is not counted as independent of itself. Compared with `operator_org` after trimming, case-folding and collapsing spaces; a name not in your directory changes nothing. Since 0.6.0 |
| `--threshold f` | count gate as a fraction of the directory (default 0.66) |
| `--min-witnesses N` | count gate as an absolute number; use for large directories. A gate at or below half the directory is allowed; a WITNESSED result that is not a strict majority exits 11 |
| `--allow-sub-majority` | accept WITNESSED from fewer than a strict majority of the directory as exit 0 (the split-view warning is still printed) |
| `--strict` | accepted for 0.4 scripts; strict has been the default since 0.5.0, so it does nothing |
| `--revocations <path>` | revocations you know of (one statement or an array); applied whether or not the dossier carries them |
| `--known-head <size>:<root hex>` | a head you already trust for this identity (a checkpoint you kept, a cosignature you saw). If the dossier's first `<size>` leaves give a different root: DIVERGED. A head larger than the dossier cannot be checked and is listed in `report.known_heads_unchecked`, not an error. Repeatable |
| `--evidence <file>` | a witness equivocation proof, as `witness serve` writes it under `evidence/` (`{"kind":"equivocation","proof":{...}}`) or a bare proof. If it verifies under the key named by the canonical origin `witness-log/<identity hex>` (the proof's own `log_vkey` must be that key, key ID included), the identity signed two roots for one size: DIVERGED. A proof for another identity or signed by another key is ignored; a file that is neither form is a usage error (exit 2). Repeatable |
| `--accept-fleet-anchor` | **EXPERIMENTAL** ([Fleet log](Fleet-Log), RFC-0001). Also count witnesses from your directory that cosigned a fleet log checkpoint containing this checkpoint, when the dossier's `fleet_anchor` fully verifies. Requires `--subject-org` (the organisation that runs the fleet log and its agents); its own witnesses never count. One witness key counts once across direct receipts and the fleet. Fleet cosigners never count toward split-view resistance, so a WITNESSED reached through the fleet alone exits 11 unless `--allow-sub-majority`. A fleet anchor that fails a check is reported and adds nothing; it never lowers a verdict. Without this flag the field is ignored. Since 0.6.0 |
| `--json` | one JSON object: `verdict`, `exit_code`, `strict`, `allow_sub_majority`, `subject_org`, `report`, the inputs used (`accept_fleet_anchor: true` when given); schema and stability rules in [`spec/verify-output.schema.json`](https://github.com/0xAndersen/witness-log/blob/main/spec/verify-output.schema.json) |
| `--explain` | one line under each check: what it proves and does not |

The `--json` `report` carries every check, `quorum`, `internally_consistent`,
`verdict` (`"witnessed"`, `"consistent_unwitnessed"`, `"unanchored"`,
`"diverged"`, `"invalid"`), `split_view_unsafe`, `failures` (why INVALID;
empty otherwise), `contradictions` (why DIVERGED; empty otherwise) and
`known_heads_unchecked`. The wording of `failures` and `contradictions`
is not part of the contract; their being empty or not is.

Experimental report fields (RFC-0001), absent unless they apply: when the
dossier carries a `fleet_anchor`, `report.fleet_anchor` is `{status, origin,
entry_index, fleet_tree_size, failures}` with `status` one of `"ignored"`
(no `--accept-fleet-anchor`), `"verified"` or `"failed"`. With
`--accept-fleet-anchor`, `report.witnessed_via` is `"direct"`, `"fleet"` or
`"both"` for a WITNESSED verdict and `null` otherwise, and
`report.witness_paths` is `{direct: {witnesses, independent_operators},
fleet: {witnesses, independent_operators}, on_both}`. A run without the
flag on a dossier without the field prints exactly the 0.5.0 JSON.

Exit: 0 / 10 / 11 / 20 / 30 / 40; 2 usage or unreadable input (including
an unreadable `--evidence` file or a malformed `--known-head`).

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
other), equivocation (two valid histories under one key), or tampering.
Exit 0 consistent, 30 equivocation (both copies valid, histories
conflict), 40 either copy invalid or tampered (any difference is then
explained by the tampering, not by equivocation), 2 usage or different
identities.

## bind

```
witness-log bind <a.json> <b.json> [--json]
```

Two *different* agents' dossiers: match their handoff and authorization
leaves. Exit 0 bound, 30 mismatch, 10 nothing to bind, 2 usage. Leaves
are matched one to one: each handoff or authorization leaf naming the
other identity binds at most one leaf on the other side. Any such leaf left
over on either side is a mismatch: a grant, revocation or scope change only
one side recorded, or recorded more times on one side; a Sent handoff the
receiver never logged, or a Received one the sender never logged. Each is
reported with the dossier that holds it (`A leaf N` / `B leaf N`), and the
result is the same whichever dossier comes first.

## prove-silence

```
witness-log prove-silence <receipt.json> --dossier <d.json> [--dossier <d2.json> ...]
                          --directory <trusted.json> [--identity <hex>] [--min-checkpoints N]
                          [--subject-org <org>] [--revocations <path>] [--json]
```

Offline. The check made by whoever holds a write receipt (`log receipt`):
is the event it names in the log's witnessed history, at the index the
receipt promised, or has the log provably left it out (SPEC §9.4)? See
[Threat model: proving an omission](Threat-Model#proving-an-omission).

The receipt's `tree_size` is the index the event is due at: `log receipt
<journal> <index>` signs `tree_size = <index>`, and the log promises that
every later checkpoint has the event there.

**Which dossiers count.** Only verified, witnessed dossiers are used for
anything. A `--dossier` counts when its checkpoint is signed by the
receipt's key and that signature verifies, its `tree_size` is larger than
the receipt's, it was cosigned by witnesses in `--directory` from at least
two independent operators (the bar of WITNESSED; project-operated witnesses
and the `--subject-org` never count), and its leaves reproduce its own
checkpoint. Any other dossier (another log's, a forged or unwitnessed
checkpoint, an edited copy) is listed in a note with the reason and used
for nothing, not even for the revocations it carries, so adding one never
changes the result.

**Where the leaves come from.** The largest counted dossier. They must
reproduce the root of every counted checkpoint: leaves that reproduce the
largest but not a smaller one show the log signed two histories (a fork),
reported as INCONCLUSIVE. The event is looked for only among those leaves,
up to the largest counted checkpoint.

Inputs are read with `verify`'s rules: the same size cap (64 KiB for the
receipt), `Dossier::from_json`'s depth limit, the same directory and
revocation forms; the receipt is read from a JSON object only.

| flag | effect |
|---|---|
| `--dossier <path>` | a dossier of the log; repeatable, at least one |
| `--directory <path>` | the directory you trust, `{"witnesses":[...]}` or a bare array; required |
| `--identity <hex>` | the log's identity key, obtained out of band; a receipt signed by any other key is refused (exit 2). Without it the result is about whatever key signed the receipt, and anyone can sign a receipt and then omit the event from their own log |
| `--min-checkpoints N` | counted checkpoints after the receipt that CENSORED needs; default 2, the library's conservative minimum (5 is robust) |
| `--subject-org <org>` | the organisation that operates the log; its witnesses never count, as for `verify` |
| `--revocations <path>` | revocations you know of (one statement, as `log revoke` prints it, or an array), applied together with those counted dossiers carry. A v2 revocation of the receipt's key (`log revoke --experimental --as-of-index N`) is in effect once a counted checkpoint is at least `N` large, and then the receipt proves nothing (INCONCLUSIVE), whatever its `issued_at_ms` says. v1 statements, and v2 ones no counted checkpoint has reached, are not applied: the accused log could sign them at no cost (see [Threat model](Threat-Model#proving-an-omission)). A statement naming the receipt's key that does not verify is exit 2; one for another key is ignored, as `verify` ignores it |
| `--json` | one JSON object instead of the verdict line |

| result | exit | means |
|---|---|---|
| PRESENT | `0` | the leaf at the promised index carries the event, in leaves that reproduce every counted checkpoint (`bound_tree_size`, `bound_root_hash` is the largest): it is in a history two independent operators cosigned, where the log said it would be |
| INCONCLUSIVE | `20` | not enough witnessed evidence either way, and never an accusation: `reason` says what is missing (no or too few counted checkpoints, leaves that do not cover or reproduce them, a fork or two roots for one size, or a revocation of the key in effect) |
| CENSORED | `30` | the receipt verifies and no revocation of its key is in effect, at least `--min-checkpoints` counted checkpoints follow it, the leaves reproduce all of them, and the event is not among those leaves. Bound to the largest of them |
| MISPLACED | `31` | the same bundle, with the event among those leaves at `leaf_index` instead of the promised index: the log broke the position it signed for (appended the event late, say), but did not leave it out. One counted checkpoint is enough; `witnessed_checkpoints_without` counts those that lacked the event entirely |
| | `2` | usage error, unreadable or malformed input, a receipt or a `--revocations` statement for its key that does not verify, or a receipt not signed by `--identity` |

A script that gates on `-ge 30` treats CENSORED and MISPLACED alike: the
log broke something it signed.

`--json` prints `result` (`"present"`, `"inconclusive"`, `"censored"`,
`"misplaced"`), `exit_code`, `leaf_index` (where the event is in the
bound leaves: the promised index for present, another one for misplaced,
otherwise `null`), `promised_index` and `receipt_tree_size` (the same
number), `witnessed_checkpoints_after` (censored),
`witnessed_checkpoints_seen` (inconclusive) or
`witnessed_checkpoints_without` (misplaced), `min_checkpoints`,
`revocations_not_in_effect` (revocations of the key that verify but were
not applied), `bound_tree_size`, `bound_root_hash`, `reason`,
`subject_org`, `identity` (the receipt's signer), `identity_pinned`, and
the inputs: `receipt` (`path`, `payload_hash`, `tree_size`,
`issued_at_ms`, `signer_pubkey`), `directory`, `revocations`, `dossiers`
(`path`, `tree_size`, `root_hash`, `leaves`, `witness_receipts`,
`status`: `counted`, `other_log`, `bad_signature`, `not_after_receipt`,
`not_witnessed` or `leaves_do_not_reproduce`) and `leaves_from`. The
wording of `reason` is not part of the contract.

---

## doctor

```
witness-log doctor [<journal>] [--directory <trusted.json>] [--subject-org ORG]
                   [--witness <witness dir>] [--offline] [--json]
                   [--identity-seed-env NAME | --identity-seed-file F]
```

Checks what you give it and prints, for each problem, the command that
fixes it. Changes nothing (with `--witness`, it creates and removes one empty probe file in `logs/` to test that it is writable). One line per check: `✓` fine, `!` worth
fixing, `✗` will not work, `·` information.

| given | checked |
|---|---|
| (always) | version; whether `https://` witnesses are reachable, and against which roots (`WITNESS_LOG_CA_FILE` must load if set) |
| `<journal>` | replays (a sealed journal needs its seed flag); journal and `.salts` private (Unix); `.salts` present; a lock left by a dead process; against `<journal>.witnesses.json`: never submitted, *k* leaves not yet witnessed, up to date, or **contradicting the cosigned head** (truncated, replaced or edited: do not submit) |
| `--directory` | parses; duplicate keys; independent operators (project-operated never count; `--subject-org` and a listed log key are excluded, as in `verify`); **whether WITNESSED is reachable at all**; the default `submit --min`; then `GET /` on every witness (16 at a time, 5 s each): reachable, serves the key the directory lists, open enrollment. `--offline` skips the network |
| `--witness DIR` | `witness.json` readable with an operator org; `witness.key` present and private; `logs/` writable and how many logs; equivocation proofs in `evidence/`; its public URL answers with its own key (unless `--offline`) |

`--json` prints `{version, ok, problems, warnings, findings: [{section,
level: "ok"|"info"|"warn"|"fail", what, fix}]}`; the wording of `what`
and `fix` is not part of the contract, `level` and `ok` are.

Exit: 0 nothing is `✗`; 1 something is; 2 usage.

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

```
witness-log log receipt <journal> <index> [--out receipt.json]
```

Signs a write receipt for leaf `<index>` with the identity key (SPEC
§9.4): `{payload_hash, tree_size, issued_at_ms, sig_alg, signer_pubkey,
signature}` with `tree_size = <index>`, the log's statement that it
accepted that event at tree size `<index>`: every checkpoint larger than
that must have it at index `<index>`. The
operator hands it to whoever submitted the event, at that moment; they
keep it and check it later with [`prove-silence`](#prove-silence).
Printed on stdout, or written to `--out` (0644) with a note on stderr.
Exit 2 for an index the journal does not hold.

```
witness-log log revoke <journal> --reason TEXT [--as-of-ms MS] [--out revocation.json]
                       [--experimental (--as-of-index N | --at-current-size)]
```

Sign a revocation of the journal's identity key (SPEC §5) and print it.
`as_of_ms` defaults to the millisecond after now. Verifiers apply it with
`verify --revocations <file>` whether or not a dossier carries it.
`--as-of-index N` / `--at-current-size` (RFC-0005, needs `--experimental`)
also cut off by position: nothing at index N or later and no head larger
than N counts, whatever its timestamps. See
[Keys and identity](Keys-and-Identity#revocation).

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

Witness URLs may be `http://` or `https://` (since 0.6.0; registry
witnesses are `https://`). TLS certificates are checked against the
Mozilla root set compiled into the binary; set `WITNESS_LOG_CA_FILE` to a
PEM file to trust exactly the CA certificates in it instead (a private
CA). The same applies to `directory build --url` and `testnet`.

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
  exit by that verdict (0 / 10 / 20 / 40; the split-view exit 11 does not
  apply here).

The verdict against the directory is printed on stderr either way.

### submit --fleet (EXPERIMENTAL)

```
witness-log submit <journal> --fleet <url> [--fleet-wait SECS] [--out dossier.json]
                   [--directory <trusted.json> [--min N] [--state <file>]]
```

[Fleet log](Fleet-Log), RFC-0001. Appends the journal's head (its C2SP
checkpoint note) to the organisation's fleet log at `<url>` and adds a
`fleet_anchor` to the dossier: the entry, its inclusion proof, and the
largest cosigned fleet checkpoint that contains it. The anchor is checked
against the journal's own checkpoint before it is written. Re-running it
for a head the fleet log already holds appends nothing and returns a fresh
anchor, which is how an agent picks up a fleet checkpoint cosigned since
its last run; `--fleet-wait SECS` polls for one instead.

- With `--directory`, the direct submission runs exactly as without
  `--fleet` and its exit rules apply; the anchor is added on top.
- Without `--directory`, exit 0 when a cosigned fleet checkpoint covers the
  entry, 20 when none does yet (the dossier is still written, anchored to
  the fleet log's current head) or when the fleet log refused the
  checkpoint (422: it does not extend the one the fleet log holds for this
  agent).
- `--allow-partial` is not supported with `--fleet`.

## fleet (EXPERIMENTAL)

```
witness-log fleet init <dir> --origin <org-domain>/witness-log/fleet --org <org> [--url <public-url>] [--json]
witness-log fleet serve <dir> [--listen 127.0.0.1:7480] [--allow-remote] [--max-origins N]
                              [--directory <trusted.json> --witness-every SECS [--min N]]
witness-log fleet witness <dir> --directory <trusted.json> [--min N]
```

A prototype of RFC-0001; see [Fleet log](Fleet-Log). Not part of the
specification.

`init` creates the fleet log's key (0600), `fleet.json` and an empty
`entries` file, and prints the C2SP vkey (with `--json`, one object:
`origin`, `vkey`, `org`, `pubkey_hex`, `data_dir`). `--origin` must not
start with `witness-log/` (that prefix names one agent's log). Witnesses
enroll it with `witness add-log <their dir> <origin> <vkey>`.

`serve` runs the fleet log over HTTP/1.1, loopback only unless
`--allow-remote` (it has no authentication). On loopback it also refuses (403) any request carrying an `Origin`
header or a `Host` other than `localhost`/a loopback address on its own
port: that is how a web page in the operator's browser (CSRF, DNS
rebinding) would reach it, and local programs send neither.

| endpoint | what it does |
|---|---|
| `POST /add-entry` | body: a `c2sp.org/tlog-witness` add-checkpoint request for an agent's checkpoint (old size, consistency proof, the note). 200: JSON `{origin, entry_index, entry_bytes_b64, inclusion_proof, fleet_checkpoint_note, fleet_tree_size, cosigned, cosignature_lines, appended}`. 409: the size the fleet log holds for that agent (`text/x.tlog.size`). 422: the checkpoint does not extend the one held; same-size conflicts are kept under `evidence/` as an equivocation proof (`witness verify-evidence` checks it). 400: not an agent checkpoint (origin must be `witness-log/<key>`, no extension lines). 403: not signed by the key its origin names. 503: `--max-origins` reached |
| `GET /proof/<index>` | the same JSON for an existing entry, against the largest cosigned fleet checkpoint that contains it, or the current head when none does |
| `GET /latest/<agent origin>` | the latest entry for one agent: `{origin, entry_index, tree_size, root_hash}` |
| `GET /` | origin, vkey, operator org, entry and agent counts, cosigned size, current checkpoint |
| `GET /health` | `ok` |

An entry is appended and fsynced before the response. With `--directory`
and `--witness-every SECS`, the fleet checkpoint is submitted to the
directory's witnesses every SECS seconds when it has grown.

`witness` submits the fleet checkpoint at its current size to every witness
in the directory once (consistency proofs from each witness's last size,
kept in `witnesses.json`) and keeps the cosignatures in `cosigned.note`.
Exit 0 when at least `--min` cosigned (default `max(2, N/2 + 1)`), 20 when
fewer did or any witness refused (422), 1 when the state cannot be read.

Not implemented: `c2sp.org/tlog-tiles` serving, batching or rate limits per
agent, retention.

## journal serve

```
witness-log journal serve <journal> [--listen 127.0.0.1:7390] [--directory trusted.json]
                          [--state <file>] [--allow-remote] [--identity-seed-env NAME | --identity-seed-file F]
```

Holds the journal open (its lock is taken; `log append` on the same file
is refused meanwhile) and serves JSON over HTTP/1.1 for agents in any
language. Loopback only unless `--allow-remote`: there is no
authentication. On loopback it also refuses (403) any request carrying an `Origin`
header or a `Host` other than `localhost`/a loopback address on its own
port: that is how a web page in the operator's browser (CSRF, DNS
rebinding) would reach it, and local programs send neither. Bodies up to 64 KiB.

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
witness-log directory build [--registry DIR | --url URL] [--include-project] [--allow-insecure] --out trusted.json
```

Collects `DIR/*.json` (one directory entry per file, sorted by file name;
default `DIR` is `./registry/witnesses`) or a directory document fetched
from an `https://` URL into `{"witnesses": [...]}`, the schema
`registry/build_directory.py` prints and `verify`/`submit` read.
Project-operated entries are left out unless `--include-project`. Every
entry, project-operated or not, must pass the offline checks of
`registry/validate.py`: only the known fields, all required ones present,
a 64 lowercase hex key, a real `operator_org` with no stray whitespace,
`runtime` `human` or `agent`, an `https://` URL that is not loopback or
another non-public address (an IP host must be a public address in
ordinary notation), a C2SP key name, no invisible or control characters
in the name or organisation, no duplicate key or name. Otherwise every problem is
printed with the file (or `URL#index`) it is in, nothing is written, and
the exit status is 1. `--allow-insecure` accepts `http://` and loopback
URLs, in entries and for `--url`, for local tests. Exit 2 on usage
errors, including a plain-`http://` `--url` without `--allow-insecure`.

```
witness-log directory add <trusted.json> --vkey <c2sp vkey> --org ORG --url URL [--compute PROVIDER] [--project-operated]
```

Adds one witness by its C2SP cosignature verifier key (what `witness
init` prints and `GET /` serves as `vkey`). Creates the file if needed;
refuses a key already listed (exit 1), a log key instead of a witness
key, a non-http URL, an empty org (exit 2). A `--url` ending in
`/add-checkpoint` (the form witness about pages give) is stored without
it, since every client appends that path itself.

## witness-network

```
witness-log witness-network log-list <logs> (--every SECS | --qpd N) --contact TEXT
witness-log witness-network request  <logs> (--every SECS | --qpd N) --contact TEXT
                                     [--list testing|staging] [--about TEXT]
```

`<logs>` is one or more of `--fleet <dir>` (a fleet log, from its
`fleet.json`), `--identity <hex>` (an agent's own log, origin
`witness-log/<hex>`) and `--vkey <log vkey>` (any C2SP checkpoint log with
an Ed25519 key, type 0x01, named as its origin), each repeatable. See
[Public witness network](Public-Witness-Network).

- `log-list` prints a `logs/v0` log list naming those logs: what an
  `omniwitness` reads with `--public_witness_config_url`, and the entry
  the witness network's maintainers add for you.
- `request` prints the participation request for witness-network.org:
  origin line, vkey, add-checkpoint rate, list (default `testing`),
  contact, and the `logs/v0` entries. Nothing is sent.

`--every SECS` is how often the log asks each witness to cosign
(`qpd = ceil(86400 / SECS)`); `--qpd N` states the requests per day
directly, `1 <= N < 2^31`. `--contact` and `--about` are one line each.
Exit 0, or 2 for a usage error, a witness (type 0x04) key given as a log
key, an agent origin that names a different key, or an unreadable
`fleet.json`.

---

## witness

```
witness-log witness init <dir> --name <key-name> [--org <operator>] [--url <public-url>] [--compute <provider>] [--json]
witness-log witness serve <dir> [--listen 127.0.0.1:7380] [--open-enrollment] [--max-logs N] [--max-conns N] [--max-conns-per-ip N] [--enroll-rate N]
witness-log witness add-log <dir> <origin> <log-vkey>
witness-log witness info <http://witness-url>
witness-log witness submit <journal> --directory <trusted.json> [--out dossier.json] [--state F] [--min N] [--allow-partial] [--identity-seed-env NAME | --identity-seed-file F]
witness-log witness verify-evidence <evidence.json> [--vkey <log vkey>]
```

`init` creates a key (0600) and state directory and prints the directory
entry; `--json` prints one object instead (`identity`, `vkey`, `org`,
`name`, `url`, `data_dir`, `entry`) and nothing else on stdout. `serve`
runs a `c2sp.org/tlog-witness` witness: persists every cosigned head
before replying, refuses forks with 422, records proven equivocation
under `evidence/`. `info` prints a witness's `GET /`; its
`directory_entry` is the file to add to `registry/witnesses/`
(`witness-log witness info <url> | jq .directory_entry`). `submit` is
documented above. `verify-evidence` checks
an equivocation file independently, under the key named by its canonical
origin or the `--vkey` you supply, never the key inside the file: exit 0
PROVEN, 40 NOT PROVEN, 2 unreadable. `verify --evidence` applies the same
file to a dossier.

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
a line verifies and at least one does; 40 (REJECTED) when a supplied key
fails or none verified; 2 usage. `export` exits 40 when there is nothing
to export (no usable cosignature and no `--sign-with`).

## conform

```
witness-log conform <candidate-corpus-dir> [--reference <corpus-dir>]
```

Compares another implementation's vectors against the reference corpus:
the encoding vectors `01` to `12`. The verification vector
`13_verdicts.json` (whole dossiers and the verdict, exit code and report
fields each case must produce) is not compared here; a verifier runs it in
its own tests. `14_fleet_anchor.json` pins the experimental fleet anchor
(RFC-0001) the same way and is not part of conformance. Exit 0
conformant, 1 not, 2 unreadable reference.

## demo

```
witness-log demo [--tamper]
```

The worked example; writes nothing, needs no network. Exit 0, or 40
(INVALID) for the forgery in `--tamper`.

---

## Files the CLI writes

| file | mode (Unix) | written by |
|---|---|---|
| `<journal>` | 0600 | `log init` (holds the seed unless `--sealed`) |
| `<journal>.salts` | 0600 | `log init`, `log append`, `log forget` |
| `<journal>.lock` | | while a `log` command or `journal serve` has it open |
| `<journal>.witnesses.json` | 0600 | `submit` (last cosigned size per witness) |
| `dossier.json`, `trusted.json`, `note.txt`, `receipt.json`, `revocation.json` | 0644 | `submit`, `log export`, `directory`, `testnet up`, `c2sp export`, `log receipt --out`, `log revoke --out` |
| `<witness dir>/witness.key` | 0600 | `witness init` |
| `<witness dir>/witness.json`, `logs/`, `evidence/` | 0600 | `witness init`, `witness serve` |
| `<fleet dir>/fleet.key`, `fleet.json`, `entries`, `witnesses.json`, `evidence/` | 0600 | `fleet init`, `fleet serve`, `fleet witness` (experimental) |
| `<fleet dir>/cosigned.note` | 0644 | `fleet witness`, `fleet serve --witness-every` (experimental) |
| `<fleet dir>/fleet.lock` | | while `fleet serve` runs |
