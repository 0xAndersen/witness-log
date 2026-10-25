# Fleet log (EXPERIMENTAL)

> **EXPERIMENTAL.** This page describes a prototype of
> [RFC-0001](https://github.com/0xAndersen/witness-log/blob/main/docs/rfcs/RFC-0001-fleet-checkpoint-log.md)
> shipped in 0.6.0: `witness-log fleet`, `submit --fleet` and
> `verify --accept-fleet-anchor`. It is not part of the specification. The
> dossier field, the report fields, the fleet log's state directory and its
> HTTP endpoints may change or be removed before RFC-0001's open questions
> are answered. Nothing here changes a verdict for a verifier that does not
> pass `--accept-fleet-anchor`.

## What it is

A witness-log identity is one C2SP origin, `witness-log/<identity hex>`.
Witnesses outside this project are configured one origin at a time, after
a review, so an organisation with a thousand agents would need a thousand
admissions. A fleet log is the unit such a witness can admit instead: one
append-only log per organisation, with its own origin (for example
`acme.example/witness-log/fleet`) and its own key, whose entries are the
signed checkpoint notes of that organisation's agents.

- Each agent appends its checkpoint to the fleet log (`submit --fleet`).
- Ordinary `c2sp.org/tlog-witness` witnesses cosign the fleet log's
  checkpoint. Each enrolls it once, as it would any log whose origin is
  not a witness-log identity: `witness add-log` for a witness-log witness,
  a log list for an omniwitness or a public witness-network witness
  ([Public witness network](Public-Witness-Network)).
- The agent's dossier carries a `fleet_anchor`: its entry, an RFC 6962
  inclusion proof, and the fleet log's checkpoint with the cosignature
  lines.
- A verifier that opts in counts those cosigners as it counts direct
  receipts: against its own directory, at least two independent operators
  for WITNESSED, each witness key once.

## What it proves less well than direct witnessing

A witness that cosigns an agent's own checkpoint holds that agent's last
head and **refuses** a checkpoint that does not extend it (422, and an
equivocation proof when the agent signed two roots for one size). If a
strict majority of the directory cosigned, no conflicting history can have
collected a passing set of cosignatures without some witness seeing both.

A witness that cosigns a fleet log's checkpoint holds the fleet log's last
head. It refuses a fork of the fleet log, but it does not look inside the
entries. Two conflicting checkpoints of one agent are refused by an honest
fleet log (it keeps the last checkpoint per agent and runs the same state
machine a witness runs, see below), but the fleet log is run by the
agent's own organisation. If that organisation misbehaves, it can append
both checkpoints, or put them in two fleet logs it runs, and every witness
would cosign. The conflicting checkpoints are then **recorded** in an
append-only, cosigned log where anyone who reads it can find them, not
**refused** by an independent party.

The verifier reflects this in three ways:

- `report.witnessed_via` says which kind of evidence a WITNESSED verdict
  rests on: `"direct"` (every counted witness key has a direct receipt),
  `"fleet"` (none does) or `"both"`.
- Fleet cosigners never count toward `split_view_resistant`. A WITNESSED
  verdict reached through the fleet alone is therefore always
  `split_view_unsafe`: `verify` exits 11, and `--allow-sub-majority`
  accepts it as 0. Direct receipts from a strict majority of the
  directory are the only way to exit 0 without that flag.
- A verifier that wants direct witnessing only does not pass
  `--accept-fleet-anchor`. That is the whole of `--require-direct`.

What a holder of the fleet log's key can do: sign any fleet checkpoint;
witnesses still cosign only one that extends the fleet history they hold.
It cannot forge an agent's entry (the verifier checks the agent's own
signature on it). It can append both of an agent's conflicting
checkpoints, leave an agent out, or run several fleet origins and put
conflicting checkpoints in different ones; each fleet origin needs its own
enrollment with each witness. The fleet log's own signature is not checked
by the verifier: the cosignatures already sign the exact checkpoint body,
and a witness cosigns a body only after verifying it under the key it was
configured with for that origin.

## Trying it on one machine

Two witnesses under two organisation names, one fleet log, one agent.
This shows the mechanics, not independence: everything runs under one
operator.

```sh
witness-log witness init w1 --name w1.test/witness --org "Org One" --url http://127.0.0.1:17381 > e1.json
witness-log witness init w2 --name w2.test/witness --org "Org Two" --url http://127.0.0.1:17382 > e2.json
jq -s '{witnesses: .}' e1.json e2.json > trusted.json

# The organisation's fleet log; init prints the vkey witnesses enroll it with.
VKEY=$(witness-log fleet init fleet --origin acme.example/witness-log/fleet --org "Acme")
witness-log witness add-log w1 acme.example/witness-log/fleet "$VKEY"
witness-log witness add-log w2 acme.example/witness-log/fleet "$VKEY"

witness-log witness serve w1 --listen 127.0.0.1:17381 &
witness-log witness serve w2 --listen 127.0.0.1:17382 &
witness-log fleet serve fleet --listen 127.0.0.1:17480 &

witness-log log init agent.jsonl
witness-log log append agent.jsonl --intent "hello"

# The agent appends its checkpoint. No fleet checkpoint covers it yet: exit 20.
witness-log submit agent.jsonl --fleet http://127.0.0.1:17480 --out dossier.json

# The fleet operator gets the fleet checkpoint cosigned (or runs
# `fleet serve ... --directory trusted.json --witness-every 60`).
witness-log fleet witness fleet --directory trusted.json

# The agent submits again: nothing is appended, the anchor now points at
# the cosigned fleet checkpoint. Exit 0.
witness-log submit agent.jsonl --fleet http://127.0.0.1:17480 --out dossier.json

witness-log verify dossier.json --identity "$(jq -r .identity_pubkey dossier.json)" \
    --directory trusted.json --accept-fleet-anchor --subject-org Acme
```

The last command printed, in a run of this sequence:

```
✓ 2/2 witness signatures valid (gate: 66% of the directory)
✓ Independent operators: 2 cosigned (org one, org two); 2 of 2 known operators represented (100%)
⚠ Split view possible: 0 of 2 directory witnesses cosigned this log directly, not a majority. ...
✓ Fleet anchor (EXPERIMENTAL): entry 0 of acme.example/witness-log/fleet is in its checkpoint of size 1; 2 witnesses from your directory cosigned it (2 independent operators), 0 of them also directly

Verdict: WITNESSED (via the fleet log, EXPERIMENTAL) — ...
Exit 11: WITNESSED, but fewer than a strict majority of your directory cosigned this log directly. ...
```

Without `--accept-fleet-anchor` the same dossier is CONSISTENT-UNWITNESSED
(exit 10): it carries no direct receipts, and the anchor is reported as
not used.

`submit --fleet` can be combined with `--directory`: the dossier then
carries direct receipts and the anchor, and a witness on both paths counts
once.

## The verifier opt-in

| verifier | opt-in |
|---|---|
| `witness-log verify` | `--accept-fleet-anchor` (requires `--subject-org`) |
| Rust `witness-log-network` | `VerifyContext { accept_fleet_anchor: true, subject_org: Some(..), .. }` |
| Go `clients/go` | `Options{AcceptFleetAnchor: true, SubjectOrg: ..}`; `witness-log-verify --accept-fleet-anchor` |
| TypeScript `@witness-log/client` | `verifyDossier(d, { acceptFleetAnchor: true, subjectOrg })`; `cli.verify(.., { acceptFleetAnchor })` |
| Node `@witness-log/node` | `verifyDossierNative(d, { acceptFleetAnchor: true, subjectOrg })` |
| wasm | options `{"accept_fleet_anchor": true, "subject_org": ..}` |
| Python | `verify_dossier_json(.., subject_org=.., accept_fleet_anchor=True)` |

With the opt-in, after every check a dossier gets without it:

1. `entry_bytes` must be a checkpoint note for the identity that signed the
   dossier's checkpoint, at the same tree size and root, signed by that
   identity, with no extension lines.
2. The inclusion proof of `SHA256(0x00 || entry_bytes)` at `entry_index`
   must verify under the root in `fleet_checkpoint_note`, whose origin must
   be the anchor's `origin`, which must not start with `witness-log/`.
3. Every cosignature line on the fleet checkpoint that verifies
   (`cosignature/v1`) under a key in the verifier's directory is a cosigner.
4. Cosigners and direct receipts are scored together: each witness key
   once, project-operated witnesses as one bucket, and witnesses whose
   `operator_org` matches `subject_org` as none. A fleet log is run by the
   organisation whose agents it records, so `subject_org` names the fleet
   operator too; without it the anchor is not used.

An anchor that fails any step is reported (`report.fleet_anchor.status:
"failed"`, with `failures`) and adds nothing. It does not make the verdict
INVALID and does not lower it: anyone holding the dossier could remove the
field and get the verdict without it. A dossier whose anchor entry is
validly signed by its identity for the same size but a different root is
reported with that reason; it is not turned into DIVERGED in this
prototype.

`/corpus/14_fleet_anchor.json` pins these cases, and every verifier above
runs it.

## The dossier field

```json
"fleet_anchor": {
  "origin": "acme.example/witness-log/fleet",
  "entry_index": 0,
  "entry_bytes_b64": "<the agent checkpoint note exactly as appended>",
  "inclusion_proof": ["<hex>", "..."],
  "fleet_checkpoint_note": "<the fleet checkpoint, with cosignature lines>"
}
```

Optional. A dossier without it is byte-identical to one from 0.5.0.
Verifiers before 0.6.0 ignore it as an unknown field, and a malformed one
does not make a dossier unreadable to a verifier that has not opted in.
`spec/dossier.schema.json` lists it as an optional property marked
experimental.

## The fleet log server

`fleet serve` keeps, for each agent origin, the last checkpoint it
appended, and handles `POST /add-entry` with the `c2sp.org/tlog-witness`
request format and state machine: the agent sends the size it believes the
fleet log holds for it and a consistency proof, gets 409 with the right
size when it is wrong, and 422 when its checkpoint does not extend the held
one. Two signed roots for one size are kept under `evidence/` in the format
a witness writes; `witness verify-evidence` checks the file and
`verify --evidence` applies it to that agent's dossiers. Re-sending the held
checkpoint appends nothing. Every appended entry is fsynced before the
response; the entries file is the only state the tree and the per-agent
memory are rebuilt from; and the server refuses to start if a cosigned
fleet checkpoint is not a head of its own entries (a restore from an older
backup). It listens on loopback unless `--allow-remote`: it has no
authentication, and anyone who can reach it can append any validly signed
agent checkpoint. The [CLI reference](CLI-Reference#fleet-experimental)
lists the endpoints.

## Not implemented

- `c2sp.org/tlog-tiles`. An auditor reads entries one at a time with
  `GET /proof/<index>`; `GET /latest/<agent origin>` gives one agent's
  latest entry.
- Batching or rate limits per agent, and retention (RFC-0001 open
  question 2). Each checkpoint that advances an agent is one entry.
- A verifier-side list of accepted fleet origins per organisation, which
  would narrow the several-fleet-logs case above.
- Publishing the fleet log's vkey in DNS (RFC-0003).
- Equivocation found by scanning the fleet log is not turned into a
  verdict automatically; the fleet log's own `evidence/` files are, with
  `verify --evidence`.
