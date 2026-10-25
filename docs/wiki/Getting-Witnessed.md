# Getting witnessed

WITNESSED requires cosignatures from **at least two distinct `operator_org`
values** in the directory the verifier passes. Witnesses you run yourself
are one operator however many there are. So "getting witnessed" has two
halves: your side (submit) and the network's side (who runs witnesses).

## Your side, end to end on one machine

The public registry is empty today (see below), so the only way to see a
WITNESSED verdict right now is to run two witnesses under two organisation
names yourself. This proves the mechanics, not independence. The script
below is complete and CI runs it as written on every commit
(`docs/doctest.py`); the output under it is from one such run (keys and
signatures will differ on yours).

<!-- doctest: group=local -->
```sh
# two witnesses, two organisation labels, two ports. `witness init` prints
# the directory entry (JSON) on stdout and the prose on stderr.
witness-log witness init ./w1 --name w1.example.org/witness --org "Example Org A" \
    --url http://127.0.0.1:7381 --compute hetzner      > w1.json
witness-log witness init ./w2 --name w2.example.net/witness --org "Example Org B" \
    --url http://127.0.0.1:7382 --compute oracle-cloud > w2.json
witness-log witness serve ./w1 --listen 127.0.0.1:7381 --open-enrollment &
witness-log witness serve ./w2 --listen 127.0.0.1:7382 --open-enrollment &
sleep 1                                                 # let them start listening
jq -s '{witnesses: .}' w1.json w2.json > trusted.json   # the directory a verifier trusts

# a journal to witness: any witness-log journal works. From the CLI:
witness-log log init agent.jsonl
witness-log log append agent.jsonl --intent '{"tool":"hello"}'
witness-log log append agent.jsonl --result '{"ok":true}'
# or from Python:  python3 -c 'import witness_log as wl; l=wl.open("agent.jsonl"); l.append_intent(b"hello"); l.append_result(b"ok"); l.sync()'
# or from Rust:    cargo run -p witness-log-core --example quickstart   (prints where it wrote its journal)

witness-log witness submit agent.jsonl --directory trusted.json --out dossier.json --min 2
witness-log verify dossier.json --identity "$(jq -r .identity_pubkey dossier.json)" \
    --directory trusted.json --min-witnesses 2
echo "exit $?"
```

Example output:

```
  ✓ w1.example.org/witness           cosigned size 4
  ✓ w2.example.net/witness           cosigned size 4
2/2 witnesses cosigned size 4 for witness-log/869d39d42c453f4694beddf77d526bd463f93421e9c88ec8000b09de400f1446
wrote dossier.json. Verify with:
  witness-log verify dossier.json --identity 869d39d42c453f4694beddf77d526bd463f93421e9c88ec8000b09de400f1446 --directory <directory YOU trust>

WitnessLog dossier verification
  identity: 869d39d4...400f1446
  claimed tree size: 4

✓ Checkpoint signature valid
✓ Identity bound to --identity 869d39d4...400f1446
✓ Leaf structure valid
✓ Key bindings valid (3 bindings, 0 revocations)
✓ Merkle continuity verified (4 leaves)
✓ 2/2 witness signatures valid (gate: at least 2 witnesses)
✓ Independent operators: 2 cosigned (example org a, example org b); 2 of 2 known operators represented (100%)
✓ Compute-provider diversity: 2 of 2 known providers represented (100%)

Verdict: WITNESSED — proofs verify and at least 2 independent operators from your trusted directory cosigned this checkpoint
exit 0
```

Three things in that output are worth knowing before you automate it:

- **`--identity "$(jq -r .identity_pubkey dossier.json)"`** is a
  convenience for a demo. In a real gate the identity comes from *your*
  configuration, not from the file being checked; reading it out of the
  dossier only proves the dossier is consistent with itself.
- **`--min 2` on `submit`** makes the command exit 1 when fewer than two
  witnesses cosigned. The 0.3.6 default is `--min 1`, and a `--min` larger
  than the number of witnesses in the directory can never be met (it exits
  1 with the per-witness lines above and no further message). 0.4.0 plans
  to default `--min` to a majority of the directory and to exit non-zero
  on any 422.
- **Operator labels print lowercased** (`example org a`): the verifier
  folds case and whitespace when it counts operators, so two spellings of
  one organisation are one operator. The registry, by contrast, requires
  the label in the file to match the witness byte for byte
  ([Troubleshooting](Troubleshooting)).

The same from Python, without blocking the agent: `w =
witness_log.Witnesser(log, "trusted.json", "agent.jsonl")`, `w.request()`
after steps, `w.flush(timeout=30)`, `w.dossier()`. From MCP:
`submit_to_witnesses`. Lower level: `select_witnesses(directory, identity,
want)` picks a diversity-first, load-spread subset; POST
`add_checkpoint_body(old)` to each; `dossier_from_responses(...)`.

Resubmit after every batch of work (a cron job, the end of a session, or
every N leaves). Each submission carries a consistency proof from the size
the witness last cosigned; a `409` carries that size if you lost track,
and `submit` handles it ([Witness protocol walkthrough](Witness-Protocol-Walkthrough)).
`witness-log testnet up` does the two-witness setup above in one command
([testnet](CLI-Reference#testnet)).

## Your side, against the public registry

```sh
git clone https://github.com/0xAndersen/witness-log && cd witness-log
witness-log directory build --out trusted.json           # every registered independent witness
jq '.witnesses | length' trusted.json                     # 0 today
witness-log witness submit agent.jsonl --directory trusted.json --out dossier.json --min 2
witness-log verify dossier.json --identity "$AGENT_IDENTITY" --directory trusted.json \
  --min-witnesses 2 --subject-org "<your organisation>"
```

With zero entries `submit` has nobody to talk to and exits 1; the verdict
against an empty directory is CONSISTENT-UNWITNESSED. Once the registry
holds more than three witnesses, two cosignatures are not a majority of
it: `verify` reports WITNESSED and exits 11 (split view possible) unless
you verify against the subset you submit to or pass `--allow-sub-majority`. That is the honest
state of the network, not a bug in your setup. (`python3
registry/build_directory.py --exclude-project > trusted.json` builds the same file;
both refuse to build from an entry `registry/validate.py` would reject.) If
your organisation runs one of the registered witnesses, `--subject-org`
keeps it from counting as independent of your own agent. Live status of registered witnesses:
[STATUS.md](https://github.com/0xAndersen/witness-log/blob/status/STATUS.md).

## The network's side

The public [`registry/`](https://github.com/0xAndersen/witness-log/tree/main/registry)
lists witnesses anyone may trust. Verifiers build their directory from it
(or a subset). It is small by design until more organisations run
witnesses. Three ways to grow it:

1. Run your own ([Running a witness](Running-a-Witness)) and register it.
   Even as a single operator it gives your logs a cosigned, time-anchored
   head and availability for the day a second operator appears.
2. Ask a partner, customer, auditor or university to run one. The playbook
   is one page and executable by a coding agent. Independence between two
   parties who already transact is exactly the property an audit trail wants.
   Three organisations with one witness each is the smallest group in which
   every member's logs reach WITNESSED without anyone else
   ([Pilot: three organisations](Pilot-Three-Organisations)); two need a
   third party both trust.
3. Join the public witness network. Its witnesses (run on
   transparency-dev's omniwitness and other C2SP witnesses) cosign
   witness-log checkpoints with no witness-log-specific code, for every
   log on the lists they configure. A log joins a list by email request:
   `witness-log witness-network request` writes it, and CI checks the
   whole path against omniwitness weekly
   ([Public witness network](Public-Witness-Network)). Those witnesses
   admit logs one origin at a time, and a witness-log origin is per agent
   (`witness-log/<identity hex>`). The unit to enroll for an organisation
   is therefore one fleet log
   ([RFC-0001](https://github.com/0xAndersen/witness-log/blob/main/docs/rfcs/RFC-0001-fleet-checkpoint-log.md),
   experimental), plus the agents worth a direct request. Open enrollment,
   where the origin itself is the key and no configuration is needed,
   exists only in witness-log's own witness
   ([Operator onboarding](Operator-Onboarding)).

## What a verifier should demand

- `--identity`: the key you expected, from somewhere the log's operator does not control.
- `--directory`: *your* list. Never the dossier's.
- `--subject-org`: the organisation that operates the log you are checking. Its own witnesses then never count as independent of it. Without it, an operator that also runs a witness in your directory counts as one of its own two independent operators. Since 0.6.0.
- `--min-witnesses`: an absolute count (3 is a sensible floor), and above half your directory if you want the gate itself to resist a split view. Since 0.5.0 `verify` exits 11 for a WITNESSED dossier whose cosigners are not a strict majority of your directory, whatever gate you set; `--allow-sub-majority` accepts it as 0 ([RFC-0002](https://github.com/0xAndersen/witness-log/blob/main/docs/rfcs/RFC-0002-verdict-strictness-and-INVALID.md)).
- `--known-head <size>:<root>`: a head you saw earlier for this identity (a receipt you kept). A dossier that no longer reproduces it is DIVERGED, exit 30.
- Two independent operators: enforced by the verdict, not optional.
- Freshness: `quorum.newest_trusted_witness_ms`, not the checkpoint's own timestamp.
