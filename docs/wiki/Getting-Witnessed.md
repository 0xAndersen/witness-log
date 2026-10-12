# Getting witnessed

WITNESSED requires cosignatures from **at least two distinct `operator_org`
values** in the directory the verifier passes. Witnesses you run yourself
are one operator however many there are. So "getting witnessed" has two
halves: your side (submit) and the network's side (who runs witnesses).

## Your side

```sh
python registry/build_directory.py > trusted.json        # every registered witness
witness-log witness submit agent.jsonl --directory trusted.json --out dossier.json --min 3
witness-log verify dossier.json --identity "$ID" --directory trusted.json --min-witnesses 3
```

From Python: `select_witnesses(directory, identity, want)` picks a
diversity-first, load-spread subset; POST `add_checkpoint_body(old)` to each;
`dossier_from_responses(...)`. From MCP: `submit_to_witnesses`.

Resubmit after every batch of work (a cron job, the end of a session, or
every N leaves). Each submission carries a consistency proof from the size
the witness last cosigned; a 409 tells you that size if you lost track.

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
3. Public witnesses from the Certificate Transparency ecosystem can cosign
   witness-log checkpoints without any witness-log-specific code (same
   protocol and note format); see [Spec and interop](Spec-and-Interop).
   One practical difference: those witnesses (OmniWitness, litewitness,
   the witness-network.org lists) are configured one log origin at a time,
   with the origin and its Ed25519 vkey added by the operator. witness-log
   origins are per agent (`witness-log/<identity hex>`), so they cosign
   only the agent logs someone has added to their configuration. Open
   enrollment, where the origin itself is the key and no configuration is
   needed, exists only in witness-log's own witness; the quickest path for
   such an operator is to run it beside their existing witness
   ([Operator onboarding](Operator-Onboarding)).

## What a verifier should demand

- `--identity`: the key you expected, from somewhere the log's operator does not control.
- `--directory`: *your* list. Never the dossier's.
- `--min-witnesses`: an absolute count (3 is a sensible floor).
- Two independent operators: enforced by the verdict, not optional.
- Freshness: `quorum.newest_trusted_witness_ms`, not the checkpoint's own timestamp.
