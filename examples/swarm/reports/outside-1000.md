# Outside swarm: 1000 agents, 18 personas, 100 witnesses — after the fixes (0.3.3)

- target: `target/release/witness-log` (witness-log 0.3.2), witness_log 0.3.2
- 1000 agents in 244 s, 8 x 16 in flight, 92301 operations, 1234 verdicts
- agents finished cleanly: 1000/1000; operations failed: 0/92301
- witness add-checkpoint statuses: {200: 22620}
- verdicts: {'witnessed': 853, 'unanchored': 366, 'diverged': 15}

## Common issues (clustered by signature, most frequent first)

None.

## Per persona

| persona | agents | crashed | notes |
|---|---|---|---|
| adversary | 32 | 0 | 0 |
| auditor | 54 | 0 | 0 |
| big_payload | 25 | 0 | 0 |
| c2sp_user | 24 | 0 | 0 |
| cli_only | 79 | 0 | 0 |
| coder | 217 | 0 | 0 |
| crash_restart | 50 | 0 | 0 |
| mcp_user | 25 | 0 | 0 |
| multisession | 46 | 0 | 0 |
| operator | 31 | 0 | 0 |
| pipeline | 72 | 0 | 0 |
| researcher | 76 | 0 | 0 |
| rollback_victim | 9 | 0 | 0 |
| schema | 20 | 0 | 0 |
| snapshot | 38 | 0 | 0 |
| support | 96 | 0 | 0 |
| trader | 91 | 0 | 0 |
| verifier_only | 15 | 0 | 0 |

## Latency per operation (ms; successful calls)

| op | n | p50 | p95 | p99 | max | failed |
|---|---|---|---|---|---|---|
| append_intent | 27396 | 0.00 | 0.02 | 0.08 | 170.9 | 0 |
| append_result | 27300 | 0.00 | 0.01 | 0.06 | 335.1 | 0 |
| witness.add-checkpoint | 22620 | 107.56 | 548.31 | 1469.71 | 4620.3 | 0 |
| step.edit_file | 3255 | 0.02 | 0.10 | 2.30 | 283.1 | 0 |
| append_memory.40k | 3040 | 0.04 | 0.13 | 15.57 | 214.7 | 0 |
| sync | 1309 | 4.47 | 83.51 | 149.29 | 591.1 | 0 |
| verify_dossier_json | 1076 | 4.21 | 75.82 | 164.13 | 444.5 | 0 |
| open | 1052 | 7.34 | 86.65 | 147.35 | 766.5 | 0 |
| inclusion_proof | 910 | 0.08 | 0.93 | 8.56 | 137.0 | 0 |
| verify_inclusion | 910 | 0.01 | 0.03 | 0.30 | 50.5 | 0 |
| dossier_from_responses | 528 | 12.90 | 105.34 | 168.18 | 421.3 | 0 |
| append_memory | 480 | 0.01 | 0.03 | 0.09 | 17.3 | 0 |
| checkpoint | 342 | 0.04 | 0.17 | 26.67 | 94.0 | 0 |
| to_dossier_json | 313 | 0.11 | 0.50 | 29.71 | 163.6 | 0 |
| forget | 288 | 3.53 | 70.76 | 146.05 | 524.5 | 0 |
| cli.diff | 133 | 26.30 | 114.78 | 158.74 | 290.5 | 0 |
| resume | 96 | 1.87 | 74.66 | 133.45 | 161.6 | 0 |
| can_forget | 96 | 0.00 | 0.00 | 0.00 | 0.0 | 0 |
| forget.after_restart | 96 | 3.28 | 49.58 | 118.36 | 254.8 | 0 |
| cli.submit | 88 | 1078.45 | 2317.26 | 3330.42 | 3334.3 | 0 |
| cli.verify | 79 | 40.31 | 181.74 | 237.05 | 272.0 | 0 |
| cli.explain | 79 | 19.28 | 79.20 | 139.13 | 142.0 | 0 |
| append_result.2MiB | 75 | 4.23 | 85.13 | 134.22 | 204.2 | 0 |
| open.b | 72 | 4.68 | 80.78 | 136.89 | 145.8 | 0 |
| append_handoff_sent | 72 | 0.03 | 0.07 | 0.20 | 0.5 | 0 |
| append_handoff_received | 72 | 0.01 | 0.02 | 0.02 | 0.0 | 0 |
| cli.verify.other | 54 | 49.52 | 177.41 | 191.98 | 248.0 | 0 |
| cli.verify.tampered | 54 | 41.16 | 132.84 | 166.35 | 171.7 | 0 |
| resume.after_crash | 50 | 124.33 | 254.17 | 890.46 | 890.5 | 0 |
| generate | 38 | 0.06 | 2.28 | 536.84 | 536.8 | 0 |
| save_snapshot | 38 | 8.07 | 76.14 | 104.91 | 104.9 | 0 |
| load_snapshot | 38 | 0.18 | 0.37 | 0.55 | 0.6 | 0 |
| verify_continuity | 38 | 0.09 | 0.14 | 0.29 | 0.3 | 0 |
| operator.logs_served | 31 | 684.00 | 706.00 | 710.00 | 710.0 | 0 |
| mcp.session | 25 | 9717.74 | 11174.87 | 12085.54 | 12085.5 | 0 |
| sync.after_burst | 25 | 4.52 | 135.38 | 177.61 | 177.6 | 0 |
| sign_c2sp_checkpoint | 24 | 0.05 | 0.13 | 0.64 | 0.6 | 0 |
| cli.c2sp.verify | 24 | 22.79 | 144.41 | 552.40 | 552.4 | 0 |
| cli.c2sp.show | 24 | 29.25 | 105.36 | 155.30 | 155.3 | 0 |
| jsonschema.validate | 20 | 14.94 | 53.84 | 98.86 | 98.9 | 0 |
| cli.submit.after_rollback | 9 | 33.19 | 73.01 | 73.01 | 73.0 | 0 |
