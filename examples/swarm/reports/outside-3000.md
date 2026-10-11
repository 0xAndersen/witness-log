# Outside swarm: 3,000 agents, 18 personas, 100 witnesses (0.3.3, two-core host)

- target: `target/release/witness-log` (witness-log 0.3.2), witness_log 0.3.2
- 3000 agents in 605 s, 8 x 24 in flight, 325708 operations, 3657 verdicts
- agents finished cleanly: 3000/3000; operations failed: 0/325708
- witness add-checkpoint statuses: {200: 137462}
- verdicts: {'witnessed': 2517, 'unanchored': 1094, 'diverged': 46}

## Common issues (clustered by signature, most frequent first)

- **13x** `adversary note: fork statuses {<n>: <n>, <n>: <n>}`  
  e.g. `fork statuses {422: 70, 0: 1}`

## Per persona

| persona | agents | crashed | notes |
|---|---|---|---|
| adversary | 93 | 0 | 13 |
| auditor | 191 | 0 | 0 |
| big_payload | 88 | 0 | 0 |
| c2sp_user | 94 | 0 | 0 |
| cli_only | 252 | 0 | 0 |
| coder | 637 | 0 | 0 |
| crash_restart | 183 | 0 | 0 |
| mcp_user | 61 | 0 | 0 |
| multisession | 128 | 0 | 0 |
| operator | 66 | 0 | 0 |
| pipeline | 197 | 0 | 0 |
| researcher | 231 | 0 | 0 |
| rollback_victim | 24 | 0 | 0 |
| schema | 58 | 0 | 0 |
| snapshot | 119 | 0 | 0 |
| support | 292 | 0 | 0 |
| trader | 240 | 0 | 0 |
| verifier_only | 46 | 0 | 0 |

## Latency per operation (ms; successful calls)

| op | n | p50 | p95 | p99 | max | failed |
|---|---|---|---|---|---|---|
| witness.add-checkpoint | 137462 | 151.02 | 1267.39 | 3719.20 | 43496.8 | 0 |
| append_intent | 72292 | 0.00 | 0.02 | 0.07 | 155.6 | 0 |
| append_result | 72000 | 0.00 | 0.01 | 0.05 | 288.3 | 0 |
| step.edit_file | 9555 | 0.02 | 0.10 | 1.89 | 246.3 | 0 |
| append_memory.40k | 9240 | 0.04 | 0.11 | 5.08 | 213.1 | 0 |
| sync | 3634 | 3.58 | 80.71 | 170.46 | 598.9 | 0 |
| verify_dossier_json | 3153 | 9.45 | 99.39 | 200.47 | 352.8 | 0 |
| open | 3095 | 8.99 | 105.96 | 215.56 | 708.3 | 0 |
| inclusion_proof | 2400 | 0.08 | 0.63 | 25.44 | 312.9 | 0 |
| verify_inclusion | 2400 | 0.01 | 0.02 | 0.21 | 62.0 | 0 |
| dossier_from_responses | 1502 | 29.18 | 133.90 | 219.35 | 346.9 | 0 |
| append_memory | 1460 | 0.01 | 0.04 | 0.13 | 118.9 | 0 |
| checkpoint | 1043 | 0.04 | 0.11 | 1.35 | 123.7 | 0 |
| to_dossier_json | 929 | 0.12 | 0.56 | 19.64 | 70.9 | 0 |
| forget | 876 | 2.57 | 84.72 | 157.18 | 348.0 | 0 |
| cli.diff | 443 | 30.37 | 183.97 | 433.91 | 1516.5 | 0 |
| resume | 292 | 1.52 | 57.19 | 100.42 | 241.4 | 0 |
| can_forget | 292 | 0.00 | 0.00 | 0.00 | 0.0 | 0 |
| forget.after_restart | 292 | 2.04 | 75.15 | 151.94 | 384.8 | 0 |
| cli.submit | 276 | 3543.00 | 10100.16 | 10188.81 | 12392.2 | 0 |
| append_result.2MiB | 264 | 4.37 | 93.67 | 199.56 | 218.7 | 0 |
| cli.verify | 252 | 51.13 | 250.72 | 432.47 | 774.7 | 0 |
| cli.explain | 252 | 29.85 | 157.36 | 261.23 | 780.3 | 0 |
| open.b | 197 | 5.15 | 80.00 | 193.03 | 272.8 | 0 |
| append_handoff_sent | 197 | 0.03 | 0.09 | 1.43 | 198.4 | 0 |
| append_handoff_received | 197 | 0.01 | 0.04 | 0.10 | 17.6 | 0 |
| cli.verify.other | 191 | 51.02 | 180.42 | 267.74 | 566.3 | 0 |
| cli.verify.tampered | 191 | 48.00 | 179.07 | 349.01 | 489.2 | 0 |
| resume.after_crash | 183 | 128.18 | 244.53 | 282.87 | 321.6 | 0 |
| generate | 119 | 0.06 | 0.18 | 2.55 | 6.0 | 0 |
| save_snapshot | 119 | 9.26 | 69.30 | 146.94 | 184.7 | 0 |
| load_snapshot | 119 | 0.19 | 2.29 | 226.41 | 395.8 | 0 |
| verify_continuity | 119 | 0.09 | 0.42 | 3.74 | 27.2 | 0 |
| sign_c2sp_checkpoint | 94 | 0.05 | 0.08 | 0.19 | 0.5 | 0 |
| cli.c2sp.verify | 94 | 34.77 | 183.42 | 251.92 | 326.2 | 0 |
| cli.c2sp.show | 94 | 27.93 | 163.22 | 269.54 | 339.7 | 0 |
| sync.after_burst | 88 | 3.90 | 128.17 | 272.48 | 902.7 | 0 |
| operator.logs_served | 66 | 2182.00 | 2186.00 | 2186.00 | 2191.0 | 0 |
| mcp.session | 61 | 2514.34 | 10235.64 | 11050.39 | 11216.6 | 0 |
| jsonschema.validate | 58 | 8.12 | 103.72 | 125.09 | 176.7 | 0 |
| cli.submit.after_rollback | 24 | 31.36 | 160.62 | 161.55 | 161.5 | 0 |
