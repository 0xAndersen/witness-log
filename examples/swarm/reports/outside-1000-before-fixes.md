# Outside swarm: 1000 agents, 18 personas, 100 witnesses — before the fixes (0.3.2 code + 100-witness directory)

- target: `target/release/witness-log` (witness-log 0.3.2), witness_log 0.3.2
- 1000 agents in 252 s, 8 x 16 in flight, 92926 operations, 1234 verdicts
- agents finished cleanly: 1000/1000; operations failed: 367/92926
- witness add-checkpoint statuses: {200: 22881, 429: 356, 0: 8}
- verdicts: {'witnessed': 798, 'unanchored': 366, 'consistent_unwitnessed': 55, 'diverged': 15}

## Common issues (clustered by signature, most frequent first)

- **356x** `witness.add-checkpoint: HTTP <n>: enrollment rate limit
`  
  e.g. `HTTP 429: enrollment rate limit
`
- **9x** `adversary note: fork statuses {<n>: <n>, <n>: <n>}`  
  e.g. `fork statuses {429: 4, 422: 32}`
- **8x** `witness.add-checkpoint: HTTP <n>: URLError: <urlopen error [Errno <n>] Connection refused>`  
  e.g. `HTTP 0: URLError: <urlopen error [Errno 111] Connection refused>`
- **3x** `fork.attempt: a fork was cosigned`  
  e.g. `a fork was cosigned`

## Per persona

| persona | agents | crashed | notes |
|---|---|---|---|
| adversary | 32 | 0 | 9 |
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
| append_intent | 27396 | 0.00 | 0.02 | 0.07 | 177.7 | 0 |
| append_result | 27300 | 0.01 | 0.01 | 0.06 | 548.8 | 0 |
| witness.add-checkpoint | 22881 | 100.11 | 492.65 | 1455.92 | 5642.5 | 364 |
| step.edit_file | 3255 | 0.02 | 0.10 | 1.84 | 57.3 | 0 |
| append_memory.40k | 3040 | 0.04 | 0.12 | 10.60 | 161.0 | 0 |
| sync | 1309 | 8.67 | 81.54 | 153.66 | 769.3 | 0 |
| verify_dossier_json | 1076 | 3.59 | 67.07 | 131.47 | 246.8 | 0 |
| open | 1052 | 14.93 | 103.79 | 204.71 | 515.6 | 0 |
| inclusion_proof | 910 | 0.08 | 0.60 | 21.45 | 79.0 | 0 |
| verify_inclusion | 910 | 0.01 | 0.02 | 0.11 | 18.8 | 0 |
| dossier_from_responses | 528 | 6.27 | 73.30 | 124.03 | 260.7 | 0 |
| append_memory | 480 | 0.01 | 0.04 | 0.08 | 1.0 | 0 |
| checkpoint | 342 | 0.04 | 0.10 | 15.10 | 117.5 | 0 |
| to_dossier_json | 313 | 0.12 | 0.34 | 9.48 | 50.1 | 0 |
| forget | 288 | 5.12 | 79.30 | 125.22 | 1011.6 | 0 |
| cli.diff | 133 | 23.51 | 106.80 | 234.67 | 264.2 | 0 |
| resume | 96 | 3.25 | 75.77 | 127.86 | 226.2 | 0 |
| can_forget | 96 | 0.00 | 0.00 | 0.02 | 0.0 | 0 |
| forget.after_restart | 96 | 4.89 | 59.91 | 110.22 | 146.6 | 0 |
| cli.submit | 88 | 1194.58 | 2563.52 | 4924.18 | 8038.9 | 0 |
| cli.verify | 79 | 31.31 | 123.83 | 231.65 | 252.9 | 0 |
| cli.explain | 79 | 19.63 | 117.44 | 247.55 | 252.9 | 0 |
| append_result.2MiB | 75 | 5.82 | 78.01 | 99.06 | 161.6 | 0 |
| open.b | 72 | 7.35 | 79.36 | 112.48 | 124.2 | 0 |
| append_handoff_sent | 72 | 0.03 | 0.10 | 0.55 | 7.6 | 0 |
| append_handoff_received | 72 | 0.01 | 0.03 | 0.06 | 0.1 | 0 |
| cli.verify.other | 54 | 22.16 | 117.86 | 168.51 | 174.6 | 0 |
| cli.verify.tampered | 54 | 19.21 | 107.55 | 121.89 | 137.6 | 0 |
| resume.after_crash | 50 | 123.08 | 210.02 | 238.78 | 238.8 | 0 |
| generate | 38 | 0.06 | 1.07 | 2.26 | 2.3 | 0 |
| save_snapshot | 38 | 13.96 | 101.53 | 127.91 | 127.9 | 0 |
| load_snapshot | 38 | 0.18 | 0.25 | 0.30 | 0.3 | 0 |
| verify_continuity | 38 | 0.09 | 0.50 | 12.59 | 12.6 | 0 |
| operator.logs_served | 31 | 707.00 | 739.00 | 747.00 | 747.0 | 0 |
| mcp.session | 25 | 4461.41 | 7885.09 | 8057.06 | 8057.1 | 0 |
| sync.after_burst | 25 | 16.25 | 92.59 | 93.75 | 93.7 | 0 |
| sign_c2sp_checkpoint | 24 | 0.05 | 0.07 | 0.13 | 0.1 | 0 |
| cli.c2sp.verify | 24 | 36.54 | 187.60 | 582.52 | 582.5 | 0 |
| cli.c2sp.show | 24 | 26.11 | 105.62 | 118.98 | 119.0 | 0 |
| jsonschema.validate | 20 | 16.10 | 91.91 | 97.59 | 97.6 | 0 |
| cli.submit.after_rollback | 9 | 53.75 | 177.99 | 177.99 | 178.0 | 0 |
| fork.attempt | 0 | - | - | - | - | 3 |
