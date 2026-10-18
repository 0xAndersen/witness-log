# Outside swarm: 10,000-agent confirmation run of the 0.5.0 fixes (run e), 37 personas, 20 witnesses

- target: `target/release/witness-log` (witness-log 0.5.0), witness_log 0.5.0, 2 cpu, Linux x86_64
- 10,000 agents in 371 s (27.0 agents/s), 2 x 24 in flight, 463,153 operations, 10,271 verdicts
- agents finished cleanly: 10,000/10,000; operations failed: 0/463,153
- witness add-checkpoint statuses: {200: 25377}
- verdicts: {'witnessed': 7158, 'unanchored': 2970, 'invalid': 143}
- per-agent wall time: p50 0.90 s, p95 4.11 s, max 29.4 s

## Findings (clustered by signature, most frequent first)

None.

## Per persona

| persona | agents | crashed | notes |
|---|---|---|---|
| adversary | 246 | 0 | 0 |
| auditor | 374 | 0 | 0 |
| big_payload | 181 | 0 | 0 |
| c2sp_export | 133 | 0 | 0 |
| c2sp_user | 189 | 0 | 0 |
| cli_nocode | 374 | 0 | 0 |
| cli_only | 500 | 0 | 0 |
| coder | 1,340 | 0 | 0 |
| commerce | 234 | 0 | 0 |
| crash_restart | 398 | 0 | 0 |
| directory_builder | 109 | 0 | 0 |
| discloser | 399 | 0 | 0 |
| evidence_window | 131 | 0 | 0 |
| go_verifier | 112 | 0 | 0 |
| handoff_pair | 239 | 0 | 0 |
| hook_user | 134 | 0 | 0 |
| jcs_user | 231 | 0 | 0 |
| journal_serve | 121 | 0 | 0 |
| mcp_0_4 | 134 | 0 | 0 |
| mcp_proxy_user | 57 | 0 | 0 |
| mcp_user | 119 | 0 | 0 |
| multisession | 298 | 0 | 0 |
| node_user | 100 | 0 | 0 |
| operator | 54 | 0 | 0 |
| pipeline | 358 | 0 | 0 |
| recorder | 235 | 0 | 0 |
| researcher | 503 | 0 | 0 |
| rollback_victim | 56 | 0 | 0 |
| schema | 133 | 0 | 0 |
| sealed | 263 | 0 | 0 |
| snapshot | 247 | 0 | 0 |
| strict_verifier | 197 | 0 | 0 |
| submitter | 331 | 0 | 0 |
| support | 608 | 0 | 0 |
| trader | 488 | 0 | 0 |
| verifier_only | 143 | 0 | 0 |
| witnesser | 231 | 0 | 0 |

## Latency per operation (ms; successful calls)

| op | n | p50 | p95 | p99 | max | failed |
|---|---|---|---|---|---|---|
| append_intent | 158,054 | 0.01 | 0.03 | 0.07 | 511.8 | 0 |
| append_result | 146,400 | 0.01 | 0.02 | 0.05 | 369.6 | 0 |
| witness.add-checkpoint | 25,377 | 69.06 | 292.54 | 492.76 | 1840.7 | 0 |
| append_memory.40k | 20,120 | 0.22 | 12.51 | 106.19 | 845.0 | 0 |
| step.edit_file | 20,100 | 0.03 | 0.12 | 0.45 | 386.8 | 0 |
| sync | 8,888 | 43.27 | 225.34 | 393.48 | 1397.5 | 0 |
| open | 8,387 | 56.22 | 252.39 | 466.86 | 1567.5 | 0 |
| verify_dossier_json | 7,654 | 0.76 | 131.27 | 291.06 | 729.0 | 0 |
| inclusion_proof | 4,880 | 0.41 | 90.37 | 206.50 | 645.3 | 0 |
| verify_inclusion | 4,880 | 0.02 | 0.03 | 0.08 | 350.9 | 0 |
| dossier_from_responses | 3,292 | 0.72 | 88.41 | 207.46 | 906.3 | 0 |
| disclose | 3,192 | 0.02 | 0.08 | 0.20 | 154.6 | 0 |
| verify_disclosure | 3,192 | 0.00 | 0.01 | 0.04 | 0.6 | 0 |
| append_memory | 3,040 | 0.01 | 0.05 | 0.11 | 11.6 | 0 |
| recorder.intent | 2,350 | 0.02 | 0.09 | 0.18 | 13.0 | 0 |
| forget | 2,335 | 42.90 | 224.11 | 389.42 | 718.5 | 0 |
| witnesser.request | 2,310 | 0.00 | 0.00 | 0.00 | 0.2 | 0 |
| scheduler.noop | 2,310 | 0.00 | 0.00 | 0.00 | 0.1 | 0 |
| checkpoint | 2,259 | 0.05 | 0.10 | 22.50 | 285.1 | 0 |
| cli.log.append.intent | 2,244 | 98.73 | 339.64 | 505.02 | 1299.9 | 0 |
| cli.log.append.result | 2,244 | 97.40 | 340.26 | 508.18 | 1183.3 | 0 |
| to_dossier_json | 1,948 | 0.14 | 21.31 | 108.12 | 657.3 | 0 |
| recorder.result | 1,645 | 0.02 | 0.05 | 0.12 | 8.3 | 0 |
| resume | 1,007 | 26.75 | 184.67 | 320.44 | 751.7 | 0 |
| cli.submit | 930 | 196.34 | 436.14 | 701.07 | 1009.5 | 0 |
| cli.diff | 874 | 38.32 | 223.68 | 384.78 | 652.5 | 0 |
| open.b | 831 | 47.37 | 228.80 | 355.21 | 651.8 | 0 |
| hook.pre | 804 | 125.59 | 512.96 | 871.31 | 1606.1 | 0 |
| hook.post | 804 | 129.11 | 529.88 | 851.72 | 1326.7 | 0 |
| recorder.result.error | 705 | 0.02 | 0.03 | 0.09 | 3.5 | 0 |
| can_forget | 608 | 0.00 | 0.01 | 0.03 | 0.2 | 0 |
| forget.after_restart | 608 | 36.00 | 191.75 | 360.85 | 1363.8 | 0 |
| append_handoff_sent | 597 | 0.04 | 0.09 | 0.16 | 68.2 | 0 |
| append_handoff_received | 597 | 0.02 | 0.05 | 0.09 | 0.2 | 0 |
| append_result.2MiB | 543 | 91.41 | 318.74 | 559.22 | 754.3 | 0 |
| cli.verify | 500 | 64.01 | 287.84 | 466.72 | 879.7 | 0 |
| cli.explain | 500 | 39.95 | 244.94 | 508.92 | 643.3 | 0 |
| cli.log.init | 495 | 106.04 | 348.62 | 503.59 | 790.6 | 0 |
| open.store_payloads | 399 | 64.19 | 269.65 | 467.44 | 798.8 | 0 |
| disclose.after_resume | 399 | 0.05 | 0.13 | 0.33 | 1.3 | 0 |
| resume.after_crash | 398 | 147.81 | 317.22 | 424.52 | 527.0 | 0 |
| cli.log.forget | 374 | 115.25 | 320.35 | 464.41 | 584.3 | 0 |
| cli.log.disclose | 374 | 39.55 | 236.04 | 480.64 | 995.0 | 0 |
| cli.log.info | 374 | 41.06 | 242.08 | 426.25 | 529.6 | 0 |
| cli.verify.strict | 374 | 84.00 | 361.98 | 466.56 | 918.6 | 0 |
| cli.verify.other | 374 | 28.35 | 112.18 | 181.86 | 295.9 | 0 |
| cli.verify.tampered | 374 | 33.45 | 120.26 | 223.75 | 320.3 | 0 |
| cli.verify.known_head | 374 | 27.69 | 97.28 | 156.06 | 360.1 | 0 |
| submit | 331 | 768.88 | 2221.56 | 2706.86 | 3149.6 | 0 |
| asubmit | 331 | 1024.32 | 2838.48 | 3612.67 | 4685.1 | 0 |
| cli.c2sp.verify | 322 | 41.67 | 232.31 | 355.69 | 494.7 | 0 |
| cli.log.info.seed_file | 263 | 46.11 | 273.39 | 391.72 | 762.8 | 0 |
| mcp.session | 253 | 8948.28 | 11264.05 | 12255.76 | 12912.6 | 0 |
| generate | 247 | 0.07 | 0.13 | 4.03 | 20.4 | 0 |
| save_snapshot | 247 | 35.37 | 159.92 | 244.86 | 503.8 | 0 |
| load_snapshot | 247 | 0.31 | 3.04 | 48.52 | 154.5 | 0 |
| verify_continuity | 247 | 0.18 | 0.32 | 3.15 | 21.1 | 0 |
| append_authorization_event | 239 | 0.01 | 0.02 | 0.09 | 0.4 | 0 |
| append_authorization_event.b | 239 | 0.01 | 0.02 | 0.06 | 0.6 | 0 |
| verify_handoff_binding | 239 | 0.01 | 0.04 | 0.32 | 0.5 | 0 |
| verify_authorization_binding | 239 | 0.01 | 0.01 | 0.04 | 0.1 | 0 |
| cli.bind | 239 | 37.96 | 266.38 | 496.20 | 769.6 | 0 |
| cli.bind.tampered | 239 | 52.32 | 279.86 | 537.81 | 795.7 | 0 |
| ap2.mandate_hash | 234 | 0.06 | 0.14 | 1.02 | 15.4 | 0 |
| ap2.record_grant | 234 | 0.06 | 0.13 | 0.36 | 11.2 | 0 |
| ap2.record_grant.b | 234 | 0.03 | 0.10 | 0.27 | 5.2 | 0 |
| ap2.record_receipt | 234 | 0.07 | 0.14 | 0.36 | 20.3 | 0 |
| ap2.bind_profile_ap2 | 234 | 0.23 | 0.47 | 3.04 | 7.3 | 0 |
| ap2.dispute_export | 234 | 1.04 | 97.88 | 406.14 | 486.7 | 0 |
| x402.record_grant | 234 | 0.07 | 0.17 | 18.97 | 236.6 | 0 |
| x402.record_grant.b | 234 | 0.03 | 0.08 | 1.92 | 122.1 | 0 |
| vi.record_grant | 234 | 0.02 | 0.06 | 1.53 | 7.2 | 0 |
| vi.record_grant.b | 234 | 0.02 | 0.05 | 0.16 | 98.6 | 0 |
| x402.bind | 234 | 0.33 | 0.89 | 21.80 | 172.3 | 0 |
| vi.bind | 234 | 0.21 | 0.60 | 3.02 | 18.7 | 0 |
| witnesser.flush | 231 | 816.59 | 2128.03 | 2529.81 | 3026.7 | 0 |
| proxy.tools_call | 228 | 99.98 | 549.62 | 930.70 | 1083.2 | 0 |
| cli.verify.strict.unwitnessed | 197 | 44.09 | 276.16 | 503.91 | 591.1 | 0 |
| cli.verify.strict.plain | 197 | 50.90 | 262.53 | 534.00 | 669.1 | 0 |
| cli.verify.invalid | 197 | 42.03 | 262.18 | 427.43 | 559.4 | 0 |
| cli.verify.garbage | 197 | 44.42 | 246.78 | 487.54 | 998.5 | 0 |
| sign_c2sp_checkpoint | 189 | 0.06 | 0.12 | 0.28 | 2.2 | 0 |
| cli.c2sp.show | 189 | 46.38 | 172.12 | 326.68 | 780.6 | 0 |
| sync.after_burst | 181 | 55.72 | 202.37 | 304.21 | 496.6 | 0 |
| hook.generic | 134 | 126.24 | 502.43 | 697.12 | 1074.1 | 0 |
| hook.status | 134 | 37.79 | 348.62 | 539.79 | 548.0 | 0 |
| hook.export | 134 | 983.05 | 2689.08 | 3666.38 | 3728.1 | 0 |
| hook.submit | 134 | 928.77 | 2802.68 | 4019.81 | 4481.6 | 0 |
| cli.c2sp.export | 133 | 89.96 | 266.01 | 433.57 | 758.0 | 0 |
| go.verify | 133 | 102.49 | 396.06 | 756.92 | 947.0 | 0 |
| jsonschema.validate | 133 | 11.02 | 183.06 | 414.65 | 443.0 | 0 |
| journal.submit | 121 | 131.50 | 414.58 | 774.23 | 1103.7 | 0 |
| go.verify.witnessed | 112 | 179.08 | 624.09 | 804.37 | 834.9 | 0 |
| go.verify.tampered | 112 | 164.96 | 526.05 | 632.43 | 717.4 | 0 |
| go.verify.one_receipt | 112 | 156.98 | 512.74 | 882.70 | 896.3 | 0 |
| cli.directory.build | 109 | 85.92 | 224.23 | 373.32 | 385.2 | 0 |
| cli.witness.init.json | 109 | 95.53 | 321.81 | 536.65 | 565.1 | 0 |
| cli.directory.add | 109 | 92.27 | 317.92 | 535.27 | 665.2 | 0 |
| cli.verify.node_dossier | 100 | 46.11 | 200.60 | 358.96 | 415.5 | 0 |
| proxy.initialize | 57 | 965.53 | 2388.84 | 3469.64 | 4054.2 | 0 |
| proxy.tools_list | 57 | 64.92 | 343.37 | 361.05 | 361.9 | 0 |
| proxy.tools_call.fail | 57 | 88.51 | 420.04 | 562.19 | 635.9 | 0 |
| proxy.tools_call.crash | 57 | 137.16 | 456.74 | 724.53 | 726.3 | 0 |
| proxy.tools_call.after_crash | 57 | 251.50 | 617.02 | 703.46 | 768.8 | 0 |
| proxy.audit_status | 57 | 46.91 | 365.29 | 396.84 | 812.3 | 0 |
| proxy.audit_export | 57 | 264.10 | 673.70 | 777.64 | 1023.4 | 0 |
| cli.submit.after_rollback | 56 | 52.43 | 161.94 | 250.69 | 290.3 | 0 |
| operator.logs_served | 54 | 1.00 | 1.00 | 1.00 | 1.0 | 0 |
