# Outside swarm: 100,000 agents against the released 0.5.0 (after the fixes), 37 personas, 20 witnesses under four organisations

- target: `target/release/witness-log` (witness-log 0.5.0), witness_log 0.5.0, 2 cpu, Linux x86_64
- 100,000 agents in 4519 s (22.1 agents/s), 2 x 24 in flight, 4,655,983 operations, 102,111 verdicts
- agents finished cleanly: 100,000/100,000; operations failed: 0/4,655,983
- witness add-checkpoint statuses: {200: 247446}
- verdicts: {'witnessed': 72124, 'unanchored': 28673, 'invalid': 1314}
- per-agent wall time: p50 1.38 s, p95 4.49 s, max 30.0 s

## Findings (clustered by signature, most frequent first)

None.

## Per persona

| persona | agents | crashed | notes |
|---|---|---|---|
| adversary | 2,538 | 0 | 0 |
| auditor | 3,801 | 0 | 0 |
| big_payload | 1,883 | 0 | 0 |
| c2sp_export | 1,223 | 0 | 0 |
| c2sp_user | 1,822 | 0 | 0 |
| cli_nocode | 3,826 | 0 | 0 |
| cli_only | 5,005 | 0 | 0 |
| coder | 12,443 | 0 | 0 |
| commerce | 2,480 | 0 | 0 |
| crash_restart | 3,732 | 0 | 0 |
| directory_builder | 1,250 | 0 | 0 |
| discloser | 3,784 | 0 | 0 |
| evidence_window | 1,258 | 0 | 0 |
| go_verifier | 1,218 | 0 | 0 |
| handoff_pair | 2,442 | 0 | 0 |
| hook_user | 1,254 | 0 | 0 |
| jcs_user | 2,454 | 0 | 0 |
| journal_serve | 1,249 | 0 | 0 |
| mcp_0_4 | 1,265 | 0 | 0 |
| mcp_proxy_user | 582 | 0 | 0 |
| mcp_user | 1,181 | 0 | 0 |
| multisession | 3,100 | 0 | 0 |
| node_user | 1,181 | 0 | 0 |
| operator | 610 | 0 | 0 |
| pipeline | 3,723 | 0 | 0 |
| recorder | 2,433 | 0 | 0 |
| researcher | 4,878 | 0 | 0 |
| rollback_victim | 636 | 0 | 0 |
| schema | 1,175 | 0 | 0 |
| sealed | 2,428 | 0 | 0 |
| snapshot | 2,578 | 0 | 0 |
| strict_verifier | 1,882 | 0 | 0 |
| submitter | 3,703 | 0 | 0 |
| support | 6,223 | 0 | 0 |
| trader | 4,951 | 0 | 0 |
| verifier_only | 1,314 | 0 | 0 |
| witnesser | 2,495 | 0 | 0 |

## Latency per operation (ms; successful calls)

| op | n | p50 | p95 | p99 | max | failed |
|---|---|---|---|---|---|---|
| append_intent | 1,603,788 | 0.01 | 0.03 | 0.07 | 469.6 | 0 |
| append_result | 1,485,300 | 0.01 | 0.02 | 0.05 | 898.2 | 0 |
| witness.add-checkpoint | 247,446 | 84.95 | 302.78 | 485.85 | 1759.9 | 0 |
| append_memory.40k | 195,120 | 0.22 | 4.74 | 99.10 | 1547.1 | 0 |
| step.edit_file | 186,645 | 0.03 | 0.11 | 0.27 | 605.6 | 0 |
| sync | 89,264 | 45.89 | 201.33 | 348.43 | 1429.0 | 0 |
| open | 84,253 | 57.26 | 226.99 | 380.27 | 1532.0 | 0 |
| verify_dossier_json | 75,363 | 0.75 | 112.91 | 234.15 | 1218.3 | 0 |
| inclusion_proof | 49,510 | 0.42 | 86.74 | 203.49 | 864.5 | 0 |
| verify_inclusion | 49,510 | 0.02 | 0.03 | 0.09 | 278.3 | 0 |
| dossier_from_responses | 32,159 | 0.73 | 90.81 | 207.72 | 977.2 | 0 |
| append_memory | 31,115 | 0.01 | 0.06 | 0.12 | 124.7 | 0 |
| disclose | 30,272 | 0.02 | 0.08 | 0.16 | 290.4 | 0 |
| verify_disclosure | 30,272 | 0.00 | 0.01 | 0.03 | 62.0 | 0 |
| witnesser.request | 24,950 | 0.00 | 0.00 | 0.00 | 1.9 | 0 |
| scheduler.noop | 24,950 | 0.00 | 0.00 | 0.00 | 0.8 | 0 |
| recorder.intent | 24,330 | 0.02 | 0.09 | 0.17 | 174.1 | 0 |
| forget | 23,671 | 47.47 | 205.16 | 353.18 | 1377.3 | 0 |
| cli.log.append.intent | 22,956 | 86.53 | 277.51 | 446.25 | 1647.1 | 0 |
| cli.log.append.result | 22,956 | 84.94 | 275.61 | 434.42 | 1355.9 | 0 |
| checkpoint | 22,090 | 0.05 | 0.11 | 16.57 | 1271.2 | 0 |
| to_dossier_json | 18,666 | 0.14 | 43.06 | 147.42 | 663.9 | 0 |
| recorder.result | 17,031 | 0.02 | 0.05 | 0.11 | 79.1 | 0 |
| resume | 10,007 | 35.45 | 187.21 | 342.85 | 1226.3 | 0 |
| cli.submit | 9,467 | 171.15 | 397.99 | 582.35 | 1265.0 | 0 |
| cli.diff | 8,806 | 50.03 | 217.87 | 351.93 | 1084.8 | 0 |
| open.b | 8,645 | 50.80 | 213.59 | 362.51 | 925.6 | 0 |
| hook.pre | 7,524 | 168.94 | 527.38 | 768.04 | 1590.8 | 0 |
| hook.post | 7,524 | 167.18 | 509.12 | 819.81 | 1435.3 | 0 |
| recorder.result.error | 7,299 | 0.02 | 0.04 | 0.09 | 12.0 | 0 |
| can_forget | 6,223 | 0.00 | 0.01 | 0.03 | 3.3 | 0 |
| forget.after_restart | 6,223 | 43.13 | 204.40 | 361.24 | 815.8 | 0 |
| append_handoff_sent | 6,165 | 0.04 | 0.09 | 0.23 | 549.3 | 0 |
| append_handoff_received | 6,165 | 0.02 | 0.05 | 0.13 | 141.2 | 0 |
| append_result.2MiB | 5,649 | 77.51 | 250.97 | 400.72 | 1098.6 | 0 |
| cli.log.init | 5,075 | 96.22 | 300.51 | 478.20 | 828.3 | 0 |
| cli.verify | 5,005 | 52.38 | 227.28 | 367.67 | 801.1 | 0 |
| cli.explain | 5,005 | 35.93 | 202.05 | 333.29 | 774.6 | 0 |
| cli.log.forget | 3,826 | 100.47 | 298.95 | 471.86 | 1186.4 | 0 |
| cli.log.disclose | 3,826 | 37.82 | 200.73 | 341.99 | 760.7 | 0 |
| cli.log.info | 3,826 | 38.77 | 209.91 | 359.15 | 1154.0 | 0 |
| cli.verify.strict | 3,826 | 72.76 | 258.55 | 419.55 | 718.4 | 0 |
| cli.verify.other | 3,801 | 57.85 | 215.88 | 336.29 | 617.8 | 0 |
| cli.verify.tampered | 3,801 | 55.96 | 212.56 | 345.84 | 737.0 | 0 |
| cli.verify.known_head | 3,801 | 45.23 | 205.50 | 312.30 | 555.2 | 0 |
| open.store_payloads | 3,784 | 60.83 | 219.29 | 356.85 | 1056.5 | 0 |
| disclose.after_resume | 3,784 | 0.05 | 0.12 | 0.45 | 360.5 | 0 |
| resume.after_crash | 3,732 | 144.49 | 307.45 | 452.48 | 953.7 | 0 |
| submit | 3,703 | 1112.95 | 2369.68 | 3144.44 | 4997.8 | 0 |
| asubmit | 3,703 | 1546.99 | 3119.31 | 3985.36 | 6400.0 | 0 |
| cli.c2sp.verify | 3,045 | 40.88 | 205.87 | 398.06 | 855.4 | 0 |
| generate | 2,578 | 0.07 | 0.16 | 17.93 | 270.8 | 0 |
| save_snapshot | 2,578 | 38.48 | 177.13 | 304.04 | 796.3 | 0 |
| load_snapshot | 2,578 | 0.31 | 0.83 | 36.66 | 215.7 | 0 |
| verify_continuity | 2,578 | 0.16 | 0.34 | 14.47 | 438.8 | 0 |
| witnesser.flush | 2,495 | 1143.22 | 2475.81 | 3302.13 | 5356.7 | 0 |
| ap2.mandate_hash | 2,480 | 0.07 | 0.14 | 0.41 | 201.5 | 0 |
| ap2.record_grant | 2,480 | 0.06 | 0.13 | 0.33 | 86.3 | 0 |
| ap2.record_grant.b | 2,480 | 0.04 | 0.09 | 0.30 | 176.2 | 0 |
| ap2.record_receipt | 2,480 | 0.07 | 0.15 | 0.53 | 112.6 | 0 |
| ap2.bind_profile_ap2 | 2,480 | 0.25 | 0.50 | 1.72 | 130.3 | 0 |
| ap2.dispute_export | 2,480 | 5.17 | 186.99 | 384.80 | 778.9 | 0 |
| x402.record_grant | 2,480 | 0.08 | 0.16 | 0.56 | 104.6 | 0 |
| x402.record_grant.b | 2,480 | 0.04 | 0.08 | 0.28 | 177.6 | 0 |
| vi.record_grant | 2,480 | 0.03 | 0.06 | 0.16 | 253.9 | 0 |
| vi.record_grant.b | 2,480 | 0.02 | 0.06 | 0.15 | 41.4 | 0 |
| x402.bind | 2,480 | 0.35 | 0.69 | 3.00 | 306.2 | 0 |
| vi.bind | 2,480 | 0.22 | 0.49 | 1.83 | 143.6 | 0 |
| mcp.session | 2,446 | 8370.98 | 10842.37 | 11939.92 | 13994.0 | 0 |
| append_authorization_event | 2,442 | 0.01 | 0.03 | 0.08 | 2.3 | 0 |
| append_authorization_event.b | 2,442 | 0.01 | 0.02 | 0.06 | 1.8 | 0 |
| verify_handoff_binding | 2,442 | 0.01 | 0.03 | 0.07 | 39.7 | 0 |
| verify_authorization_binding | 2,442 | 0.01 | 0.01 | 0.04 | 0.4 | 0 |
| cli.bind | 2,442 | 40.98 | 215.92 | 378.82 | 672.3 | 0 |
| cli.bind.tampered | 2,442 | 41.12 | 221.96 | 348.04 | 1039.3 | 0 |
| cli.log.info.seed_file | 2,428 | 44.90 | 218.84 | 403.92 | 1278.8 | 0 |
| proxy.tools_call | 2,328 | 96.67 | 440.68 | 660.33 | 1446.1 | 0 |
| sync.after_burst | 1,883 | 48.84 | 196.53 | 406.96 | 745.1 | 0 |
| cli.verify.strict.unwitnessed | 1,882 | 45.45 | 219.75 | 379.66 | 636.9 | 0 |
| cli.verify.strict.plain | 1,882 | 41.43 | 200.64 | 336.82 | 658.7 | 0 |
| cli.verify.invalid | 1,882 | 42.53 | 215.71 | 361.28 | 645.7 | 0 |
| cli.verify.garbage | 1,882 | 35.72 | 196.72 | 345.56 | 846.6 | 0 |
| sign_c2sp_checkpoint | 1,822 | 0.06 | 0.13 | 0.32 | 13.0 | 0 |
| cli.c2sp.show | 1,822 | 40.04 | 211.28 | 363.82 | 757.7 | 0 |
| hook.generic | 1,254 | 154.88 | 505.67 | 726.32 | 1474.1 | 0 |
| hook.status | 1,254 | 83.48 | 388.79 | 585.96 | 1594.3 | 0 |
| hook.export | 1,254 | 1464.67 | 3210.84 | 4179.22 | 4973.0 | 0 |
| hook.submit | 1,254 | 1298.22 | 3127.10 | 3919.77 | 5604.0 | 0 |
| cli.directory.build | 1,250 | 78.46 | 263.88 | 414.74 | 967.3 | 0 |
| cli.witness.init.json | 1,250 | 92.77 | 298.05 | 492.24 | 1221.5 | 0 |
| cli.directory.add | 1,250 | 80.68 | 278.26 | 444.58 | 1549.2 | 0 |
| journal.submit | 1,249 | 126.99 | 338.37 | 490.67 | 734.8 | 0 |
| cli.c2sp.export | 1,223 | 79.94 | 274.58 | 410.09 | 966.2 | 0 |
| go.verify | 1,223 | 76.88 | 282.15 | 425.50 | 783.6 | 0 |
| go.verify.witnessed | 1,218 | 139.12 | 391.95 | 605.85 | 1098.1 | 0 |
| go.verify.tampered | 1,218 | 134.02 | 417.58 | 654.16 | 1064.0 | 0 |
| go.verify.one_receipt | 1,218 | 134.97 | 436.35 | 698.34 | 1636.4 | 0 |
| cli.verify.node_dossier | 1,181 | 42.83 | 221.86 | 379.64 | 636.7 | 0 |
| jsonschema.validate | 1,175 | 3.29 | 117.55 | 220.88 | 704.7 | 0 |
| cli.submit.after_rollback | 636 | 42.55 | 220.29 | 381.17 | 723.1 | 0 |
| operator.logs_served | 610 | 1.00 | 1.00 | 1.00 | 1.0 | 0 |
| proxy.initialize | 582 | 708.35 | 1384.11 | 1659.78 | 2574.8 | 0 |
| proxy.tools_list | 582 | 71.58 | 282.21 | 465.25 | 816.0 | 0 |
| proxy.tools_call.fail | 582 | 103.65 | 388.33 | 513.31 | 1007.9 | 0 |
| proxy.tools_call.crash | 582 | 114.28 | 364.45 | 509.62 | 902.4 | 0 |
| proxy.tools_call.after_crash | 582 | 142.56 | 503.45 | 799.85 | 1070.1 | 0 |
| proxy.audit_status | 582 | 67.61 | 274.70 | 455.50 | 705.2 | 0 |
| proxy.audit_export | 582 | 188.48 | 510.19 | 749.76 | 1030.9 | 0 |
