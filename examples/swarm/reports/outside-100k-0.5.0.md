# Outside swarm: 100,000 agents against 0.5.0 (RFC-0002), 37 personas, 20 witnesses under four organisations

- driver: `examples/swarm/outside_0_4.py`, updated for the 0.5.0 exit codes (INVALID 40, exit 11 only for a sub-majority WITNESSED, a contradicted `--known-head` is DIVERGED 30); witnesses: four `fleet.py` fleets of five, one organisation each
- code: `main` at 7050e64 (0.4.3 plus RFC-0002), CLI built from it (it still reported 0.4.3: the version bump came after)
- target: `/home/claude/witness-log/target/release/witness-log` (witness-log 0.4.3), witness_log 0.4.3, 2 cpu, Linux x86_64
- 100,000 agents in 4430 s (22.6 agents/s), 2 x 24 in flight, 4,631,033 operations, 102,111 verdicts
- agents finished cleanly: 100,000/100,000; operations failed: 206/4,631,033
- witness add-checkpoint statuses: {200: 247446}
- verdicts: {'witnessed': 72108, 'unanchored': 28673, 'invalid': 1314, 'consistent_unwitnessed': 16}
- per-agent wall time: p50 1.32 s, p95 4.53 s, max 33.8 s

The `invalid` verdicts are the deliberate tamper checks: each of the
1,314 `verifier_only` agents edits the sample dossier's checkpoint
timestamp and expects INVALID (the other tamper checks run through the CLI
and are counted by exit code, not here). The 16 `consistent_unwitnessed`
are the proxy finding below.
Nothing that should verify failed to, and nothing tampered verified: the
stricter leaf validation and journal handling of 0.4.3 produced no
regression at this scale.

## Findings and triage

Each item has a regression test that fails before its fix and passes
after; they ship in 0.5.0.

| count | signature | triage |
|---|---|---|
| 206 | `witnesser.request` took more than 50 ms (0.83% of 24,744 calls; up to ~0.5 s) | **Fixed, and the 0.4.0 triage was wrong.** The 0.4.0 run called this scheduling. It was two real defects. (1) The Python binding held the GIL across fsync in `sync`, `forget`, `close` and `open`, so any thread's `sync` stalled every Python thread in the process: next to eight syncing threads a 1 ms sleep loop ran at a 44 ms median gap. These now release the GIL, as do the CPU-heavy calls (`verify_dossier_json`, `to_dossier_json`, proofs, request bodies), and a thread waiting for a log another thread holds waits without the GIL. (2) `request()` read the log's size and took the state lock, so it queued behind the background round. It now sets a flag and posts a wakeup. Tests: `test_sync_releases_the_gil_and_threads_share_a_log_safely`, `test_request_does_not_wait_behind_other_calls_on_the_log`. |
| 16 | `mcp_proxy_user`: `audit__export` returned CONSISTENT-UNWITNESSED (16 of 582 agents) | **Fixed.** An export that arrived while a periodic `--submit-every` round was still covering an older head skipped witnessing and handed on the unwitnessed current dossier. It now waits for the round in flight, then witnesses what it did not cover. The fix went live in the shared source tree at about batch 120: the 16 cases all fall in batches 7–114 and none in the 80 batches after. Test: `test_export_waits_for_a_round_in_flight`. |
| (10,000-agent confirmation run) | `mcp_proxy_user`: "proxy did not recover after a crash: server unavailable" (1 agent) | **Fixed.** The crashed call's error went to the host before the replacement server was running; a host that retried at once could reach the dead server's pipe. The error now goes out after the restart, host messages wait for a restart in progress, and a proxy at `--max-restarts` always exits non-zero (with the GIL now released in `sync`, the main thread could otherwise exit 0 first). Test: `test_a_retry_right_after_a_crash_reaches_the_restarted_server`. |

Found while fixing these, outside the swarm: `Dossier::verify` ran leaf
validation twice per dossier since the INVALID split (~15% of a
10,000-leaf verify; the overhead-budget job caught it), and `staticcheck`
stopped building under `setup-go` v6, which exports `GOTOOLCHAIN=local`.
Both fixed.

Observation, not a defect: a witness that holds tens of thousands of
logs from an earlier run reads every log file when it starts; on this
host's cold disk four fleets of five took minutes to answer. Fresh fleets
were used for the confirmation runs.

## Confirmation runs (10,000 agents each, fresh fleets, same host)

| run | code | findings | failed ops | `witnesser.request` max |
|---|---|---|---|---|
| a | 0.5.0 + export fix | 5 request > 50 ms, 1 proxy crash retry | 6 | 300 ms |
| b | + proxy crash ordering, GIL released for fsync | 9 request > 50 ms | 9 | 98 ms |
| c | + GIL released for CPU-heavy calls and lock waits | 5 request > 50 ms | 5 | 78 ms |
| d | + `request()` no longer reads the log; no-op baseline added | 4 request > 50 ms; no-op baseline 0 (max 0.1 ms) | 4 | 476 ms |
| e | + `request()` takes no lock (flag and wakeup queue) | **none** | **0** | **0.2 ms** |

Run d is what showed the remaining wait was the state lock, not the GIL:
a no-op timed the same way never passed 0.1 ms while `request()` still
did. Run e is the code that ships.

## Raw report of the 100,000-agent run

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
| mcp_proxy_user | 582 | 0 | 16 |
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
| append_intent | 1,603,788 | 0.01 | 0.03 | 0.06 | 554.0 | 0 |
| append_result | 1,485,300 | 0.01 | 0.02 | 0.05 | 758.3 | 0 |
| witness.add-checkpoint | 247,446 | 89.81 | 345.18 | 545.22 | 1575.9 | 0 |
| append_memory.40k | 195,120 | 0.21 | 1.53 | 77.58 | 798.2 | 0 |
| step.edit_file | 186,645 | 0.03 | 0.11 | 0.23 | 411.1 | 0 |
| sync | 89,264 | 4.45 | 157.32 | 306.57 | 1283.7 | 0 |
| open | 84,253 | 18.95 | 190.52 | 347.38 | 964.7 | 0 |
| verify_dossier_json | 75,363 | 0.62 | 21.08 | 124.15 | 738.7 | 0 |
| inclusion_proof | 49,510 | 0.39 | 14.80 | 111.13 | 946.6 | 0 |
| verify_inclusion | 49,510 | 0.01 | 0.03 | 0.08 | 426.1 | 0 |
| dossier_from_responses | 32,159 | 0.69 | 2.58 | 21.95 | 468.1 | 0 |
| append_memory | 31,115 | 0.01 | 0.05 | 0.11 | 206.6 | 0 |
| disclose | 30,272 | 0.02 | 0.07 | 0.18 | 444.0 | 0 |
| verify_disclosure | 30,272 | 0.00 | 0.01 | 0.03 | 280.2 | 0 |
| witnesser.request | 24,744 | 0.00 | 0.01 | 0.05 | 49.8 | 206 |
| recorder.intent | 24,330 | 0.02 | 0.08 | 0.18 | 286.6 | 0 |
| forget | 23,671 | 10.62 | 159.32 | 292.48 | 843.8 | 0 |
| cli.log.append.intent | 22,956 | 66.79 | 281.10 | 452.36 | 1418.6 | 0 |
| cli.log.append.result | 22,956 | 66.37 | 275.90 | 450.78 | 1144.5 | 0 |
| checkpoint | 22,090 | 0.05 | 0.09 | 4.71 | 404.0 | 0 |
| to_dossier_json | 18,666 | 0.13 | 0.30 | 21.58 | 664.3 | 0 |
| recorder.result | 17,031 | 0.02 | 0.05 | 0.11 | 161.7 | 0 |
| resume | 10,007 | 3.37 | 153.45 | 296.16 | 686.6 | 0 |
| cli.submit | 9,467 | 130.86 | 377.67 | 548.75 | 1243.3 | 0 |
| cli.diff | 8,806 | 42.26 | 219.58 | 370.91 | 684.8 | 0 |
| open.b | 8,645 | 27.04 | 223.21 | 393.70 | 790.4 | 0 |
| hook.pre | 7,524 | 172.55 | 560.83 | 767.21 | 1332.1 | 0 |
| hook.post | 7,524 | 167.71 | 530.50 | 800.96 | 1886.8 | 0 |
| recorder.result.error | 7,299 | 0.02 | 0.03 | 0.09 | 206.8 | 0 |
| can_forget | 6,223 | 0.00 | 0.01 | 0.03 | 34.2 | 0 |
| forget.after_restart | 6,223 | 4.12 | 146.99 | 274.19 | 770.1 | 0 |
| append_handoff_sent | 6,165 | 0.03 | 0.08 | 0.26 | 294.8 | 0 |
| append_handoff_received | 6,165 | 0.02 | 0.05 | 0.10 | 109.0 | 0 |
| append_result.2MiB | 5,649 | 53.63 | 226.21 | 392.87 | 754.9 | 0 |
| cli.log.init | 5,075 | 74.57 | 291.33 | 465.93 | 958.9 | 0 |
| cli.verify | 5,005 | 44.77 | 238.68 | 428.02 | 1017.0 | 0 |
| cli.explain | 5,005 | 36.12 | 231.69 | 381.82 | 921.7 | 0 |
| cli.log.forget | 3,826 | 72.21 | 284.06 | 444.04 | 1516.0 | 0 |
| cli.log.disclose | 3,826 | 37.92 | 228.68 | 389.94 | 812.0 | 0 |
| cli.log.info | 3,826 | 35.69 | 242.97 | 424.41 | 837.6 | 0 |
| cli.verify.strict | 3,826 | 57.24 | 258.03 | 434.86 | 1021.3 | 0 |
| cli.verify.other | 3,801 | 44.47 | 176.68 | 270.86 | 444.6 | 0 |
| cli.verify.tampered | 3,801 | 41.49 | 186.31 | 277.85 | 424.1 | 0 |
| cli.verify.known_head | 3,801 | 34.01 | 164.15 | 254.26 | 446.0 | 0 |
| open.store_payloads | 3,784 | 21.27 | 191.28 | 358.63 | 776.5 | 0 |
| disclose.after_resume | 3,784 | 0.05 | 0.11 | 0.99 | 255.5 | 0 |
| resume.after_crash | 3,732 | 133.92 | 298.85 | 430.73 | 1078.3 | 0 |
| submit | 3,703 | 1310.80 | 2442.41 | 3015.87 | 4150.8 | 0 |
| asubmit | 3,703 | 1689.69 | 3037.73 | 3711.17 | 5310.8 | 0 |
| cli.c2sp.verify | 3,045 | 37.82 | 223.80 | 375.95 | 905.8 | 0 |
| generate | 2,578 | 0.07 | 0.14 | 1.89 | 232.3 | 0 |
| save_snapshot | 2,578 | 8.47 | 195.30 | 348.38 | 613.6 | 0 |
| load_snapshot | 2,578 | 0.29 | 0.78 | 52.18 | 313.3 | 0 |
| verify_continuity | 2,578 | 0.16 | 0.32 | 17.48 | 196.0 | 0 |
| witnesser.flush | 2,495 | 1367.78 | 2543.21 | 3248.41 | 4803.4 | 0 |
| ap2.mandate_hash | 2,480 | 0.06 | 0.13 | 0.65 | 172.7 | 0 |
| ap2.record_grant | 2,480 | 0.06 | 0.11 | 0.77 | 91.3 | 0 |
| ap2.record_grant.b | 2,480 | 0.03 | 0.08 | 0.29 | 105.0 | 0 |
| ap2.record_receipt | 2,480 | 0.07 | 0.14 | 0.84 | 267.7 | 0 |
| ap2.bind_profile_ap2 | 2,480 | 0.24 | 0.85 | 37.73 | 222.9 | 0 |
| ap2.dispute_export | 2,480 | 53.26 | 292.41 | 500.91 | 833.9 | 0 |
| x402.record_grant | 2,480 | 0.09 | 0.16 | 0.39 | 196.1 | 0 |
| x402.record_grant.b | 2,480 | 0.04 | 0.08 | 0.23 | 174.4 | 0 |
| vi.record_grant | 2,480 | 0.02 | 0.06 | 0.12 | 37.3 | 0 |
| vi.record_grant.b | 2,480 | 0.02 | 0.05 | 0.12 | 6.0 | 0 |
| x402.bind | 2,480 | 0.34 | 1.79 | 75.53 | 316.6 | 0 |
| vi.bind | 2,480 | 0.19 | 0.56 | 36.23 | 553.7 | 0 |
| mcp.session | 2,446 | 7458.63 | 11306.46 | 12630.80 | 14777.2 | 0 |
| append_authorization_event | 2,442 | 0.01 | 0.02 | 0.08 | 139.4 | 0 |
| append_authorization_event.b | 2,442 | 0.01 | 0.02 | 0.07 | 1.6 | 0 |
| verify_handoff_binding | 2,442 | 0.01 | 0.02 | 0.08 | 153.9 | 0 |
| verify_authorization_binding | 2,442 | 0.01 | 0.01 | 0.04 | 119.6 | 0 |
| cli.bind | 2,442 | 61.87 | 286.04 | 478.66 | 832.8 | 0 |
| cli.bind.tampered | 2,442 | 37.92 | 242.12 | 433.18 | 700.5 | 0 |
| cli.log.info.seed_file | 2,428 | 42.99 | 236.47 | 403.91 | 781.2 | 0 |
| proxy.tools_call | 2,328 | 108.61 | 452.29 | 632.12 | 1336.7 | 0 |
| sync.after_burst | 1,883 | 17.10 | 182.66 | 357.73 | 568.7 | 0 |
| cli.verify.strict.unwitnessed | 1,882 | 42.15 | 241.95 | 381.95 | 642.7 | 0 |
| cli.verify.strict.plain | 1,882 | 40.31 | 225.95 | 360.88 | 870.6 | 0 |
| cli.verify.invalid | 1,882 | 37.61 | 230.13 | 386.70 | 794.2 | 0 |
| cli.verify.garbage | 1,882 | 35.71 | 216.47 | 400.55 | 651.4 | 0 |
| sign_c2sp_checkpoint | 1,822 | 0.05 | 0.12 | 0.63 | 121.5 | 0 |
| cli.c2sp.show | 1,822 | 39.78 | 228.04 | 378.31 | 723.2 | 0 |
| hook.generic | 1,254 | 144.16 | 460.44 | 678.22 | 1179.4 | 0 |
| hook.status | 1,254 | 101.75 | 423.90 | 635.62 | 1056.3 | 0 |
| hook.export | 1,254 | 1627.40 | 3022.65 | 3913.29 | 4870.2 | 0 |
| hook.submit | 1,254 | 1311.50 | 2830.37 | 3646.11 | 4742.5 | 0 |
| cli.directory.build | 1,250 | 59.86 | 259.33 | 427.12 | 838.8 | 0 |
| cli.witness.init.json | 1,250 | 69.81 | 280.22 | 386.56 | 732.0 | 0 |
| cli.directory.add | 1,250 | 61.98 | 266.54 | 447.29 | 659.5 | 0 |
| journal.submit | 1,249 | 118.04 | 373.73 | 564.69 | 1123.1 | 0 |
| cli.c2sp.export | 1,223 | 64.61 | 253.95 | 390.38 | 594.9 | 0 |
| go.verify | 1,223 | 65.25 | 293.74 | 479.57 | 1003.1 | 0 |
| go.verify.witnessed | 1,218 | 119.69 | 413.35 | 590.12 | 882.3 | 0 |
| go.verify.tampered | 1,218 | 122.25 | 415.50 | 594.58 | 919.6 | 0 |
| go.verify.one_receipt | 1,218 | 124.73 | 390.47 | 567.15 | 1331.4 | 0 |
| cli.verify.node_dossier | 1,181 | 38.18 | 219.72 | 415.25 | 831.2 | 0 |
| jsonschema.validate | 1,175 | 2.74 | 92.15 | 220.52 | 637.4 | 0 |
| cli.submit.after_rollback | 636 | 60.23 | 285.19 | 453.20 | 641.7 | 0 |
| operator.logs_served | 610 | 1.00 | 1.00 | 1.00 | 1.0 | 0 |
| proxy.initialize | 582 | 346.94 | 775.84 | 1016.44 | 1263.4 | 0 |
| proxy.tools_list | 582 | 74.96 | 331.64 | 556.79 | 657.7 | 0 |
| proxy.tools_call.fail | 582 | 76.68 | 349.03 | 514.59 | 859.7 | 0 |
| proxy.tools_call.crash | 582 | 99.51 | 377.30 | 511.47 | 807.2 | 0 |
| proxy.tools_call.after_crash | 582 | 100.86 | 324.36 | 537.32 | 1247.6 | 0 |
| proxy.audit_status | 582 | 64.70 | 294.58 | 482.13 | 657.5 | 0 |
| proxy.audit_export | 582 | 156.76 | 379.89 | 535.85 | 749.3 | 0 |
