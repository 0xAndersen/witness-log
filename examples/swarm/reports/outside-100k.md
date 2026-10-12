# Outside swarm: 100,000 agents, 37 personas, 20 witnesses under four organisations (0.4.0)

- driver: `examples/swarm/outside_0_4.py` (the 18 personas of `outside.py` plus 19 for the surfaces shipped in 0.4.0); witnesses: four `fleet.py` fleets of five, one organisation each
- target: `/home/claude/witness-log/target/release/witness-log` (witness-log 0.4.0), witness_log 0.4.0, 2 cpu, Linux x86_64
- 100,000 agents in 3649 s (27.4 agents/s), 2 x 24 in flight, 4,644,419 operations, 102,021 verdicts
- agents finished cleanly: 99,910/100,000; operations failed: 189/4,644,419
- witness add-checkpoint statuses: {200: 247419, 422: 24}
- verdicts: {'witnessed': 71520, 'unanchored': 28586, 'diverged': 1314, 'consistent_unwitnessed': 601}
- per-agent wall time: p50 1.04 s, p95 3.80 s, max 28.7 s

## Findings (clustered by signature, most frequent first)

Each signature below is annotated with its triage. "Fixed" items have a
regression test that fails on 0.4.0 and ship in 0.4.1; "harness" items are
defects of the swarm driver, kept here so the numbers above are
reproducible from the raw results.

| count | signature | triage |
|---|---|---|
| 582 | `mcp_proxy_user`: `audit__export` returned CONSISTENT-UNWITNESSED | **Fixed.** Two defects: the export did not witness the current head (only every `--submit-every` calls), and its verdict used the 0.66-of-directory fraction gate instead of the cosignature count `submit` used, so against a 20-witness directory no export could be WITNESSED. The export now witnesses the head first, rebuilds the dossier with its receipts (`witnessed_dossier_json`) and gates on the count. |
| 165 | `witnesser.request` took more than 50 ms | Observation. 0.7% of 24,785 calls on a two-core host running 48 agent threads; p99 is 0.05 ms. `request()` holds no lock across a network round; the outliers are scheduling. |
| 87 + 1 + 1 | `KeyError: WITNESS_LOG_IDENTITY_SEED_ENV` | Harness. The `sealed` persona sets and deletes a process-wide environment variable while 23 other agent threads run; a sibling thread read `os.environ` mid-delete. |
| 24 | `pipeline`: HTTP 422 "witness holds size 1, submitted 1" | Harness, and the witnesses were right. While a `sealed` agent had `WITNESS_LOG_IDENTITY_SEED_ENV` exported, a `pipeline` agent's seedless `open()` picked up that seed, so two journals shared one identity and presented two size-1 roots; every witness refused the second with evidence (12,779 evidence files in this run, 24 from this race, the rest from the 2,538 deliberate `adversary` forks). |
| 6 | `cli_nocode`: dossier written 0600 instead of 0644 | **Fixed.** `witness-log-hookd` changed the process umask around its socket bind; in-process daemons in sibling threads made concurrently spawned CLIs inherit 0600. The socket is now bound in a private directory and moved into place; no umask. |
| (smoke run) | `verify_handoff_binding` / `verify_authorization_binding` returned `None` on success | **Fixed.** They return `bool`; `handoff_binding_error` / `authorization_binding_error` return the reason. |
| (smoke run) | Node `canonicalJson` escaped non-ASCII, Python emitted UTF-8 | **Fixed.** Both are RFC 8785 now; Node's tests pin the bytes to Python's output. |
| (smoke run) | export after `submit` has no receipts | **Fixed.** `submit`/`Witnesser` save the round; `log.witnessed_dossier_json()` rebuilds the cosigned dossier. |
| (smoke run) | `hookd` removed its socket before releasing the journal | **Fixed.** Order reversed. |

Other observations, not defects: Python `log.submit` had p50 1.1 s under this
contention against 112 ms for the CLI (11 ms for both on the idle host; the
difference is six urllib threads per call under the GIL with 48 agent
threads); `open()` p50 was 12 ms (a resume mints and writes a session
binding) and p95 160 ms under load. The `mcp.session` persona (a full MCP
client handshake plus seven tool calls through a subprocess) is the slowest
at 6.3 s p50 and is dominated by process start.

Raw clusters as the driver printed them:

- **582x** `mcp_proxy_user note: proxy with --submit-every <n> exported consistent_unwitnessed after <n> calls`  
  e.g. (mcp_proxy_user#920) `proxy with --submit-every 3 exported consistent_unwitnessed after 7 calls`
- **165x** `witnesser.request: request() blocked <n> ms`  
  e.g. (witnesser#1930) `request() blocked 116 ms`
- **87x** `sealed crashed: KeyError: 'WITNESS_LOG_IDENTITY_SEED_ENV' @ ~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^`  
  e.g. (sealed#1799) `KeyError: 'WITNESS_LOG_IDENTITY_SEED_ENV' @ ~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^`
- **24x** `witness.add-checkpoint: HTTP <n>: consistency proof failed: witness holds size <n>, submitted <n>
`  
  e.g. (pipeline#25735) `HTTP 422: consistency proof failed: witness holds size 1, submitted 1
`
- **6x** `cli_nocode note: dossier mode <n>o<n>, expected <n>`  
  e.g. (cli_nocode#3160) `dossier mode 0o600, expected 0644`
- **1x** `mcp_0_4 crashed: KeyError: 'WITNESS_LOG_IDENTITY_SEED_ENV' @ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^`  
  e.g. (mcp_0_4#27670) `KeyError: 'WITNESS_LOG_IDENTITY_SEED_ENV' @ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^`
- **1x** `pipeline crashed: MalformedError: old_size <n> exceeds this log's size <n> @ st, body, ct = http("POST", w["url"].rstrip("/") + "<path>", log.add_checkpoint_body(o))`  
  e.g. (pipeline#68344) `MalformedError: old_size 6 exceeds this log's size 1 @ st, body, ct = http("POST", w["url"].rstrip("/") + "/add-checkpoint", log.add_checkpoint_body(o))`
- **1x** `mcp_user crashed: KeyError: 'WITNESS_LOG_IDENTITY_SEED_ENV' @ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^`  
  e.g. (mcp_user#82752) `KeyError: 'WITNESS_LOG_IDENTITY_SEED_ENV' @ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^`

## Per persona

| persona | agents | crashed | notes |
|---|---|---|---|
| adversary | 2,538 | 0 | 0 |
| auditor | 3,801 | 0 | 0 |
| big_payload | 1,883 | 0 | 0 |
| c2sp_export | 1,223 | 0 | 0 |
| c2sp_user | 1,822 | 0 | 0 |
| cli_nocode | 3,826 | 0 | 6 |
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
| mcp_0_4 | 1,265 | 1 | 0 |
| mcp_proxy_user | 582 | 0 | 582 |
| mcp_user | 1,181 | 1 | 0 |
| multisession | 3,100 | 0 | 0 |
| node_user | 1,181 | 0 | 0 |
| operator | 610 | 0 | 0 |
| pipeline | 3,723 | 1 | 0 |
| recorder | 2,433 | 0 | 0 |
| researcher | 4,878 | 0 | 0 |
| rollback_victim | 636 | 0 | 0 |
| schema | 1,175 | 0 | 0 |
| sealed | 2,428 | 87 | 0 |
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
| append_intent | 1,615,841 | 0.00 | 0.02 | 0.05 | 682.2 | 0 |
| append_result | 1,485,300 | 0.00 | 0.01 | 0.03 | 720.7 | 0 |
| witness.add-checkpoint | 247,419 | 74.24 | 292.17 | 455.94 | 2147.1 | 24 |
| append_memory.40k | 195,120 | 0.03 | 0.06 | 0.22 | 621.0 | 0 |
| step.edit_file | 186,645 | 0.02 | 0.09 | 0.19 | 259.5 | 0 |
| sync | 91,692 | 3.73 | 129.53 | 257.64 | 1024.2 | 0 |
| open | 84,253 | 12.18 | 159.52 | 292.20 | 1276.0 | 0 |
| verify_dossier_json | 77,703 | 0.54 | 2.78 | 56.69 | 575.6 | 0 |
| inclusion_proof | 49,510 | 0.08 | 0.14 | 4.25 | 507.2 | 0 |
| verify_inclusion | 49,510 | 0.01 | 0.02 | 0.04 | 304.5 | 0 |
| dossier_from_responses | 32,158 | 0.59 | 1.45 | 3.91 | 355.8 | 0 |
| append_memory | 31,115 | 0.01 | 0.04 | 0.08 | 339.7 | 0 |
| disclose | 30,272 | 0.02 | 0.07 | 0.15 | 164.4 | 0 |
| verify_disclosure | 30,272 | 0.00 | 0.01 | 0.02 | 356.1 | 0 |
| witnesser.request | 24,785 | 0.00 | 0.01 | 0.05 | 49.9 | 165 |
| recorder.intent | 24,330 | 0.01 | 0.08 | 0.14 | 239.0 | 0 |
| forget | 23,671 | 8.33 | 141.52 | 271.62 | 858.2 | 0 |
| cli.log.append.intent | 22,956 | 55.85 | 234.37 | 389.11 | 1209.0 | 0 |
| cli.log.append.result | 22,956 | 54.84 | 231.59 | 384.16 | 1115.0 | 0 |
| checkpoint | 22,090 | 0.04 | 0.07 | 0.41 | 343.1 | 0 |
| to_dossier_json | 18,666 | 0.11 | 0.24 | 15.63 | 390.3 | 0 |
| recorder.result | 17,031 | 0.01 | 0.04 | 0.08 | 143.0 | 0 |
| resume | 10,007 | 3.08 | 123.51 | 253.14 | 760.7 | 0 |
| cli.submit | 9,467 | 111.79 | 323.05 | 476.86 | 1016.9 | 0 |
| cli.diff | 8,806 | 34.08 | 187.04 | 320.64 | 924.8 | 0 |
| open.b | 8,645 | 24.60 | 182.70 | 317.73 | 1085.9 | 0 |
| hook.pre | 7,524 | 143.02 | 469.64 | 701.94 | 1432.6 | 0 |
| hook.post | 7,524 | 141.45 | 465.00 | 667.87 | 1358.1 | 0 |
| recorder.result.error | 7,299 | 0.01 | 0.02 | 0.07 | 212.0 | 0 |
| can_forget | 6,223 | 0.00 | 0.00 | 0.02 | 123.3 | 0 |
| forget.after_restart | 6,223 | 4.14 | 126.22 | 254.34 | 1129.5 | 0 |
| append_handoff_sent | 6,165 | 0.03 | 0.07 | 0.14 | 272.1 | 0 |
| append_handoff_received | 6,165 | 0.02 | 0.04 | 0.07 | 233.1 | 0 |
| append_result.2MiB | 5,649 | 2.12 | 27.25 | 117.77 | 386.1 | 0 |
| cli.log.init | 5,075 | 63.10 | 248.87 | 386.11 | 764.4 | 0 |
| cli.verify | 5,005 | 34.89 | 199.33 | 335.97 | 842.4 | 0 |
| cli.explain | 5,005 | 27.59 | 192.04 | 339.59 | 654.3 | 0 |
| cli.log.forget | 3,826 | 62.53 | 240.87 | 393.83 | 844.6 | 0 |
| cli.log.disclose | 3,826 | 28.01 | 180.08 | 300.00 | 840.0 | 0 |
| cli.log.info | 3,826 | 28.31 | 189.01 | 330.64 | 837.3 | 0 |
| cli.verify.strict | 3,826 | 46.10 | 214.93 | 342.16 | 700.5 | 0 |
| cli.verify.other | 3,801 | 41.69 | 167.90 | 256.71 | 429.5 | 0 |
| cli.verify.tampered | 3,801 | 39.90 | 173.02 | 275.51 | 470.8 | 0 |
| open.store_payloads | 3,784 | 10.76 | 160.31 | 292.06 | 871.4 | 0 |
| disclose.after_resume | 3,784 | 0.05 | 0.10 | 1.17 | 150.9 | 0 |
| resume.after_crash | 3,732 | 128.77 | 270.17 | 381.92 | 798.0 | 0 |
| submit | 3,703 | 1111.49 | 2061.79 | 2521.37 | 3509.5 | 0 |
| asubmit | 3,703 | 1465.16 | 2606.15 | 3188.46 | 4066.1 | 0 |
| cli.c2sp.verify | 3,045 | 29.37 | 194.36 | 339.04 | 539.1 | 0 |
| generate | 2,578 | 0.06 | 0.12 | 0.64 | 290.5 | 0 |
| save_snapshot | 2,578 | 4.63 | 153.21 | 300.75 | 465.0 | 0 |
| load_snapshot | 2,578 | 0.19 | 0.44 | 40.07 | 201.2 | 0 |
| verify_continuity | 2,578 | 0.09 | 0.16 | 0.79 | 175.8 | 0 |
| witnesser.flush | 2,495 | 1183.86 | 2194.53 | 2668.94 | 3686.6 | 0 |
| ap2.mandate_hash | 2,480 | 0.06 | 0.12 | 0.80 | 137.3 | 0 |
| ap2.record_grant | 2,480 | 0.05 | 0.10 | 0.67 | 153.4 | 0 |
| ap2.record_grant.b | 2,480 | 0.03 | 0.07 | 0.19 | 214.6 | 0 |
| ap2.record_receipt | 2,480 | 0.06 | 0.13 | 0.90 | 315.0 | 0 |
| ap2.bind_profile_ap2 | 2,480 | 0.22 | 0.87 | 59.96 | 496.1 | 0 |
| ap2.dispute_export | 2,480 | 44.60 | 249.55 | 412.14 | 866.0 | 0 |
| x402.record_grant | 2,480 | 0.08 | 0.15 | 0.39 | 4.2 | 0 |
| x402.record_grant.b | 2,480 | 0.03 | 0.07 | 0.16 | 1.3 | 0 |
| vi.record_grant | 2,480 | 0.02 | 0.05 | 0.14 | 7.7 | 0 |
| vi.record_grant.b | 2,480 | 0.02 | 0.03 | 0.08 | 3.3 | 0 |
| x402.bind | 2,480 | 0.31 | 1.99 | 44.71 | 403.0 | 0 |
| vi.bind | 2,480 | 0.18 | 0.74 | 56.28 | 335.2 | 0 |
| mcp.session | 2,444 | 6336.65 | 9934.58 | 11226.32 | 13126.8 | 0 |
| append_authorization_event | 2,442 | 0.01 | 0.02 | 0.05 | 326.4 | 0 |
| append_authorization_event.b | 2,442 | 0.01 | 0.01 | 0.05 | 31.0 | 0 |
| verify_handoff_binding | 2,442 | 0.01 | 0.03 | 0.09 | 70.1 | 0 |
| verify_authorization_binding | 2,442 | 0.00 | 0.01 | 0.03 | 80.8 | 0 |
| cli.bind | 2,442 | 49.77 | 249.04 | 382.06 | 731.7 | 0 |
| cli.bind.tampered | 2,442 | 30.21 | 189.66 | 334.61 | 618.2 | 0 |
| open.sealed_env | 2,428 | 13.96 | 162.32 | 313.14 | 554.2 | 0 |
| resume_with_identity | 2,341 | 2.00 | 111.02 | 245.41 | 410.5 | 0 |
| cli.log.info.seed_env | 2,341 | 49.05 | 246.24 | 397.80 | 666.7 | 0 |
| proxy.tools_call | 2,328 | 94.66 | 368.88 | 531.83 | 769.2 | 0 |
| sync.after_burst | 1,883 | 14.81 | 151.76 | 268.69 | 505.3 | 0 |
| cli.verify.strict.unwitnessed | 1,882 | 34.19 | 201.90 | 364.72 | 934.8 | 0 |
| cli.verify.strict.plain | 1,882 | 29.28 | 192.81 | 360.06 | 842.9 | 0 |
| cli.verify.garbage | 1,882 | 28.11 | 195.44 | 351.50 | 695.2 | 0 |
| sign_c2sp_checkpoint | 1,822 | 0.05 | 0.10 | 0.73 | 134.0 | 0 |
| cli.c2sp.show | 1,822 | 28.21 | 189.65 | 334.08 | 602.0 | 0 |
| hook.generic | 1,254 | 125.51 | 426.15 | 618.44 | 950.5 | 0 |
| hook.status | 1,254 | 88.17 | 344.53 | 532.53 | 1096.9 | 0 |
| hook.export | 1,254 | 1345.96 | 2716.29 | 3108.66 | 4540.9 | 0 |
| hook.submit | 1,254 | 1131.35 | 2366.41 | 3171.97 | 4158.7 | 0 |
| cli.directory.build | 1,250 | 55.35 | 241.95 | 420.82 | 895.3 | 0 |
| cli.witness.init.json | 1,250 | 58.41 | 239.63 | 380.13 | 561.1 | 0 |
| cli.directory.add | 1,250 | 52.30 | 235.41 | 387.15 | 611.0 | 0 |
| journal.submit | 1,249 | 98.40 | 337.29 | 485.04 | 1008.0 | 0 |
| cli.c2sp.export | 1,223 | 56.91 | 234.72 | 381.36 | 581.7 | 0 |
| go.verify | 1,223 | 48.68 | 233.60 | 387.42 | 1512.5 | 0 |
| go.verify.witnessed | 1,218 | 97.78 | 359.58 | 505.05 | 946.8 | 0 |
| go.verify.tampered | 1,218 | 98.73 | 350.07 | 560.12 | 878.4 | 0 |
| go.verify.one_receipt | 1,218 | 101.34 | 336.20 | 509.01 | 941.0 | 0 |
| cli.verify.node_dossier | 1,181 | 32.19 | 192.87 | 329.95 | 557.9 | 0 |
| jsonschema.validate | 1,175 | 2.43 | 72.21 | 189.04 | 571.6 | 0 |
| cli.submit.after_rollback | 636 | 50.82 | 237.28 | 366.04 | 725.3 | 0 |
| operator.logs_served | 610 | 1.00 | 1.00 | 1.00 | 1.0 | 0 |
| proxy.initialize | 582 | 291.16 | 655.23 | 849.03 | 1231.3 | 0 |
| proxy.tools_list | 582 | 60.03 | 267.55 | 416.05 | 593.1 | 0 |
| proxy.tools_call.fail | 582 | 66.66 | 272.32 | 406.40 | 557.4 | 0 |
| proxy.tools_call.crash | 582 | 86.33 | 299.37 | 420.87 | 737.1 | 0 |
| proxy.tools_call.after_crash | 582 | 76.71 | 297.94 | 436.82 | 761.1 | 0 |
| proxy.audit_status | 582 | 58.45 | 255.92 | 390.39 | 770.2 | 0 |
| proxy.audit_export | 582 | 125.82 | 337.24 | 516.39 | 726.4 | 0 |
