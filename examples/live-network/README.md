# Live witness network

Ten real witness processes on your machine, ten ways of using them. This
is the pressure test that found the two security bugs fixed in 0.3.1
(forks accepted at non-power-of-two sizes; cosigned receipts never
counting), kept here so anyone can rerun it.

```sh
cargo build --release -p witness-log-cli
cd crates/witness-log-python && pip install maturin && maturin develop && cd -
python examples/live-network/scenarios.py          # all ten, ~1 minute
python examples/live-network/scenarios.py s05 s07  # just some
```

It starts 8 Rust witnesses (`witness-log witness serve`) and 2 Python
witnesses (`py_witness.py`, ~60 lines on `witness_log.WitnessService`) on
ports 17300-17309, each with its own key, state directory, operator and
compute provider. Linux or macOS. Exit status is 0 only if every
scenario passes.

| # | Scenario | What must hold |
|---|----------|----------------|
| 1 | CLI agent end to end | `witness submit` gets 10/10; `verify` exits 0 (WITNESSED) |
| 2 | Pure-Python agent | stdlib `urllib` + bindings reach WITNESSED |
| 3 | Incremental growth, lost client state | consistency-proven advances; 409 size hints recover |
| 4 | Hostile HTTP | 15 malformed requests answered correctly; slowloris cut at ~10s; a flood from one address does not deny service to others |
| 5 | Equivocation | growing and same-size forks refused (422) by all ten; evidence written; fork never WITNESSED |
| 6 | Stale / replayed checkpoints | 400 / 200 / 409, never recorded as fork evidence |
| 7 | Crash durability | SIGKILL all witnesses after cosigning; restart; forks still refused; two servers on one state dir refused |
| 8 | 50 concurrent agents | 1,500 cosignings; every agent WITNESSED; racing submitters both succeed |
| 9 | Byzantine and Sybil witnesses | forged/garbage cosignatures rejected; one-operator directory not WITNESSED |
| 10 | Offline auditor | witnesses down, two files in hand: WITNESSED; five kinds of tampering all caught |

`py_witness.py` doubles as the reference for running a witness inside
any Python web stack.
