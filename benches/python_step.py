"""Per-call cost of the Python decorator path (`@witness_log.step`).

Each repetition times a calibration loop (`json.dumps` of a small dict,
the pure-Python work `step` itself does per call) immediately before the
metric and records `metric / calibration`; `check_budget.py` compares the
median ratio with the committed baseline.

    python benches/python_step.py --out target/bench-python.json
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import tempfile
import time

import witness_log

REPS = 21
CALLS = 2_000
CAL_ITERS = 20_000


def calibration_ns() -> float:
    d = {"tool": "transfer_funds", "args": [250], "kwargs": {}, "t_ms": 1700000000000}
    t = time.perf_counter_ns()
    for _ in range(CAL_ITERS):
        json.dumps(d, sort_keys=True, separators=(",", ":"))
    return (time.perf_counter_ns() - t) / CAL_ITERS


def measure(make_log):
    raw, ratio = [], []
    for _ in range(REPS):
        log = make_log()

        @witness_log.step(log)
        def transfer_funds(amount_usd: int) -> dict:
            return {"status": "ok", "tx_id": "tx_7ac31"}

        cal = calibration_ns()
        t = time.perf_counter_ns()
        for i in range(CALLS):
            transfer_funds(i)
        ns = (time.perf_counter_ns() - t) / CALLS
        raw.append(ns)
        ratio.append(ns / cal)
        close = getattr(log, "close", None)
        if close:
            close()
    return {"ns": round(statistics.median(raw), 1), "normalized": round(statistics.median(ratio), 4)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="target/bench-python.json")
    args = ap.parse_args()
    tmp = tempfile.mkdtemp(prefix="wl-bench-py-")
    n = [0]

    def journaled():
        n[0] += 1
        return witness_log.open(os.path.join(tmp, f"j{n[0]}.jsonl"))

    out = {
        "suite": "python",
        "calibration": "json.dumps of a 4-key dict",
        "metrics": {
            "python_step_inmem": measure(witness_log.WitnessLog.generate),
            "python_step_journaled_nosync": measure(journaled),
        },
    }
    text = json.dumps(out, indent=2) + "\n"
    print(text, end="")
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as f:
        f.write(text)


if __name__ == "__main__":
    main()
