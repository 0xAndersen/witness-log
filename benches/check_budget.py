"""Fail if any benchmark regressed more than the budget against the
committed baseline.

    python benches/check_budget.py target/bench-rust.json target/bench-python.json
    python benches/check_budget.py --update target/bench-*.json   # rewrite the baseline

Compared value: each metric's `normalized` median (metric time divided by
a calibration loop timed in the same repetition; see overhead.rs and
python_step.py). Raw nanoseconds are printed for information only: they
depend on the machine, the ratio much less so. Exit 1 on a regression
over the budget, or when a baseline metric is missing from the results.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
BASELINE = HERE / "baseline.json"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results", nargs="+")
    ap.add_argument("--baseline", default=str(BASELINE))
    ap.add_argument("--budget", type=float, default=None, help="allowed regression, e.g. 0.20")
    ap.add_argument("--update", action="store_true", help="write the results as the new baseline")
    args = ap.parse_args()

    current: dict = {}
    for p in args.results:
        current.update(json.loads(pathlib.Path(p).read_text())["metrics"])

    base_doc = json.loads(pathlib.Path(args.baseline).read_text()) if pathlib.Path(args.baseline).exists() else {}
    if args.update:
        base_doc["metrics"] = current
        pathlib.Path(args.baseline).write_text(json.dumps(base_doc, indent=2) + "\n")
        print(f"baseline updated: {args.baseline}")
        return 0

    budget = args.budget if args.budget is not None else float(base_doc.get("budget", 0.20))
    base = base_doc.get("metrics", {})
    failed = []
    print(f"budget: +{budget:.0%} on the normalized median; baseline runner: {base_doc.get('runner', '?')}")
    print(f"{'metric':<34} {'baseline':>10} {'current':>10} {'change':>8}   {'current ns':>12}")
    for name, b in sorted(base.items()):
        c = current.get(name)
        if c is None:
            print(f"{name:<34} {'':>10} {'MISSING':>10}")
            failed.append(name)
            continue
        change = c["normalized"] / b["normalized"] - 1.0
        flag = "  FAIL" if change > budget else ""
        print(f"{name:<34} {b['normalized']:>10.4f} {c['normalized']:>10.4f} {change:>+8.1%}   {c['ns']:>12,.0f}{flag}")
        if change > budget:
            failed.append(name)
    for name in sorted(set(current) - set(base)):
        print(f"{name:<34} {'(new)':>10} {current[name]['normalized']:>10.4f}")
    if failed:
        print(f"\nregressed beyond +{budget:.0%} (or missing): {', '.join(failed)}", file=sys.stderr)
        return 1
    print("\nwithin budget")
    return 0


if __name__ == "__main__":
    sys.exit(main())
