#!/usr/bin/env python3
"""First-independent-WITNESSED report.

Builds a directory from the registry's independent entries
(`is_project_operated: false`), counts distinct operator_org values, and:

  - fewer than 2: prints why and claims nothing (exit 0, no file written);
  - 2 or more: writes a real journal with the `witness_log` package,
    submits it with `witness-log witness submit` to that directory, runs
    `witness-log verify --min-witnesses N` against the same directory, and
    writes a Markdown report with the exact commands, the operators whose
    cosignatures came back, the receipts and the verify output. The report
    is written only when the verdict is WITNESSED; any other verdict exits 1.

Requires the `witness-log` binary (--cli) and the `witness_log` Python
package in this interpreter. The `witnessed-report` workflow runs it.

  python3 registry/witnessed_report.py --cli ./witness-log \\
      --out examples/swarm/reports/first-independent-witnessed.md
  python3 registry/witnessed_report.py --registry-dir /tmp/reg ...   # local test
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import os
import shlex
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def norm_org(o: str) -> str:
    return " ".join(str(o).split()).lower()


def run(cmd: list[str], cwd: str) -> tuple[int, str]:
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=600)
    return r.returncode, (r.stdout + r.stderr).rstrip()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="first independent WITNESSED report")
    ap.add_argument("--registry-dir", default=os.path.join(HERE, "witnesses"))
    ap.add_argument("--cli", default="witness-log", help="path to the witness-log binary")
    ap.add_argument("--min-witnesses", type=int, default=2)
    ap.add_argument("--out", required=True, help="Markdown report to write on success")
    ap.add_argument("--work", help="working directory (default: a temp dir)")
    ap.add_argument("--run-url", default=os.environ.get("RUN_URL", ""), help="link to the CI run, for the report")
    a = ap.parse_args(argv)

    entries = []
    for p in sorted(glob.glob(os.path.join(a.registry_dir, "*.json"))):
        with open(p) as f:
            entries.append(json.load(f))
    # The directory is exactly what a verifier gets from build_directory.py.
    bd = subprocess.run([sys.executable, os.path.join(HERE, "build_directory.py"), "--exclude-project",
                         "--registry-dir", a.registry_dir], capture_output=True, text=True, check=True)
    indep = json.loads(bd.stdout)["witnesses"]
    orgs = sorted({norm_org(e["operator_org"]) for e in indep})
    print(f"registry: {len(entries)} entries, {len(indep)} independent, "
          f"{len(orgs)} distinct independent operator_org: {orgs}")
    if len(orgs) < 2:
        print("fewer than 2 distinct independent operator_org values in the registry: "
              "WITNESSED cannot be reached against it, so nothing is claimed and no report is written.")
        return 0
    if a.min_witnesses < 2:
        print("--min-witnesses below 2 would not demonstrate anything; refusing.")
        return 2

    work = a.work or tempfile.mkdtemp(prefix="witnessed-report-")
    os.makedirs(work, exist_ok=True)
    cli = os.path.abspath(a.cli) if os.sep in a.cli else a.cli
    with open(os.path.join(work, "directory.json"), "w") as f:
        f.write(bd.stdout)

    import witness_log as wl  # the released Python package

    journal = os.path.join(work, "agent.jsonl")
    log = wl.open(journal)
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    log.append_intent(json.dumps({"task": "first independent WITNESSED report", "at": now}).encode())
    log.append_result(json.dumps({"registry_independent_orgs": len(orgs), "directory_witnesses": len(indep)}).encode())
    log.append_intent(b"submit this journal to every independent witness in the registry")
    log.sync()
    ident = log.identity_pubkey_hex()
    size = log.tree_size()
    log.close()

    submit = [cli, "witness", "submit", "agent.jsonl", "--directory", "directory.json",
              "--out", "dossier.json", "--min", str(a.min_witnesses)]
    rc_s, out_s = run(submit, work)
    print(out_s)
    if rc_s != 0 or not os.path.exists(os.path.join(work, "dossier.json")):
        print(f"submit failed (exit {rc_s}); nothing claimed")
        return 1
    verify = [cli, "verify", "dossier.json", "--identity", ident, "--directory", "directory.json",
              "--min-witnesses", str(a.min_witnesses)]
    rc_v, out_v = run(verify, work)
    print(out_v)
    rc_j, out_j = run(verify + ["--json"], work)
    try:
        vj = json.loads(out_j)
    except ValueError:
        vj = {}
    if rc_v != 0 or vj.get("verdict") != "WITNESSED":
        print(f"verify exit {rc_v}, verdict {vj.get('verdict')}: not WITNESSED; nothing claimed")
        return 1
    _, c2sp = run([cli, "c2sp", "show", "dossier.json", "--origin", f"witness-log/{ident}", "--raw"], work)
    _, version = run([cli, "--version"], work)

    with open(os.path.join(work, "dossier.json")) as f:
        dossier = json.load(f)
    by_key = {e["pubkey"]: e for e in indep}
    receipts = dossier.get("witness_receipts", [])
    q = vj["report"]["quorum"]

    L = ["# First independent WITNESSED verdict against the public registry", ""]
    L.append(f"Generated {now} by `registry/witnessed_report.py`"
             + (f" in [this workflow run]({a.run_url})" if a.run_url else "") + f", with `{version}`.")
    L.append("")
    L.append(f"The registry held {len(entries)} witness entries; {len(indep)} are not project-operated, "
             f"from {len(orgs)} distinct `operator_org` values. The directory below is exactly those "
             "independent entries; project-operated witnesses were excluded, so the verdict does not rest on them.")
    L += ["", "## Commands", "", "```sh",
          "python3 registry/build_directory.py --exclude-project > directory.json",
          "# agent.jsonl: a fresh journal written with the witness_log package "
          f"({size} leaves, identity {ident})",
          " ".join(shlex.quote(x) for x in ["witness-log"] + submit[1:]),
          " ".join(shlex.quote(x) for x in ["witness-log"] + verify[1:]),
          "```", "", "## Operators that cosigned", "",
          "| operator_org | witness | url | pubkey | tree size | witnessed at (UTC) |",
          "|---|---|---|---|---|---|"]
    for r in receipts:
        e = by_key.get(r["witness_pubkey"], {})
        t = dt.datetime.fromtimestamp(r["witnessed_at_ms"] / 1000, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        L.append(f"| {e.get('operator_org', '?')} | `{e.get('name', '?')}` | {e.get('url', '?')} | "
                 f"`{r['witness_pubkey']}` | {r['tree_size']} | {t} |")
    L += ["", f"Distinct independent operators represented: {q.get('distinct_independent_operators')} "
          f"({', '.join(q.get('independent_operators_represented', []))}); valid receipts: {q.get('valid_receipts')}.",
          "", "## The checkpoint they cosigned (c2sp.org/tlog-checkpoint body)", "", "```", c2sp.strip(), "```",
          "", "## Cosignatures (from dossier.json)", "", "```json", json.dumps(receipts, indent=1), "```",
          "", "## `witness-log verify` output", "", "```", out_v.strip(), "```", "",
          "Anyone can re-run the check: the dossier and directory are attached to the workflow run, "
          "and `witness-log verify` needs nothing but those two files and the identity above.", ""]
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w") as f:
        f.write("\n".join(L))
    print(f"WITNESSED by {q.get('distinct_independent_operators')} independent operators; wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
