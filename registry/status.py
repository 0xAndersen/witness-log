#!/usr/bin/env python3
"""Probe every registered witness and write a status page.

Reads registry/witnesses/*.json, asks each witness for `GET /` and
`GET /health`, appends one sample per witness to a rolling history, and
writes:

  STATUS.md      a table for humans
  status.json    the same data for machines
  history.jsonl  one line per run: {"t": unix, "up": {<first 16 hex of pubkey>: 0|1}}

Uptime is the share of samples in the window (24 h, 7 d) in which the
witness answered /health with `ok` AND served the public key its registry
entry names. Nothing here is estimated: every number is a count over
history.jsonl, which is published next to the page.

Stdlib only. The `status` workflow runs this every 10 minutes and
force-pushes the three files to the orphan branch `status`:

  https://github.com/0xAndersen/witness-log/blob/status/STATUS.md
  https://raw.githubusercontent.com/0xAndersen/witness-log/status/status.json

Local use:

  python3 registry/status.py --out-dir /tmp/status
  python3 registry/status.py --registry-dir /tmp/reg --out-dir /tmp/status
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import glob
import json
import os
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_URL = "https://github.com/0xAndersen/witness-log"
RUN_ONE = f"{REPO_URL}/blob/main/docs/wiki/Operator-Onboarding.md"
DAY = 86400


def load_registry(reg_dir: str) -> tuple[list[dict], list[str]]:
    entries, problems = [], []
    for path in sorted(glob.glob(os.path.join(reg_dir, "*.json"))):
        try:
            with open(path) as f:
                e = json.load(f)
            if not isinstance(e, dict) or not e.get("pubkey") or not e.get("url"):
                raise ValueError("missing pubkey or url")
        except Exception as ex:  # noqa: BLE001
            problems.append(f"{os.path.basename(path)}: {ex}")
            continue
        e["_file"] = os.path.basename(path)
        entries.append(e)
    return entries, problems


def fetch(url: str, timeout: float) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "witness-log-status/1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:  # noqa: BLE001
        return 0, f"{type(e).__name__}: {e}"


def probe(entry: dict, timeout: float) -> dict:
    base = str(entry["url"]).rstrip("/")
    out = {"state": "down", "error": None, "info": None}
    hs, hbody = fetch(base + "/health", timeout)
    st, body = fetch(base + "/", timeout)
    info = None
    if st == 200:
        try:
            info = json.loads(body)
        except ValueError:
            info = None
    if isinstance(info, dict):
        out["info"] = info
    if hs != 200 or hbody.strip() != "ok":
        out["error"] = f"/health: HTTP {hs}" if hs else f"/health: {hbody[:120]}"
        return out
    if not isinstance(info, dict):
        out["error"] = f"GET /: HTTP {st}" if st != 200 else "GET /: not JSON"
        return out
    served = str(info.get("pubkey_hex", "")).lower()
    if served != str(entry["pubkey"]).lower():
        out["state"] = "key-mismatch"
        out["error"] = f"serves key {served[:16]}..., registry says {str(entry['pubkey'])[:16]}..."
        return out
    out["state"] = "up"
    return out


def read_history(path: str) -> list[dict]:
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                if isinstance(r, dict) and isinstance(r.get("t"), int) and isinstance(r.get("up"), dict):
                    rows.append(r)
            except ValueError:
                continue  # a torn line from an interrupted run is dropped, not fatal
    return rows


def uptime(rows: list[dict], key: str, since: int) -> tuple[float | None, int]:
    samples = [r["up"][key] for r in rows if r["t"] >= since and key in r["up"]]
    if not samples:
        return None, 0
    return sum(1 for s in samples if s) / len(samples), len(samples)


def last_seen(rows: list[dict], key: str) -> int | None:
    for r in reversed(rows):
        if r["up"].get(key):
            return r["t"]
    return None


def iso(t: int | None) -> str | None:
    if t is None:
        return None
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def pct(v: float | None, n: int) -> str:
    if v is None:
        return "n/a"
    return f"{v * 100:.1f}% ({n})"


def md_cell(v) -> str:
    s = "" if v is None else str(v)
    return s.replace("|", "\\|").replace("\n", " ")


def hkey(entry: dict) -> str:
    """History key: the first 64 bits of the public key keeps history.jsonl
    small (7 days x 144 probes x N witnesses) and is unambiguous in a registry
    validate.py keeps free of duplicate keys."""
    return str(entry["pubkey"]).lower()[:16]


def norm_org(o: str) -> str:
    return " ".join(str(o).split()).lower()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--registry-dir", default=os.path.join(HERE, "witnesses"))
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--history", help="history file (default <out-dir>/history.jsonl)")
    ap.add_argument("--timeout", type=float, default=5.0, help="per-request timeout, seconds")
    ap.add_argument("--keep-days", type=float, default=7.0, help="history kept, days")
    ap.add_argument("--now", type=int, help=argparse.SUPPRESS)  # tests only
    a = ap.parse_args(argv)

    now = a.now if a.now is not None else int(time.time())
    os.makedirs(a.out_dir, exist_ok=True)
    hist_path = a.history or os.path.join(a.out_dir, "history.jsonl")

    entries, problems = load_registry(a.registry_dir)
    with cf.ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda e: probe(e, a.timeout), entries))

    rows = [r for r in read_history(hist_path) if r["t"] >= now - int(a.keep_days * DAY)]
    if entries:
        rows.append({"t": now, "up": {hkey(e): int(r["state"] == "up") for e, r in zip(entries, results)}})
    tmp = hist_path + ".tmp"
    with open(tmp, "w") as f:
        for r in rows:
            f.write(json.dumps(r, separators=(",", ":"), sort_keys=True) + "\n")
    os.replace(tmp, hist_path)

    witnesses = []
    for e, r in zip(entries, results):
        info = r["info"] or {}
        u24, n24 = uptime(rows, hkey(e), now - DAY)
        u7, n7 = uptime(rows, hkey(e), now - 7 * DAY)
        ls = last_seen(rows, hkey(e))
        witnesses.append({
            "file": e["_file"],
            "name": e.get("name"),
            "operator_org": e.get("operator_org"),
            "url": e.get("url"),
            "pubkey": e["pubkey"],
            "runtime": e.get("runtime"),
            "compute_provider": e.get("compute_provider"),
            "is_project_operated": bool(e.get("is_project_operated")),
            "state": r["state"],
            "error": r["error"],
            "uptime_24h": u24, "samples_24h": n24,
            "uptime_7d": u7, "samples_7d": n7,
            "logs": info.get("logs") if r["state"] == "up" else None,
            "cosigned_since_start": info.get("cosigned_since_start") if r["state"] == "up" else None,
            "proven_equivocations_since_start": info.get("proven_equivocations_since_start") if r["state"] == "up" else None,
            "software": info.get("software") if r["state"] == "up" else None,
            "started_unix": info.get("started_unix") if r["state"] == "up" else None,
            "open_enrollment": info.get("open_enrollment") if r["state"] == "up" else None,
            "last_seen_unix": ls,
            "last_seen": iso(ls),
        })

    indep = [w for w in witnesses if not w["is_project_operated"]]
    summary = {
        "registered": len(witnesses),
        "up": sum(1 for w in witnesses if w["state"] == "up"),
        "independent_orgs_registered": len({norm_org(w["operator_org"]) for w in indep}),
        "independent_orgs_up": len({norm_org(w["operator_org"]) for w in indep if w["state"] == "up"}),
        "project_operated_registered": sum(1 for w in witnesses if w["is_project_operated"]),
    }
    status = {
        "generated_unix": now,
        "generated": iso(now),
        "history_samples": len(rows),
        "history_window_days": a.keep_days,
        "summary": summary,
        "registry_problems": problems,
        "witnesses": witnesses,
    }
    with open(os.path.join(a.out_dir, "status.json"), "w") as f:
        json.dump(status, f, indent=1, sort_keys=True)
        f.write("\n")
    with open(os.path.join(a.out_dir, "STATUS.md"), "w") as f:
        f.write(render_md(status))
    print(f"{summary['registered']} registered, {summary['up']} up, "
          f"{summary['independent_orgs_up']} independent operator orgs up; wrote {a.out_dir}", file=sys.stderr)
    return 0


def render_md(s: dict) -> str:
    sm = s["summary"]
    L = ["# witness-log witness status", ""]
    L.append(f"Generated {s['generated']} by [`registry/status.py`]({REPO_URL}/blob/main/registry/status.py) "
             f"from [`registry/witnesses/`]({REPO_URL}/tree/main/registry/witnesses). "
             f"Raw data: [`status.json`](status.json), [`history.jsonl`](history.jsonl).")
    L.append("")
    if not s["witnesses"]:
        L.append("**No registered witnesses yet — run one:** "
                 f"[{RUN_ONE}]({RUN_ONE})")
        L.append("")
        L.append("WITNESSED needs cosignatures from two or more distinct `operator_org` values in the "
                 "verifier's own directory. The first two independent operators to register are the "
                 "network's first real milestone.")
        for p in s["registry_problems"]:
            L.append(f"\n- registry file skipped: {md_cell(p)}")
        L.append("")
        return "\n".join(L)
    L.append(f"- registered witnesses: **{sm['registered']}**, up now: **{sm['up']}**")
    L.append(f"- distinct independent `operator_org` values: **{sm['independent_orgs_registered']}** registered, "
             f"**{sm['independent_orgs_up']}** up now (WITNESSED needs 2 in the verifier's directory)")
    L.append(f"- project-operated witnesses: {sm['project_operated_registered']} (they count as one bucket, however many)")
    L.append(f"- uptime = share of probes (every ~10 min, last {s['history_window_days']:g} days kept) where `/health` said `ok` "
             "and `GET /` served the registered key; sample count in brackets")
    L.append("")
    L.append("| operator_org | name | url | state | uptime 24h | uptime 7d | logs | cosigned since start | software | last seen |")
    L.append("|---|---|---|---|---|---|---|---|---|---|")
    order = sorted(s["witnesses"], key=lambda w: (w["is_project_operated"], norm_org(w["operator_org"] or ""), w["name"] or ""))
    for w in order:
        org = md_cell(w["operator_org"]) + (" (project)" if w["is_project_operated"] else "")
        state = {"up": "up", "down": "**down**", "key-mismatch": "**key mismatch**"}[w["state"]]
        L.append("| " + " | ".join([
            org, f"`{md_cell(w['name'])}`", md_cell(w["url"]), state,
            pct(w["uptime_24h"], w["samples_24h"]), pct(w["uptime_7d"], w["samples_7d"]),
            md_cell(w["logs"] if w["logs"] is not None else "-"),
            md_cell(w["cosigned_since_start"] if w["cosigned_since_start"] is not None else "-"),
            md_cell(w["software"] or "-"), md_cell(w["last_seen"] or "never (in window)"),
        ]) + " |")
    down = [w for w in order if w["state"] != "up"]
    if down:
        L += ["", "## Probe errors", ""]
        for w in down:
            L.append(f"- `{md_cell(w['name'])}`: {md_cell(w['error'])}")
    if s["registry_problems"]:
        L += ["", "## Registry files skipped", ""]
        L += [f"- {md_cell(p)}" for p in s["registry_problems"]]
    L += ["", f"Run your own witness: [{RUN_ONE}]({RUN_ONE})", ""]
    return "\n".join(L)


if __name__ == "__main__":
    sys.exit(main())
