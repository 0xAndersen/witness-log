#!/usr/bin/env python3
"""The rewrite attack, reproduced on localhost.

An operator holds its agent's identity key and rewrites the agent's whole
history with it: a different event at an earlier index, re-signed by the
same key. Every signature in the rewritten log is valid. This script shows
what independent witnesses do with it.

    pip install witness-log            # Python package (provides `import witness_log`)
    cargo install witness-log-cli      # or put a release binary on PATH
    python3 examples/rewrite-attack/run.py

No network beyond 127.0.0.1, no accounts, nothing outside a temp directory.
Exits 0 only if every step behaved as described; 1 otherwise.

Options: --keep DIR keeps all artefacts in DIR (default: a temp dir, deleted).
Env: WITNESS_LOG_BIN=/path/to/witness-log to pick a specific CLI binary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

try:
    import witness_log as wl
except ImportError:  # pragma: no cover
    sys.exit("this demo needs the Python package: pip install witness-log")

CLI = os.environ.get("WITNESS_LOG_BIN") or shutil.which("witness-log")
if not CLI:
    sys.exit("this demo needs the CLI on PATH: cargo install witness-log-cli (or set WITNESS_LOG_BIN)")

# A fixed seed, so the agent's identity key is the same on every run. (Leaf
# hashes and roots still differ between runs: every payload is salted with 32
# fresh random bytes, which is what makes erasure possible.)
SEED = hashlib.sha256(b"witness-log rewrite-attack demo identity").digest()

HONEST = [
    ("intent", {"tool": "read_invoice", "args": {"invoice": "INV-0042"}}),
    ("result", {"supplier": "acct_supplier_17", "amount_due_usd": 250}),
    ("intent", {"tool": "transfer_funds", "args": {"to": "acct_supplier_17", "amount_usd": 25000}}),
    ("result", {"status": "ok", "tx_id": "tx_7ac31"}),
]
# What the operator would prefer the record said: leaf 2 transferred $250.
REWRITTEN = HONEST[:2] + [
    ("intent", {"tool": "transfer_funds", "args": {"to": "acct_supplier_17", "amount_usd": 250}}),
    ("result", {"status": "ok", "tx_id": "tx_7ac31"}),
]
KEEP = 2  # the operator keeps leaves 0-1 byte for byte and rewrites from leaf 2

failures: list[str] = []


def say(text: str = "") -> None:
    print(text, flush=True)


def step(n: int, title: str) -> None:
    say()
    say(f"── {n}. {title}")


def check(cond: bool, what: str) -> None:
    say(f"   {'✓' if cond else '✗'} {what}")
    if not cond:
        failures.append(what)


def cli(*args: str, cwd: str) -> tuple[int, str]:
    r = subprocess.run([CLI, *args], cwd=cwd, capture_output=True, text=True, timeout=60)
    return r.returncode, (r.stdout + r.stderr)


def show(out: str, keep: tuple[str, ...] = (), limit: int = 12) -> None:
    """Print the lines of CLI output that carry the point (all of them if keep is empty)."""
    lines = [l for l in out.splitlines() if l.strip()]
    if keep:
        lines = [l for l in lines if any(k in l for k in keep)]
    for l in lines[:limit]:
        say(f"     │ {l.rstrip()}")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def post(url: str, body: str) -> tuple[int, str]:
    req = urllib.request.Request(url, data=body.encode(), method="POST", headers={"Content-Type": "text/plain"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def append(log, events) -> None:
    for kind, payload in events:
        (log.append_intent if kind == "intent" else log.append_result)(wl.canonical_json(payload))
    log.sync()


def rewrite_from(src: str, dst: str, keep: int, events) -> "wl.JournaledLog":
    """What an operator holding the key and the journal can do: copy the
    journal, cut it back to `keep` leaves (exactly what restoring an old
    backup does), and append a different history. Leaves 0..keep-1 stay
    byte-identical, salts included; everything is signed by the same key."""
    with open(src) as f, open(dst, "w") as g:
        for line in f:
            rec = json.loads(line)
            if "leaf_type" in rec and rec["index"] >= keep:
                continue
            g.write(line)
    with open(src + ".salts") as f, open(dst + ".salts", "w") as g:
        for line in f:
            if json.loads(line)["i"] < keep:
                g.write(line)
    os.chmod(dst, 0o600)
    os.chmod(dst + ".salts", 0o600)
    log = wl.open(dst)  # resumes: same identity key, a new session key bound to it
    append(log, events)
    return log


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--keep", metavar="DIR", help="keep artefacts in DIR instead of a temp dir")
    args = ap.parse_args()
    if args.keep:
        work = os.path.abspath(args.keep)
        if os.path.exists(work):
            sys.exit(f"{work} exists; pick a new directory")
        os.makedirs(work)
    else:
        work = tempfile.mkdtemp(prefix="wl-rewrite-")
    t0 = time.monotonic()
    procs: list[subprocess.Popen] = []
    _, version = cli("--version", cwd=work)
    say(f"witness-log rewrite-attack demo  ({version.strip()}, Python witness_log {wl.__version__})")
    say("An operator rewrites its agent's history with the agent's own key. What do witnesses do?")

    try:
        # ── 1. two witnesses, two organisations ────────────────────────────
        step(1, "Start two witnesses run by two different organisations (localhost)")
        entries = []
        for name, org in (("witness-a", "Example Org A"), ("witness-b", "Example Org B")):
            port = free_port()
            url = f"http://127.0.0.1:{port}"
            code, out = cli("witness", "init", name, "--name", f"{name}.example/w", "--org", org, "--url", url, cwd=work)
            check(code == 0, f"witness init {name}")
            meta = json.load(open(os.path.join(work, name, "witness.json")))
            entries.append({"name": meta["key_name"], "operator_org": org, "url": url, "pubkey": meta["pubkey_hex"],
                            "runtime": "human", "compute_provider": None, "is_project_operated": False})
            procs.append(subprocess.Popen([CLI, "witness", "serve", name, "--listen", f"127.0.0.1:{port}", "--open-enrollment"],
                                          cwd=work, stdout=open(os.path.join(work, f"{name}.log"), "w"), stderr=subprocess.STDOUT))
        for e in entries:
            for _ in range(100):
                try:
                    urllib.request.urlopen(e["url"] + "/health", timeout=1).read()
                    break
                except Exception:
                    time.sleep(0.05)
            say(f"   {e['operator_org']:<14} {e['url']}  key {e['pubkey'][:16]}…")
        with open(os.path.join(work, "trusted.json"), "w") as f:
            json.dump({"witnesses": entries}, f, indent=2)
        say("   trusted.json = the verifier's own directory of witnesses it trusts")

        # ── 2. the agent works; its log gets witnessed ─────────────────────
        step(2, "The agent works: 4 leaves (intent, result, intent, result)")
        log = wl.open(os.path.join(work, "agent.jsonl"), SEED)
        append(log, HONEST)
        agent_key = log.identity_pubkey_hex()
        honest_root = log.root_hex()
        log.close()
        for i, (kind, p) in enumerate(HONEST):
            say(f"   leaf {i} {kind:<6} {json.dumps(p, separators=(',', ':'))}")
        say(f"   agent identity key {agent_key[:16]}…  tree size 4  root {honest_root[:16]}…")

        step(3, "Get the head cosigned (c2sp.org/tlog-witness), then verify offline")
        code, out = cli("witness", "submit", "agent.jsonl", "--directory", "trusted.json", "--out", "honest.json", cwd=work)
        show(out, limit=6)
        check(code == 0, "witness submit: both witnesses cosigned size 4")
        code, out = cli("verify", "honest.json", "--identity", agent_key, "--directory", "trusted.json", cwd=work)
        show(out, keep=("Verdict", "VERDICT", "WITNESSED", "operators"), limit=4)
        check(code == 0, f"honest dossier: exit {code} (0 = WITNESSED)")

        # ── 3. the operator rewrites history with the same key ─────────────
        step(4, "The operator rewrites history with the SAME key: leaf 2 now says $250")
        rw = rewrite_from(os.path.join(work, "agent.jsonl"), os.path.join(work, "rewritten.jsonl"), KEEP, REWRITTEN[KEEP:])
        check(rw.identity_pubkey_hex() == agent_key, "same identity key as the honest log")
        say(f"   leaves 0-1 kept byte for byte; leaf 2 intent {json.dumps(REWRITTEN[2][1], separators=(',', ':'))}")
        say(f"   tree size {rw.tree_size()}  root {rw.root_hex()[:16]}…  (honest root was {honest_root[:16]}…)")
        with open(os.path.join(work, "rewritten.json"), "w") as f:
            f.write(rw.to_dossier_json())
        code, out = cli("verify", "rewritten.json", "--identity", agent_key, cwd=work)
        show(out, keep=("✓", "✗", "Verdict", "VERDICT"), limit=8)
        check(code == 20, f"by signatures alone the rewrite is valid: exit {code} (20 = UNANCHORED, internally consistent)")

        step(5, "Ask the same witnesses to cosign the rewritten head")
        for e in entries:
            st, body = post(e["url"] + "/add-checkpoint", rw.add_checkpoint_body(0))
            say(f"   {e['operator_org']}: POST old 0 → {st} {body.strip()[:60]}")
            if st == 409:
                st, body = post(e["url"] + "/add-checkpoint", rw.add_checkpoint_body(int(body.strip())))
                say(f"   {e['operator_org']}: POST old {rw.tree_size()} → {st} {body.strip()[:70]}")
            check(st == 422, f"{e['operator_org']} refused the rewritten head with 422")
        rw.close()

        step(6, "Each witness wrote a self-contained evidence file; anyone can check it")
        for e, name in zip(entries, ("witness-a", "witness-b")):
            ev_dir = os.path.join(work, name, "evidence")
            files = sorted(os.listdir(ev_dir)) if os.path.isdir(ev_dir) else []
            check(len(files) == 1, f"{name}/evidence/ holds {len(files)} file(s)")
            if not files:
                continue
            ev = os.path.join(name, "evidence", files[0])
            size = os.path.getsize(os.path.join(work, ev))
            say(f"   {ev}  ({size} bytes)")
            code, out = cli("witness", "verify-evidence", ev, cwd=work)
            show(out, limit=6)
            check(code == 0, f"witness verify-evidence: exit {code} (0 = proves two signed roots for one size)")

        step(7, "Two copies of the log in hand: `witness-log diff`")
        code, out = cli("diff", "honest.json", "rewritten.json", cwd=work)
        show(out, keep=("Both claim", "signature:", "match root", "identical", "DIVERGENT", "EQUIVOCATION"), limit=8)
        check(code == 30 and "EQUIVOCATION DETECTED" in out, f"diff: exit {code} (30 = equivocation, both copies signed by one key)")

        step(8, "Can the rewritten dossier ever reach WITNESSED?")
        code, out = cli("verify", "rewritten.json", "--identity", agent_key, "--directory", "trusted.json", cwd=work)
        show(out, keep=("Verdict", "VERDICT", "receipts", "Quorum"), limit=4)
        check(code == 10, f"rewritten, no receipts: exit {code} (10 = CONSISTENT-UNWITNESSED)")
        d = json.load(open(os.path.join(work, "rewritten.json")))
        d["witness_receipts"] = json.load(open(os.path.join(work, "honest.json")))["witness_receipts"]
        with open(os.path.join(work, "rewritten+stolen-receipts.json"), "w") as f:
            json.dump(d, f)
        code, out = cli("verify", "rewritten+stolen-receipts.json", "--identity", agent_key, "--directory", "trusted.json", cwd=work)
        show(out, keep=("Verdict", "VERDICT", "receipts", "Quorum"), limit=4)
        check(code == 10, f"rewritten + the honest log's receipts pasted in: exit {code} (receipts sign the honest root; none count)")
        code, _ = cli("verify", "honest.json", "--identity", agent_key, "--directory", "trusted.json", cwd=work)
        check(code == 0, f"the honest dossier still verifies: exit {code} (WITNESSED)")
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()

    say()
    elapsed = time.monotonic() - t0
    if failures:
        say(f"FAILED ({len(failures)}): " + "; ".join(failures))
    else:
        say("Result: the rewrite was signed by the right key and is internally consistent, so a signature")
        say("check accepts it. Both witnesses refused it (422), each kept a file proving the operator signed")
        say("two different histories at size 4, and no rearrangement of receipts makes the rewrite WITNESSED.")
    say(f"({elapsed:.1f} s; artefacts in {work})" if args.keep else f"({elapsed:.1f} s)")
    if not args.keep:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
