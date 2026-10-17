#!/usr/bin/env python3
"""A three-organisation pilot, on localhost, with the CLI only.

Three organisations each run one witness and one agent. They exchange
witness directory entries once (that is the whole trust handshake), each
agent's log is cosigned by all three witnesses, and each organisation
verifies the others' agents. Shows why three is the smallest pilot that
reaches WITNESSED for everyone once each verifier says who operates the
log it is checking (`--subject-org`): an organisation's own witness never
counts as independent of its own agent, so each log needs the other two.

    cargo install witness-log-cli      # or put a release binary on PATH
    python3 examples/pilot-triangle/run.py

No network beyond 127.0.0.1, no accounts, nothing outside a temp directory.
Every command it runs is printed, so the same steps can be run by three
real organisations on three real machines (docs/wiki/Pilot-Three-Organisations.md).
Exits 0 only if every step behaved as described; 1 otherwise.

Options: --keep DIR keeps all artefacts in DIR (default: a temp dir, deleted).
Env: WITNESS_LOG_BIN=/path/to/witness-log to pick a specific CLI binary.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

CLI = os.environ.get("WITNESS_LOG_BIN") or shutil.which("witness-log")
if CLI and os.sep in CLI:
    CLI = os.path.abspath(CLI)
if not CLI:
    sys.exit("this demo needs the CLI on PATH: cargo install witness-log-cli (or set WITNESS_LOG_BIN)")

ORGS = [
    ("alpha", "Alpha Payments"),
    ("bravo", "Bravo Logistics"),
    ("charlie", "Charlie Audit"),
]

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


def cli(*args: str, cwd: str, show: bool = True) -> tuple[int, str, str]:
    if show:
        say("   $ witness-log " + " ".join(a if " " not in a else repr(a) for a in args))
    r = subprocess.run([CLI, *args], cwd=cwd, capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout, r.stderr


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_healthy(url: str) -> bool:
    for _ in range(200):
        try:
            urllib.request.urlopen(url + "/health", timeout=1).read()
            return True
        except Exception:
            time.sleep(0.05)
    return False


def verify_json(work: str, dossier: str, identity: str, directory: str, *extra: str) -> tuple[int, dict]:
    code, out, err = cli("verify", dossier, "--identity", identity, "--directory", directory, "--json", *extra, cwd=work)
    try:
        return code, json.loads(out)
    except ValueError:
        return code, {"error": err.strip()}


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
        work = tempfile.mkdtemp(prefix="wl-pilot-")
    t0 = time.monotonic()
    procs: list[subprocess.Popen] = []
    _, version, _ = cli("--version", cwd=work, show=False)
    say(f"witness-log three-organisation pilot  ({version.strip()})")

    try:
        step(1, "Each organisation starts one witness (one small always-on machine each)")
        for slug, org in ORGS:
            port = free_port()
            url = f"http://127.0.0.1:{port}"
            code, out, err = cli("witness", "init", f"{slug}/witness", "--name", f"witness.{slug}.example/w1",
                                 "--org", org, "--url", url, "--json", cwd=work)
            check(code == 0, f"{org}: witness init")
            info = json.loads(out)
            with open(os.path.join(work, slug, "witness-entry.json"), "w") as f:
                json.dump({"vkey": info["vkey"], "org": org, "url": url}, f)
            procs.append(subprocess.Popen(
                [CLI, "witness", "serve", f"{slug}/witness", "--listen", f"127.0.0.1:{port}", "--open-enrollment"],
                cwd=work, stdout=open(os.path.join(work, f"{slug}-witness.log"), "w"), stderr=subprocess.STDOUT))
            check(wait_healthy(url), f"{org}: witness answering at {url}")

        step(2, "They exchange directory entries once: everyone builds the same pilot directory")
        for slug, org in ORGS:
            entry = json.load(open(os.path.join(work, slug, "witness-entry.json")))
            code, _, err = cli("directory", "add", "pilot-directory.json", "--vkey", entry["vkey"],
                               "--org", entry["org"], "--url", entry["url"], cwd=work)
            check(code == 0, f"added {org}'s witness" + (f" ({err.strip()})" if code else ""))
        directory = json.load(open(os.path.join(work, "pilot-directory.json")))
        check(len(directory["witnesses"]) == 3, "pilot-directory.json lists three witnesses, three organisations")

        step(3, "Each organisation's agent works and gets its log cosigned by all three witnesses")
        identities: dict[str, str] = {}
        for slug, org in ORGS:
            j = f"{slug}/agent.jsonl"
            code, out, err = cli("log", "init", j, cwd=work)
            check(code == 0, f"{org}: agent journal created")
            for kind, payload in (("--intent", '{"tool":"settle","invoice":"INV-7"}'), ("--result", '{"ok":true}')):
                cli("log", "append", j, kind, payload, cwd=work, show=False)
            _, out, _ = cli("log", "info", j, cwd=work, show=False)
            identities[slug] = json.loads(out)["identity"]
            code, out, err = cli("witness", "submit", j, "--directory", "pilot-directory.json",
                                 "--out", f"{slug}/dossier.json", "--min", "3", cwd=work)
            check(code == 0, f"{org}: all three witnesses cosigned" + (f" ({err.strip()[-160:]})" if code else ""))

        step(4, "Each organisation verifies another's agent, saying who operates the log (--subject-org)")
        for (slug, org), (vslug, vorg) in zip(ORGS, ORGS[1:] + ORGS[:1]):
            code, rep = verify_json(work, f"{slug}/dossier.json", identities[slug], "pilot-directory.json",
                                    "--subject-org", org)
            q = (rep.get("report") or {}).get("quorum") or {}
            check(code == 0 and rep.get("verdict") == "WITNESSED"
                  and q.get("distinct_independent_operators") == 2,
                  f"{vorg} checks {org}'s agent: {rep.get('verdict')} (exit {code}), "
                  f"independent operators {q.get('distinct_independent_operators')} "
                  f"({', '.join(q.get('independent_operators_represented') or [])}); {org}'s own witness not counted")

        step(5, "Why three: with only two organisations, each log has one independent witness")
        two = {"witnesses": [w for w in directory["witnesses"] if w["operator_org"] != ORGS[2][1]]}
        with open(os.path.join(work, "two-org-directory.json"), "w") as f:
            json.dump(two, f)
        code, rep = verify_json(work, "alpha/dossier.json", identities["alpha"], "two-org-directory.json",
                                "--subject-org", ORGS[0][1])
        q = (rep.get("report") or {}).get("quorum") or {}
        check(code == 10 and q.get("distinct_independent_operators") == 1,
              f"Alpha with only Bravo as the other party: {rep.get('verdict')} (exit {code}), "
              f"independent operators {q.get('distinct_independent_operators')} (WITNESSED needs 2)")
        code, rep = verify_json(work, "alpha/dossier.json", identities["alpha"], "two-org-directory.json")
        q = (rep.get("report") or {}).get("quorum") or {}
        check(q.get("distinct_independent_operators") == 2,
              f"without --subject-org the verifier cannot tell Alpha's witness is Alpha's: counted "
              f"{q.get('distinct_independent_operators')} independent operators ({rep.get('verdict')}, exit {code}); "
              f"always pass --subject-org")

        step(6, "A tampered copy is still caught by every verifier")
        d = json.load(open(os.path.join(work, "bravo", "dossier.json")))
        d["leaves"][0]["payload_hash"] = "00" * 32
        with open(os.path.join(work, "bravo", "tampered.json"), "w") as f:
            json.dump(d, f)
        code, rep = verify_json(work, "bravo/tampered.json", identities["bravo"], "pilot-directory.json",
                                "--subject-org", ORGS[1][1])
        check(code == 40 and rep.get("verdict") == "INVALID", f"edited leaf: {rep.get('verdict')} (exit {code})")
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
        say("Result: three organisations, one witness each, one exchange of directory entries, and every")
        say("agent's log is WITNESSED by the two organisations that do not operate it.")
    say(f"({elapsed:.1f} s; artefacts in {work})" if args.keep else f"({elapsed:.1f} s)")
    if not args.keep:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
