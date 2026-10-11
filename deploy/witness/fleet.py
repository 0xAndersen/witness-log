#!/usr/bin/env python3
"""Run a fleet of witness-log witnesses on one host.

    fleet.py init  <root> --count 100 --org "Example Org" --name-base witness.example/w \\
                   --url-base https://witness.example --compute hetzner [--base-port 20000]
    fleet.py serve <root> [--open-enrollment] [--bind 127.0.0.1]
    fleet.py status <root>
    fleet.py directory <root> > directory.json

`init` creates <root>/w000 ... each with its own key, and writes
<root>/fleet.json (ports, names) and <root>/directory.json (every entry).
`serve` starts every witness, restarts any that exits, and stops them all
on SIGTERM/SIGINT. One process per witness, one state directory each:
the lock, persist-before-cosign and evidence rules all apply unchanged.

A fleet is one operator. Verifiers score independence by `operator_org`,
so a hundred witnesses here count as ONE bucket toward WITNESSED. Run a
fleet for capacity and availability, not for independence; independence
comes from other organisations running their own (AGENT_OPERATOR.md).

Requires the `witness-log` binary on PATH or in $WL_BIN.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.request

BIN = os.environ.get("WL_BIN") or shutil.which("witness-log") or "witness-log"


def http_get(url: str, timeout: float = 5.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read().decode()
    except Exception as e:  # noqa: BLE001
        return 0, str(e)


def cmd_init(a: argparse.Namespace) -> int:
    os.makedirs(a.root, exist_ok=True)
    if os.path.exists(os.path.join(a.root, "fleet.json")):
        print(f"{a.root}/fleet.json exists; refusing to re-init a fleet (keys would be lost)", file=sys.stderr)
        return 1
    width = max(3, len(str(a.count - 1)))
    members, entries = [], []
    for i in range(a.count):
        d = os.path.join(a.root, f"w{i:0{width}d}")
        port = a.base_port + i
        name = f"{a.name_base}{i:0{width}d}"
        url = f"{a.url_base}" if a.count == 1 else f"{a.url_base}:{port}" if a.url_base.startswith("http://127") else f"{a.url_base}/w{i:0{width}d}"
        cmd = [BIN, "witness", "init", d, "--name", name, "--org", a.org, "--url", url]
        if a.compute:
            cmd += ["--compute", a.compute]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stderr, file=sys.stderr)
            return 1
        entries.append(json.loads(r.stdout))
        members.append({"dir": d, "port": port, "name": name})
    with open(os.path.join(a.root, "fleet.json"), "w") as f:
        json.dump({"members": members, "org": a.org, "bind": a.bind}, f, indent=1)
    with open(os.path.join(a.root, "directory.json"), "w") as f:
        json.dump({"witnesses": entries}, f, indent=1)
    print(f"{a.count} witnesses initialised under {a.root}; directory.json has every entry", file=sys.stderr)
    print("Back up the whole directory as one unit: every w*/witness.key with its own w*/logs/.", file=sys.stderr)
    return 0


def load_fleet(root: str) -> dict:
    with open(os.path.join(root, "fleet.json")) as f:
        return json.load(f)


def cmd_serve(a: argparse.Namespace) -> int:
    fleet = load_fleet(a.root)
    bind = a.bind or fleet.get("bind", "127.0.0.1")
    extra = ["--open-enrollment"] if a.open_enrollment else []
    if a.behind_proxy:
        extra += ["--max-conns-per-ip", "256", "--enroll-rate", "6000"]
    procs: dict[str, subprocess.Popen] = {}
    logs: dict[str, object] = {}
    stopping = False

    def start(m: dict) -> None:
        log = logs.setdefault(m["name"], open(os.path.join(m["dir"], "server.log"), "ab"))
        procs[m["name"]] = subprocess.Popen(
            [BIN, "witness", "serve", m["dir"], "--listen", f"{bind}:{m['port']}", *extra],
            stdout=log, stderr=log,
        )

    def stop(*_):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    for m in fleet["members"]:
        start(m)
    print(f"{len(procs)} witnesses serving on {bind}:{fleet['members'][0]['port']}-{fleet['members'][-1]['port']}", file=sys.stderr)
    backoff: dict[str, float] = {}
    while not stopping:
        time.sleep(1)
        for m in fleet["members"]:
            p = procs[m["name"]]
            if p.poll() is not None and not stopping:
                delay = backoff.get(m["name"], 1.0)
                print(f"{m['name']} exited {p.returncode}; restarting in {delay:.0f}s", file=sys.stderr)
                time.sleep(delay)
                backoff[m["name"]] = min(delay * 2, 60)
                start(m)
    for p in procs.values():
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
    for p in procs.values():
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill()
    print("fleet stopped", file=sys.stderr)
    return 0


def cmd_status(a: argparse.Namespace) -> int:
    fleet = load_fleet(a.root)
    bind = fleet.get("bind", "127.0.0.1")
    up = 0
    for m in fleet["members"]:
        st, body = http_get(f"http://{bind}:{m['port']}/")
        if st == 200:
            info = json.loads(body)
            up += 1
            print(f"up   {m['name']:40} logs={info['logs']:<6} cosigned={info['cosigned_since_start']:<6} equivocations={info['proven_equivocations_since_start']}")
        else:
            print(f"DOWN {m['name']:40} {body[:60]}")
    print(f"{up}/{len(fleet['members'])} up")
    return 0 if up == len(fleet["members"]) else 1


def cmd_directory(a: argparse.Namespace) -> int:
    with open(os.path.join(a.root, "directory.json")) as f:
        sys.stdout.write(f.read())
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init")
    i.add_argument("root")
    i.add_argument("--count", type=int, default=10)
    i.add_argument("--org", required=True, help="the organisation that runs this fleet (one independence bucket)")
    i.add_argument("--name-base", required=True, help="C2SP key name prefix, e.g. witness.example/w")
    i.add_argument("--url-base", required=True, help="public base URL, e.g. https://witness.example")
    i.add_argument("--compute", default=None)
    i.add_argument("--base-port", type=int, default=20000)
    i.add_argument("--bind", default="127.0.0.1")
    s = sub.add_parser("serve")
    s.add_argument("root")
    s.add_argument("--open-enrollment", action="store_true")
    s.add_argument("--behind-proxy", action="store_true", help="raise per-IP limits for a reverse proxy")
    s.add_argument("--bind", default=None)
    st = sub.add_parser("status")
    st.add_argument("root")
    d = sub.add_parser("directory")
    d.add_argument("root")
    a = ap.parse_args()
    return {"init": cmd_init, "serve": cmd_serve, "status": cmd_status, "directory": cmd_directory}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
