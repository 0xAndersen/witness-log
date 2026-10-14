#!/usr/bin/env python3
"""The outside swarm extended to every surface shipped in 0.4.0.

Reuses the eighteen personas of `outside.py` and adds twenty more, one per
new element: the CLI no-code path (`log`, `submit --strict`, `verify
--strict`, `journal serve`, `directory build/add`, `c2sp export`), Python
disclosure and `submit`, sealed journals from the environment, JCS
agreement across implementations, handoff and authorization bindings via
`bind` and the commerce profiles, dispute export, the MCP server's new
tools, the MCP proxy, the hook daemon, the framework `Recorder`, the Node
addon with both verifiers, the Go verifier against the Rust CLI, and
evidence windows. Each persona asserts what the docs promise and records
a note when the system disagrees, so the report lists findings, not just
crashes.

Built for a hundred thousand agents on a small host: results stream to
per-process JSONL files, each agent's workspace is deleted once it has
finished (crashed workspaces are kept, up to a cap), and the shared
dossier pool for auditors is bounded.

    python deploy/witness/fleet.py init /tmp/fleet --count 20 --org "Swarm Org" ...
    python deploy/witness/fleet.py serve /tmp/fleet --open-enrollment &
    python examples/swarm/outside_0_4.py --agents 100000 --directory /tmp/fleet/directory.json --out /tmp/out100k
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import gzip
import hashlib
import io
import json
import multiprocessing as mp
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
import outside as base  # noqa: E402

Agent, cli, verify_py, submit_py, MIN_WITNESSES = base.Agent, base.cli, base.verify_py, base.submit_py, base.MIN_WITNESSES
FAKE_MCP = os.path.join(REPO, "crates", "witness-log-python", "tests", "fake_mcp_server.py")
NODE_PKG = os.path.join(REPO, "clients", "node", "dist", "src", "index.js")
GO_VERIFY = os.environ.get("WL_GO_VERIFY", os.path.join(REPO, "target", "release", "witness-log-verify"))


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def dir_file(a: Agent) -> str:
    p = os.path.join(a.dir, "trusted.json")
    if not os.path.exists(p):
        json.dump(a.directory(), open(p, "w"))
    return p


def cosig_vkey(name: str, pubkey_hex: str) -> str:
    """C2SP cosignature/v1 verifier key: <name>+<keyid>+<base64(0x04||pub)>."""
    import base64
    pub = bytes.fromhex(pubkey_hex)
    kid = hashlib.sha256(name.encode() + b"\n\x04" + pub).digest()[:4]
    return f"{name}+{kid.hex()}+{base64.b64encode(b'\x04' + pub).decode()}"


def ident_of(dossier_json: str) -> str:
    return json.loads(dossier_json)["identity_pubkey"]


# ------------------------------------------------------------ CLI no-code path

def p_cli_nocode(a: Agent):
    """The README's six commands, from the shell, nothing else."""
    j = a.journal
    code, out, err = a.op("cli.log.init", cli, a, "log", "init", j)
    if code != 0 or "identity" not in out:
        a.notes.append(f"log init: exit {code} {err[:120]}")
        return
    ident = json.loads(out)["identity"]
    for i in range(6):
        code, out, err = a.op("cli.log.append.intent", cli, a, "log", "append", j, "--intent", json.dumps({"tool": "t", "i": i}))
        if code != 0:
            a.notes.append(f"log append intent: exit {code} {err[:120]}")
        code, out, err = a.op("cli.log.append.result", cli, a, "log", "append", j, "--result", json.dumps({"i": i}), "--outcome", "ok")
        if code != 0:
            a.notes.append(f"log append result: exit {code} {err[:120]}")
    code, out, err = a.op("cli.log.forget", cli, a, "log", "forget", j, "1")
    if code != 0:
        a.notes.append(f"log forget: exit {code} {err[:120]}")
    code, out, err = a.op("cli.log.disclose", cli, a, "log", "disclose", j, "2")
    if code != 0 or "salt" not in out:
        a.notes.append(f"log disclose: exit {code} {err[:120]}")
    code, out, err = a.op("cli.log.info", cli, a, "log", "info", j)
    if code != 0:
        a.notes.append(f"log info: exit {code} {err[:120]}")
    dp = os.path.join(a.dir, "dossier.json")
    code, out, err = a.op("cli.submit", cli, a, "submit", j, "--directory", dir_file(a), "--out", dp, "--min", str(MIN_WITNESSES))
    if code != 0:
        a.notes.append(f"submit --min {MIN_WITNESSES}: exit {code} {err[-160:]}")
        return
    code, out, err = a.op("cli.verify.strict", cli, a, "verify", dp, "--identity", ident, "--directory", dir_file(a), "--strict")
    a.verdicts.append({0: "witnessed", 10: "consistent-unwitnessed", 11: "below-strict", 20: "unanchored", 30: "diverged", 40: "invalid"}.get(code, f"exit{code}"))
    if code not in (0, 11):
        a.notes.append(f"verify --strict after submit: exit {code} {err[-160:]}")
    if os.name == "posix" and oct(os.stat(dp).st_mode & 0o777) != "0o644":
        a.notes.append(f"dossier mode {oct(os.stat(dp).st_mode & 0o777)}, expected 0644")


def p_strict_verifier(a: Agent):
    """`verify --strict` must be 11 on an unwitnessed dossier and 2 on garbage."""
    import witness_log as wl
    log = a.op("open", wl.open, a.journal, a.seed)
    for i in range(4):
        a.op("append_intent", log.append_intent, b"x")
    a.op("sync", log.sync)
    dp = os.path.join(a.dir, "d.json")
    open(dp, "w").write(log.to_dossier_json())
    ident = log.identity_pubkey_hex()
    log.close()
    code, out, err = a.op("cli.verify.strict.unwitnessed", cli, a, "verify", dp, "--identity", ident, "--directory", dir_file(a), "--strict")
    if code != 11:
        a.notes.append(f"verify --strict on an unwitnessed dossier: exit {code}, expected 11")
    code, out, err = a.op("cli.verify.strict.plain", cli, a, "verify", dp, "--identity", ident, "--directory", dir_file(a))
    if code != 10:
        a.notes.append(f"verify (no strict) on an unwitnessed dossier: exit {code}, expected 10")
    open(dp, "w").write("{not json")
    code, out, err = a.op("cli.verify.garbage", cli, a, "verify", dp)
    if code != 2:
        a.notes.append(f"verify on garbage: exit {code}, expected 2")


def p_journal_serve(a: Agent):
    """`journal serve` on loopback: append, forget, dossier, submit over HTTP."""
    port = free_port()
    code, so, se = a.op("cli.log.init", cli, a, "log", "init", a.journal)
    if code != 0:
        a.notes.append(f"log init before journal serve: exit {code} {se[:120]}")
        return
    proc = subprocess.Popen([a.cfg["cli"], "journal", "serve", a.journal, "--listen", f"127.0.0.1:{port}", "--directory", dir_file(a)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        url = f"http://127.0.0.1:{port}"
        for _ in range(50):
            st, _, _ = base.http("GET", url + "/health", timeout=2)
            if st == 200:
                break
            time.sleep(0.1)
        else:
            a.notes.append(f"journal serve did not answer /health: {proc.stderr.read().decode()[-200:]}")
            return
        for i in range(5):
            st, body, _ = base.http("POST", url + "/append", json.dumps({"kind": "intent", "payload": {"i": i}}))
            if st != 200:
                a.notes.append(f"journal serve /append: {st} {body[:100]}")
            st, body, _ = base.http("POST", url + "/append", json.dumps({"kind": "result", "payload": {"i": i}, "outcome": "ok"}))
            if st != 200:
                a.notes.append(f"journal serve /append result: {st} {body[:100]}")
        st, body, _ = base.http("POST", url + "/forget", json.dumps({"index": 1}))
        if st != 200:
            a.notes.append(f"journal serve /forget: {st} {body[:100]}")
        st, body, _ = base.http("GET", url + "/info")
        if st != 200:
            a.notes.append(f"journal serve /info: {st}")
        t0 = time.perf_counter()
        st, body, _ = base.http("POST", url + "/submit", json.dumps({"want": 6, "min": MIN_WITNESSES}), timeout=60)
        a.ops.append({"op": "journal.submit", "ms": (time.perf_counter() - t0) * 1000, "ok": st == 200, **({} if st == 200 else {"error": f"HTTP {st}: {body[:120]}"})})
        st, body, _ = base.http("GET", url + "/dossier")
        if st != 200:
            a.notes.append(f"journal serve /dossier: {st}")
            return
        rep = verify_py(a, body, ident_of(body), a.directory())
        if rep["verdict"] != "witnessed":
            a.notes.append(f"journal serve: dossier after /submit verifies {rep['verdict']}")
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()


def p_directory_builder(a: Agent):
    """`directory build` from a registry-shaped folder and `directory add`."""
    reg = os.path.join(a.dir, "registry")
    os.makedirs(reg)
    entries = a.directory()["witnesses"][:4]
    for i, e in enumerate(entries):
        json.dump(e, open(os.path.join(reg, f"w{i}.json"), "w"))
    out = os.path.join(a.dir, "built.json")
    code, so, se = a.op("cli.directory.build", cli, a, "directory", "build", "--registry", reg, "--include-project", "--out", out)
    if code != 0:
        a.notes.append(f"directory build: exit {code} {se[:120]}")
        return
    built = json.load(open(out))
    if len(built["witnesses"]) != len(entries):
        a.notes.append(f"directory build kept {len(built['witnesses'])} of {len(entries)} entries")
    e = a.directory()["witnesses"][-1]
    code, so, se = a.op("cli.witness.init.json", cli, a, "witness", "init", os.path.join(a.dir, "w"), "--name", f"swarm{a.idx}.test/w", "--org", "Swarm Agent Org", "--url", "http://127.0.0.1:1", "--json")
    if code != 0:
        a.notes.append(f"witness init --json: exit {code} {se[:120]}")
        return
    try:
        info = json.loads(so)
    except json.JSONDecodeError:
        a.notes.append(f"witness init --json printed non-JSON: {so[:80]!r}")
        return
    code, so, se = a.op("cli.directory.add", cli, a, "directory", "add", out, "--vkey", info["vkey"], "--org", "Swarm Agent Org", "--url", "http://127.0.0.1:1")
    if code != 0:
        a.notes.append(f"directory add: exit {code} {se[:120]}")
        return
    built2 = json.load(open(out))
    if len(built2["witnesses"]) != len(entries) + 1 or built2["witnesses"][-1]["pubkey"] != info["identity"]:
        a.notes.append("directory add did not append the witness by its vkey")
    _ = e


def p_c2sp_export(a: Agent):
    """A witnessed dossier -> `c2sp export` -> `c2sp verify` with witness keys -> Go parses the note."""
    import witness_log as wl
    log = a.op("open", wl.open, a.journal, a.seed)
    for i in range(3):
        a.op("append_intent", log.append_intent, b"c2sp")
    a.op("sync", log.sync)
    responses, statuses, _ = submit_py(a, log, a.pick_witnesses(log, 5))
    dossier, n = a.op("dossier_from_responses", log.dossier_from_responses, responses)
    log.close()
    dp = os.path.join(a.dir, "d.json")
    open(dp, "w").write(dossier)
    note = os.path.join(a.dir, "note.txt")
    code, so, se = a.op("cli.c2sp.export", cli, a, "c2sp", "export", dp, "--directory", dir_file(a), "--out", note)
    if code != 0:
        a.notes.append(f"c2sp export: exit {code} {se[:120]}")
        return
    keys = []
    for w in a.directory()["witnesses"][:12]:
        keys += ["--vkey", cosig_vkey(w["name"], w["pubkey"])]
    code, so, se = a.op("cli.c2sp.verify", cli, a, "c2sp", "verify", note, *keys)
    if n and code != 0:
        a.notes.append(f"c2sp verify of an exported note with {n} cosignatures: exit {code} {se[-120:]}")
    if os.path.exists(GO_VERIFY):
        code, so, se = a.op("go.verify", lambda: (lambda r: (r.returncode, r.stdout, r.stderr))(subprocess.run([GO_VERIFY, dp, "--directory", dir_file(a), "--identity", ident_of(dossier), "--json"], capture_output=True, text=True, timeout=60)))
        code2, so2, se2 = cli(a, "verify", dp, "--identity", ident_of(dossier), "--directory", dir_file(a))
        if code != code2:
            a.notes.append(f"Go verdict exit {code} != Rust exit {code2} ({se[-100:]})")


# ------------------------------------------------------------ Python surfaces

def p_discloser(a: Agent):
    """store_payloads + disclose + verify_disclosure + payload_hash; forget removes the payload."""
    import witness_log as wl
    log = a.op("open.store_payloads", wl.open, a.journal, a.seed, store_payloads=True)
    payloads = [json.dumps({"secret": i, "v": a.rng.random()}).encode() for i in range(8)]
    idx = [a.op("append_intent", log.append_intent, p) for p in payloads]
    a.op("sync", log.sync)
    leaves = json.loads(log.leaves_json())
    for i, p in zip(idx, payloads):
        d = a.op("disclose", log.disclose, i)
        if d.get("payload") != p:
            a.notes.append(f"disclose({i}) payload mismatch")
        if not a.op("verify_disclosure", wl.verify_disclosure, leaves[i], p, d["salt"]):
            a.notes.append(f"verify_disclosure false for leaf {i}")
        if wl.payload_hash(p, bytes.fromhex(d["salt"]), i) != leaves[i]["payload_hash"]:
            a.notes.append(f"payload_hash != leaf.payload_hash for {i}")
        if wl.verify_disclosure(leaves[i], p + b"x", d["salt"]):
            a.notes.append(f"verify_disclosure accepted a wrong payload for {i}")
    a.op("forget", log.forget, idx[2])
    try:
        d = log.disclose(idx[2])
        if d.get("payload") is not None or d.get("salt"):
            a.notes.append("disclose after forget still returns payload or salt")
    except ValueError as e:
        if "forgotten" not in str(e):
            a.notes.append(f"disclose after forget raised ValueError without saying why: {str(e)[:80]}")
    except Exception as e:  # noqa: BLE001
        a.notes.append(f"disclose after forget raised {type(e).__name__}: {str(e)[:80]}")
    sidecar = a.journal + ".payloads"
    if os.path.exists(sidecar) and payloads[2] in open(sidecar, "rb").read():
        a.notes.append("forgotten payload still present in the .payloads sidecar")
    log.close()
    log2 = a.op("resume", wl.open, a.journal, a.seed, store_payloads=True)
    d = a.op("disclose.after_resume", log2.disclose, idx[5])
    if d.get("payload") != payloads[5]:
        a.notes.append("payload store not readable after resume")
    log2.close()


def p_submitter(a: Agent):
    """log.submit / asubmit: one round to WITNESSED; a second round is a no-op extension."""
    import asyncio

    import witness_log as wl
    log = a.op("open", wl.open, a.journal, a.seed)
    for i in range(5):
        a.op("append_intent", log.append_intent, b"s")
    a.op("sync", log.sync)
    r = a.op("submit", log.submit, dir_file(a), 6, MIN_WITNESSES, timeout=20)
    a.verdicts.append(r["verdict"])
    if r["verdict"] != "witnessed":
        a.notes.append(f"log.submit verdict {r['verdict']} with {r.get('cosignatures')} cosignatures: {r.get('outcomes')}")
    a.op("append_intent", log.append_intent, b"more")
    r2 = a.op("asubmit", lambda: asyncio.run(log.asubmit(dir_file(a), 6, MIN_WITNESSES, timeout=20)))
    a.verdicts.append(r2["verdict"])
    if r2["verdict"] != "witnessed":
        a.notes.append(f"asubmit after growth: {r2['verdict']} {r2.get('outcomes')}")
    rep = verify_py(a, r2["dossier"] if isinstance(r2["dossier"], str) else json.dumps(r2["dossier"]), log.identity_pubkey_hex(), a.directory())
    if rep["verdict"] != "witnessed":
        a.notes.append(f"dossier from asubmit verifies {rep['verdict']}")
    open(os.path.join(a.dir, "dossier.json"), "w").write(r2["dossier"] if isinstance(r2["dossier"], str) else json.dumps(r2["dossier"]))
    log.close()


def _sealed_child(journal: str, seed_hex: str) -> None:
    """Runs in its own process: WITNESS_LOG_IDENTITY_SEED_ENV is process-wide,
    and a sibling thread's seedless open() must not inherit this seed."""
    import witness_log as wl
    notes = []
    env_name = "WL_SEED"
    os.environ[env_name] = seed_hex
    os.environ["WITNESS_LOG_IDENTITY_SEED_ENV"] = env_name
    log = wl.open(journal)
    for _ in range(4):
        log.append_intent(b"sealed")
    log.sync()
    ident = log.identity_pubkey_hex()
    log.close()
    header = open(journal).readline()
    if seed_hex in header:
        notes.append("sealed journal header contains the seed")
    if ident not in header:
        notes.append("sealed journal header lacks the identity pubkey")
    del os.environ["WITNESS_LOG_IDENTITY_SEED_ENV"]
    try:
        wl.open(journal)
        notes.append("sealed journal resumed without a seed")
    except Exception:
        pass
    try:
        wl.open(journal, hashlib.sha256(b"wrong" + bytes.fromhex(seed_hex)).digest())
        notes.append("sealed journal resumed with the wrong seed")
    except Exception:
        pass
    log = wl.open(journal, bytes.fromhex(seed_hex))
    if log.identity_pubkey_hex() != ident:
        notes.append("identity changed across a sealed resume")
    log.append_intent(b"after")
    rep = json.loads(wl.verify_dossier_json(log.to_dossier_json(), 0.66, ident))
    log.close()
    print(json.dumps({"notes": notes, "verdict": rep["verdict"], "ident": ident}))


def p_sealed(a: Agent):
    """Sealed from the environment: no seed in the header, resume needs the seed, wrong seed refused."""
    r = subprocess.run([sys.executable, "-c", f"import sys; sys.path.insert(0, {HERE!r}); import outside_0_4 as m; m._sealed_child(sys.argv[1], sys.argv[2])", a.journal, a.seed.hex()],
                       capture_output=True, text=True, timeout=120)
    a.ops.append({"op": "sealed.child", "ms": 0, "ok": r.returncode == 0, **({} if r.returncode == 0 else {"error": r.stderr[-300:]})})
    if r.returncode != 0:
        return
    out = json.loads(r.stdout.strip().splitlines()[-1])
    a.notes += out["notes"]
    a.verdicts.append(out["verdict"])
    env = {**os.environ, "WL_SEED_FILE_UNUSED": "1"}
    seed_file = os.path.join(a.dir, "seed.hex")
    open(seed_file, "w").write(a.seed.hex())
    code, so, se = a.op("cli.log.info.seed_file", lambda: (lambda x: (x.returncode, x.stdout, x.stderr))(
        subprocess.run([a.cfg["cli"], "log", "info", a.journal, "--identity-seed-file", seed_file], capture_output=True, text=True, timeout=60, env=env)))
    if code != 0:
        a.notes.append(f"CLI log info --identity-seed-file on a Python-sealed journal: exit {code} {se[-120:]}")


def p_jcs_user(a: Agent):
    """canonical_json must agree with the strict profile encoder and with Node's canonicalJson."""
    import witness_log as wl
    from witness_log.profiles import _jcs
    rng = a.rng

    def rnd(d=0):
        r = rng.random()
        if r < 0.25:
            return rng.choice([None, True, False])
        if r < 0.45:
            return rng.randint(-2**40, 2**40)
        if r < 0.55:
            return rng.choice([0.5, 1e21, 1e-7, 123456.789, -0.0, 2.5e-5, 1e300])
        if r < 0.7:
            return "".join(chr(rng.choice([0x41, 0x7A, 0x0A, 0x22, 0x5C, 0xE9, 0x20AC, 0x1F600, 0x1F])) for _ in range(rng.randint(0, 8)))
        if d > 3:
            return 1
        if r < 0.85:
            return [rnd(d + 1) for _ in range(rng.randint(0, 4))]
        return {"".join(chr(rng.choice([0x41, 0x62, 0xE9, 0x1F600])) for _ in range(rng.randint(1, 3))): rnd(d + 1) for _ in range(rng.randint(0, 4))}

    bad = 0
    samples = []
    for _ in range(200):
        v = rnd()
        if wl.canonical_json(v) != _jcs.canonicalize(v):
            bad += 1
            samples.append(v)
    if bad:
        a.notes.append(f"canonical_json != profiles._jcs on {bad}/200 values, e.g. {json.dumps(samples[0])[:80]}")
    a.ops.append({"op": "jcs.compare", "ms": 0, "ok": bad == 0})
    if a.idx % 7 == 0 and shutil.which("node") and os.path.exists(NODE_PKG):
        v = [rnd() for _ in range(20)]
        script = f"import('{NODE_PKG}').then(m=>{{const vs=JSON.parse(process.argv[1]);for(const x of vs)process.stdout.write(Buffer.from(m.canonicalJson(x)).toString('hex')+'\\n')}})"
        r = subprocess.run(["node", "-e", script, json.dumps(v)], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            a.notes.append(f"node canonicalJson failed: {r.stderr[-120:]}")
        else:
            got = r.stdout.split()
            mism = [i for i, x in enumerate(v) if i < len(got) and wl.canonical_json(x).hex() != got[i]]
            if mism:
                a.notes.append(f"node canonicalJson != python canonical_json on {len(mism)}/20 values, e.g. {json.dumps(v[mism[0]])[:80]}")


def p_handoff_pair(a: Agent):
    """Two logs, a handoff and an authorization pair, bound with `witness-log bind` and the Python checks."""
    import witness_log as wl
    ja, jb = a.journal, os.path.join(a.dir, "b.jsonl")
    la = a.op("open", wl.open, ja, a.seed)
    lb = a.op("open.b", wl.open, jb, hashlib.sha256(b"b" + a.seed).digest())
    ia, ib = la.identity_pubkey_hex(), lb.identity_pubkey_hex()
    state = wl.canonical_json({"order": a.idx, "qty": 3})
    scope = wl.canonical_json({"mandate": a.idx, "limit": 100})
    a.op("append_intent", la.append_intent, b"work")
    s = a.op("append_handoff_sent", la.append_handoff_sent, state, ib)
    r = a.op("append_handoff_received", lb.append_handoff_received, state, ia)
    g1 = a.op("append_authorization_event", la.append_authorization_event, "granted_by_me", scope, ib)
    g2 = a.op("append_authorization_event.b", lb.append_authorization_event, "granted_to_me", scope, ia)
    la.sync()
    lb.sync()
    leaves_a, leaves_b = json.loads(la.leaves_json()), json.loads(lb.leaves_json())
    hb = a.op("verify_handoff_binding", wl.verify_handoff_binding, ia, json.dumps(leaves_a[s]), ib, json.dumps(leaves_b[r]))
    if hb not in (None, True):
        a.notes.append(f"verify_handoff_binding on a matching pair: {hb}")
    ab = a.op("verify_authorization_binding", wl.verify_authorization_binding, ia, json.dumps(leaves_a[g1]), ib, json.dumps(leaves_b[g2]))
    if ab not in (None, True):
        a.notes.append(f"verify_authorization_binding on a matching pair: {ab}")
    if hb is None:
        a.notes.append("API: verify_handoff_binding returns None on success and a string on failure (falsy on success)")
    mix = wl.verify_handoff_binding(ia, json.dumps(leaves_a[s]), ib, json.dumps(leaves_b[g2]))
    if mix in (None, True):
        a.notes.append("verify_handoff_binding accepted a handoff/authorization mix")
    da, db = os.path.join(a.dir, "a.json"), os.path.join(a.dir, "b.json")
    open(da, "w").write(la.to_dossier_json())
    open(db, "w").write(lb.to_dossier_json())
    la.close()
    lb.close()
    code, so, se = a.op("cli.bind", cli, a, "bind", da, db, "--json")
    if code != 0:
        a.notes.append(f"bind on a matching pair: exit {code} {se[-120:]}")
    else:
        try:
            rep = json.loads(so)
            txt = json.dumps(rep)
            if "Some(" in txt or "GrantedByMe" in txt:
                a.notes.append("bind --json prints Rust Debug text")
        except json.JSONDecodeError:
            a.notes.append(f"bind --json is not JSON: {so[:80]!r}")
    # tamper B's handoff state -> MISMATCH
    d = json.load(open(db))
    for leaf in d["leaves"]:
        if leaf.get("handoff_state_hash"):
            leaf["handoff_state_hash"] = "00" * 32
    json.dump(d, open(db, "w"))
    code, so, se = a.op("cli.bind.tampered", cli, a, "bind", da, db)
    if code == 0:
        a.notes.append("bind exit 0 after tampering the handoff state hash")


def p_commerce(a: Agent):
    """AP2 / x402 / VI profiles: grant, receipt, bind_profile_ap2, dispute export; a tampered mandate fails."""
    import witness_log as wl
    from witness_log.profiles import ap2, vi, x402
    la = a.op("open", wl.open, a.journal, a.seed, store_payloads=True)
    lb = a.op("open.b", wl.open, os.path.join(a.dir, "b.jsonl"), hashlib.sha256(b"b" + a.seed).digest())
    ia, ib = la.identity_pubkey_hex(), lb.identity_pubkey_hex()
    mandate = {"id": f"m-{a.idx}", "max_amount": {"value": "120.00", "currency": "USD"}, "merchant": "example-merchant", "expires": 1800000000}
    h = a.op("ap2.mandate_hash", ap2.mandate_hash, mandate)
    if h != hashlib.sha256(wl.canonical_json(mandate)).hexdigest():
        a.notes.append("ap2.mandate_hash != sha256(canonical_json(mandate))")
    ga = a.op("ap2.record_grant", ap2.record_grant, la, mandate, counterparty=ib, scope="granted_by_me")
    gb = a.op("ap2.record_grant.b", ap2.record_grant, lb, mandate, counterparty=ia, scope="granted_to_me")
    settlement = {"amount": "119.50", "currency": "USD", "tx": f"0x{a.idx:064x}"}
    rb = a.op("ap2.record_receipt", ap2.record_receipt, lb, settlement, chain_id="eip155:8453", account="eip155:8453:0x" + "ab" * 20,
              tx_ref=settlement["tx"], anchor_url=f"https://explorer.example/tx/{settlement['tx']}", mandate=mandate)
    la.sync()
    lb.sync()
    da, db = la.to_dossier_json(), lb.to_dossier_json()
    rep = a.op("ap2.bind_profile_ap2", ap2.bind_profile_ap2, da, db, mandate=mandate)
    ap = rep.get("ap2", {})
    if not ap.get("mandate_hash_equal") or not ap.get("scope_not_widened"):
        a.notes.append(f"bind_profile_ap2 on an honest pair: {json.dumps(ap)[:160]}")
    anchors = ap.get("settlement_anchors", {})
    sides = [v for v in anchors.values() if isinstance(v, dict)] if isinstance(anchors, dict) else []
    if not any(side.get("proof_hash_ok", 0) > 0 and side.get("mandate_match", 0) > 0 for side in sides):
        a.notes.append(f"bind_profile_ap2 reports no verified settlement anchor tied to the mandate: {json.dumps(anchors)[:160]}")
    bad = dict(mandate, max_amount={"value": "999.00", "currency": "USD"})
    rep2 = ap2.bind_profile_ap2(da, db, mandate=bad)
    if rep2.get("ap2", {}).get("mandate_hash_equal"):
        a.notes.append("bind_profile_ap2 accepted a different mandate as equal")
    out = os.path.join(a.dir, "dispute")
    man = a.op("ap2.dispute_export", ap2.dispute_export, la, [ga], out, payloads={ga: ap2.mandate_bytes(mandate)}, bindings=[rep])
    for f in ("dossier.json", "disclosures.json", "bindings.json", "MANIFEST.sha256"):
        if not os.path.exists(os.path.join(out, f)):
            a.notes.append(f"dispute export lacks {f}")
    for line in open(os.path.join(out, "MANIFEST.sha256")):
        digest, _, name = line.strip().partition("  ")
        if hashlib.sha256(open(os.path.join(out, name), "rb").read()).hexdigest() != digest:
            a.notes.append(f"dispute MANIFEST digest wrong for {name}")
    _ = man
    # x402 and VI reuse the same calls
    m2 = x402.mandate({"scheme": "exact", "network": "base", "maxAmountRequired": "1000"}, {"payload": "p"})
    a.op("x402.record_grant", x402.record_grant, la, m2, counterparty=ib)
    a.op("x402.record_grant.b", x402.record_grant, lb, m2, counterparty=ia, scope="granted_to_me")
    cred = {"credential": "vic", "pan_token": "tok_" + "9" * 12, "limit": "50.00"}
    a.op("vi.record_grant", vi.record_grant, la, cred, counterparty=ib)
    a.op("vi.record_grant.b", vi.record_grant, lb, cred, counterparty=ia, scope="granted_to_me")
    la.sync()
    lb.sync()
    r3 = a.op("x402.bind", x402.bind, la.to_dossier_json(), lb.to_dossier_json(), mandate=m2)
    if not r3.get("ap2", {}).get("mandate_hash_equal"):
        a.notes.append("x402.bind: mandate_hash_equal false on an honest pair")
    r4 = a.op("vi.bind", vi.bind, la.to_dossier_json(), lb.to_dossier_json(), credential=cred)
    if not r4.get("ap2", {}).get("mandate_hash_equal"):
        a.notes.append("vi.bind: mandate_hash_equal false on an honest pair")
    _ = (gb, rb)
    la.close()
    lb.close()


def p_recorder(a: Agent):
    """The adapters' shared Recorder: intent/result/handoff with outcome on exceptions."""
    import witness_log as wl
    from witness_log.integrations import Recorder
    log = a.op("open", wl.open, a.journal, a.seed)
    rec = Recorder(log)
    for i in range(10):
        ii = a.op("recorder.intent", rec.intent, "search", {"q": i, "call_id": f"c{i}"})
        if i % 3 == 2:
            a.op("recorder.result.error", rec.result, "search", ii, "boom", outcome="error")
        else:
            a.op("recorder.result", rec.result, "search", ii, {"hits": i})
    if rec.errors:
        a.notes.append(f"Recorder errors: {rec.errors[:2]}")
    leaves = json.loads(log.leaves_json())
    types = [l["leaf_type"] for l in leaves]
    if types != [1, 2] * 10:
        a.notes.append(f"Recorder leaf types {types[:8]}...")
    d = log.to_dossier_json()
    verify_py(a, d, log.identity_pubkey_hex(), None)
    log.close()


def p_evidence_window(a: Agent):
    """Evidence windows via the CLI/Python wherever exposed; out-of-range must be refused."""
    import witness_log as wl
    log = a.op("open", wl.open, a.journal, a.seed)
    for i in range(12):
        a.op("append_intent", log.append_intent, b"w")
    a.op("sync", log.sync)
    f = getattr(log, "evidence_window", None) or getattr(log, "evidence_window_json", None)
    if f is None:
        a.ops.append({"op": "evidence_window", "ms": 0, "ok": True})
        log.close()
        return
    try:
        w = a.op("evidence_window", f, 2, 6)
        n = len(w["entries"]) if isinstance(w, dict) else len(json.loads(w)["entries"])
        if n != 4:
            a.notes.append(f"evidence_window(2,6) has {n} entries")
    except Exception as e:  # noqa: BLE001
        a.notes.append(f"evidence_window(2,6) raised {type(e).__name__}: {str(e)[:80]}")
    try:
        f(100, 200)
        a.notes.append("evidence_window(100,200) on a 12-leaf log did not raise")
    except Exception:
        pass
    log.close()


# ------------------------------------------------------------ MCP, proxy, hooks

def p_mcp_0_4(a: Agent):
    """The in-wheel server: record_result, record_handoff, record_authorization (enum/object scope), export_dossier digest, audit_this_session."""
    import anyio
    from mcp.client.client import Client
    from mcp.client.stdio import StdioServerParameters
    params = StdioServerParameters(command=sys.executable, args=["-m", "witness_log.mcp_server"], env={**os.environ, "WITNESS_LOG_HOME": os.path.join(a.dir, "mcp-home")})

    def data(r):
        sc = getattr(r, "structured_content", None)
        if sc:
            return sc.get("result", sc)
        return json.loads("".join(getattr(c, "text", "") for c in r.content))

    async def go():
        async with Client(params) as c:
            sid = f"agent-{a.idx}"
            init = data(await c.call_tool("initialize_witness_chain", {"session_id": sid, "metadata": {"persona": "mcp04"}}))
            r = data(await c.call_tool("append_audit_step", {"session_id": sid, "intent": "plan", "tool_name": "plan", "payload": {"k": 1}, "state_transition": {}}))
            rr = data(await c.call_tool("record_result", {"session_id": sid, "intent_index": r["intent_index"], "tool_name": "plan", "outcome": "error", "value": {"err": "x"}}))
            if "index" not in json.dumps(rr):
                a.notes.append(f"record_result returned {json.dumps(rr)[:100]}")
            other = "ab" * 32
            h = data(await c.call_tool("record_handoff", {"session_id": sid, "direction": "sent", "counterparty_identity_pubkey": other, "state": {"task": 1}}))
            if "index" not in json.dumps(h):
                a.notes.append(f"record_handoff returned {json.dumps(h)[:100]}")
            au = data(await c.call_tool("record_authorization", {"session_id": sid, "kind": "granted_by_me", "counterparty_identity_pubkey": other, "scope": {"limit": 5}}))
            if "index" not in json.dumps(au):
                a.notes.append(f"record_authorization(object scope) returned {json.dumps(au)[:100]}")
            try:
                bad = await c.call_tool("record_authorization", {"session_id": sid, "kind": "granted_sideways", "counterparty_identity_pubkey": other, "scope": "x"})
                if not getattr(bad, "is_error", False) and "error" not in json.dumps(data(bad)).lower():
                    a.notes.append("record_authorization accepted an unknown kind")
            except Exception:
                pass
            st = data(await c.call_tool("audit_this_session", {"session_id": sid}))
            if st.get("leaf_count") not in (6, 7) or st.get("witnessed") is not False:
                a.notes.append(f"audit_this_session: {json.dumps(st)[:120]}")
            ex = data(await c.call_tool("export_dossier", {"session_id": sid}))
            if not (ex.get("path") and os.path.exists(ex["path"]) and ex.get("sha256") == hashlib.sha256(open(ex["path"], "rb").read()).hexdigest()):
                a.notes.append(f"export_dossier path/sha256 mismatch: {json.dumps(ex)[:120]}")
            sub = data(await c.call_tool("submit_to_witnesses", {"session_id": sid, "directory": a.directory(), "max_witnesses": 6, "min_witnesses": MIN_WITNESSES}))
            a.verdicts.append(sub["verdict"])
            st2 = data(await c.call_tool("audit_this_session", {"session_id": sid}))
            if sub["verdict"] == "witnessed" and st2.get("witnessed") is not True:
                a.notes.append("audit_this_session.witnessed false after a WITNESSED submit")
            return init["identity_pubkey"]

    a.op("mcp.session", lambda: anyio.run(go))


def p_mcp_proxy_user(a: Agent):
    """witness-log-mcp-proxy around the fake server: calls, an error, a crash, audit__status/export, periodic witnessing."""
    journal = os.path.join(a.dir, "proxy.jsonl")
    proc = subprocess.Popen([sys.executable, "-m", "witness_log.mcp_proxy", "--name", "fake", "--journal", journal, "--timeout", "10",
                             "--directory", dir_file(a), "--submit-every", "3", "--", sys.executable, FAKE_MCP],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={**os.environ, "FAKE_MCP_PIDFILE": os.path.join(a.dir, "pids")})
    nid = [0]

    def call(method, params=None, timeout=20):
        nid[0] += 1
        proc.stdin.write((json.dumps({"jsonrpc": "2.0", "id": nid[0], "method": method, "params": params or {}}) + "\n").encode())
        proc.stdin.flush()
        out = {}

        def rd():
            out["l"] = proc.stdout.readline()
        t = threading.Thread(target=rd, daemon=True)
        t.start()
        t.join(timeout)
        if not out.get("l"):
            raise TimeoutError(f"proxy no answer to {method}")
        return json.loads(out["l"])

    try:
        r = a.op("proxy.initialize", call, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "s", "version": "0"}})
        proc.stdin.write((json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n").encode())
        proc.stdin.flush()
        tools = [t["name"] for t in a.op("proxy.tools_list", call, "tools/list")["result"]["tools"]]
        if tools != ["echo", "audit__status", "audit__export"]:
            a.notes.append(f"proxy tools/list: {tools}")
        for i in range(4):
            r = a.op("proxy.tools_call", call, "tools/call", {"name": "echo", "arguments": {"i": i}})
            if json.loads(r["result"]["content"][0]["text"]) != {"i": i}:
                a.notes.append("proxy altered an echo result")
        e = a.op("proxy.tools_call.fail", call, "tools/call", {"name": "echo", "arguments": {"fail": True}})
        if not e["result"].get("isError"):
            a.notes.append("proxy dropped isError")
        c = a.op("proxy.tools_call.crash", call, "tools/call", {"name": "echo", "arguments": {"crash": True}}, 30)
        if "error" not in c and not c.get("result", {}).get("isError"):
            a.notes.append("proxy answered a crashed call as success")
        r = a.op("proxy.tools_call.after_crash", call, "tools/call", {"name": "echo", "arguments": {"z": 1}}, 30)
        if "result" not in r:
            a.notes.append(f"proxy did not recover after a crash: {json.dumps(r)[:100]}")
        st = a.op("proxy.audit_status", call, "tools/call", {"name": "audit__status"})["result"]["structuredContent"]
        if st.get("restarts", 0) < 1 or st.get("calls", 0) < 6:
            a.notes.append(f"audit__status after crash: {json.dumps(st)[:120]}")
        ex = a.op("proxy.audit_export", call, "tools/call", {"name": "audit__export"}, 60)["result"]["structuredContent"]
        if ex.get("sha256") != hashlib.sha256(open(ex["path"], "rb").read()).hexdigest():
            a.notes.append("audit__export sha256 mismatch")
        a.verdicts.append(ex.get("verdict", "?"))
        if ex.get("verdict") != "witnessed":
            a.notes.append(f"proxy with --submit-every 3 exported {ex.get('verdict')} after {st.get('calls')} calls")
    finally:
        try:
            proc.stdin.close()
            proc.wait(10)
        except Exception:
            proc.kill()


def p_hook_user(a: Agent):
    """hookd + hook: Claude Code events and generic events over a Unix socket; status/export; --strict without a daemon."""
    if not hasattr(socket, "AF_UNIX"):
        return
    from witness_log import hook, hookd
    sock = os.path.join(tempfile.mkdtemp(prefix="hk", dir="/tmp"), "s.sock")
    d = hookd.Hookd(os.path.join(a.dir, "hooks.jsonl"), sock, directory=dir_file(a))
    d.bind()
    t = threading.Thread(target=d.serve_forever, daemon=True)
    t.start()
    try:
        for i in range(6):
            ev = {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": {"command": f"ls {i}"}}
            if a.op("hook.pre", hook.main, ["--socket", sock], stdin=io.StringIO(json.dumps(ev))) != 0:
                a.notes.append("hook PreToolUse exit != 0")
            ev2 = {**ev, "hook_event_name": "PostToolUse", "tool_response": {"stdout": "x"}}
            if a.op("hook.post", hook.main, ["--socket", sock], stdin=io.StringIO(json.dumps(ev2))) != 0:
                a.notes.append("hook PostToolUse exit != 0")
        a.op("hook.generic", hook.main, ["--socket", sock], stdin=io.StringIO(json.dumps({"tool": "t", "args": {"i": 1}, "result": "r"})))
        st = a.op("hook.status", hook.request, sock, {"op": "status"})
        if not st.get("ok") or st.get("leaf_count") != 13:
            a.notes.append(f"hook status: {json.dumps(st)[:120]}")
        ex = a.op("hook.export", hook.request, sock, {"op": "export"})
        if not ex.get("ok") or not os.path.exists(ex.get("path", "")):
            a.notes.append(f"hook export: {json.dumps(ex)[:120]}")
        else:
            rep = verify_py(a, open(ex["path"]).read(), st["identity"], None)
            if rep["verdict"] != "unanchored":
                a.notes.append(f"hook dossier verifies {rep['verdict']}")
        sub = a.op("hook.submit", hook.request, sock, {"op": "submit"}, 60)
        if sub.get("ok"):
            a.verdicts.append(sub.get("verdict", "?"))
    finally:
        d.shutdown()
        t.join(5)
    none = sock + ".none"
    if hook.main(["--socket", none], stdin=io.StringIO('{"tool": "x"}')) != 0:
        a.notes.append("hook without a daemon was fatal without --strict")
    if hook.main(["--socket", none, "--strict"], stdin=io.StringIO('{"tool": "x"}')) == 0:
        a.notes.append("hook --strict without a daemon exited 0")


# ------------------------------------------------------------ Node and Go

def p_node_user(a: Agent):
    """@witness-log/node: open, append, forget, disclose, export; both verifiers agree with the Rust CLI."""
    if not shutil.which("node") or not os.path.exists(NODE_PKG):
        return
    script = r"""
import fs from 'node:fs';
const [pkg, journal, seedHex] = process.argv.slice(1);
const wl = await import(pkg);
const log = wl.openLog(journal, { identitySeed: Buffer.from(seedHex, 'hex'), storePayloads: true });
for (let i = 0; i < 6; i++) { log.appendIntent({ tool: 'n', i }); log.appendResult({ i }, { outcome: i % 2 ? 'error' : 'ok' }); }
const m = log.appendMemory('secret ' + journal);
const d1 = log.disclose(m);
log.forget(m);
const d2 = log.disclose(m);
log.sync();
const dossier = log.exportDossier();
const ident = log.info().identityPubkey;
const a = wl.verifyDossier(dossier, { identity: ident });
const b = wl.verifyDossierNative(dossier, { identity: ident });
console.log(JSON.stringify({ ident, verdictTs: a.verdict, exitTs: a.exitCode, verdictNative: b.verdict, exitNative: b.exitCode, disclosedBefore: !!(d1 && d1.payload && d1.verified), disclosedAfter: !d2 || d2.payload == null }));
fs.writeFileSync(journal + '.dossier.json', typeof dossier === 'string' ? dossier : JSON.stringify(dossier));
log.close();
"""
    r = subprocess.run(["node", "--input-type=module", "-e", script, "--", NODE_PKG, a.journal, a.seed.hex()], capture_output=True, text=True, timeout=120)
    a.ops.append({"op": "node.session", "ms": 0, "ok": r.returncode == 0, **({} if r.returncode == 0 else {"error": r.stderr[-300:]})})
    if r.returncode != 0:
        return
    info = json.loads(r.stdout.strip().splitlines()[-1])
    if info["verdictTs"] != info["verdictNative"]:
        a.notes.append(f"node: TS verdict {info['verdictTs']} != native {info['verdictNative']}")
    if not info["disclosedBefore"] or not info["disclosedAfter"]:
        a.notes.append(f"node disclose before/after forget: {info['disclosedBefore']}/{info['disclosedAfter']}")
    code, so, se = a.op("cli.verify.node_dossier", cli, a, "verify", a.journal + ".dossier.json", "--identity", info["ident"])
    if code != 20:
        a.notes.append(f"Rust CLI on a Node-written dossier: exit {code} (expected 20 UNANCHORED) {se[-100:]}")
    if a.idx % 5 == 0:
        import witness_log as wl
        try:
            log = wl.open(a.journal, a.seed)
            log.append_intent(b"from python")
            log.close()
        except Exception as e:  # noqa: BLE001
            a.notes.append(f"Python could not resume a Node-written journal: {type(e).__name__}: {str(e)[:80]}")


def p_go_verifier(a: Agent):
    """A witnessed dossier, a tampered one and a bind pair through the Go verifier; exit codes must match Rust."""
    if not os.path.exists(GO_VERIFY):
        return
    import witness_log as wl
    log = a.op("open", wl.open, a.journal, a.seed)
    for i in range(5):
        a.op("append_intent", log.append_intent, b"g")
    a.op("forget", log.forget, 1)
    a.op("sync", log.sync)
    responses, statuses, _ = submit_py(a, log, a.pick_witnesses(log, 5))
    dossier, n = a.op("dossier_from_responses", log.dossier_from_responses, responses)
    ident = log.identity_pubkey_hex()
    log.close()
    dp = os.path.join(a.dir, "d.json")
    open(dp, "w").write(dossier)

    def both(path, *extra):
        r1 = subprocess.run([GO_VERIFY, path, *extra], capture_output=True, text=True, timeout=60)
        r2 = subprocess.run([a.cfg["cli"], "verify", path, *extra], capture_output=True, text=True, timeout=60)
        return r1.returncode, r2.returncode, r1.stderr[-100:]

    g, r, err = a.op("go.verify.witnessed", both, dp, "--identity", ident, "--directory", dir_file(a))
    if g != r:
        a.notes.append(f"Go {g} != Rust {r} on a witnessed dossier {err}")
    d = json.loads(dossier)
    d["leaves"][3]["payload_hash"] = "00" * 32
    open(dp, "w").write(json.dumps(d))
    g, r, err = a.op("go.verify.tampered", both, dp, "--identity", ident, "--directory", dir_file(a))
    if g != r or g != 40:
        a.notes.append(f"Go {g} != Rust {r} (want 40) on a tampered dossier {err}")
    d = json.loads(dossier)
    d["receipts"] = d.get("receipts", [])[:1]
    open(dp, "w").write(json.dumps(d))
    g, r, err = a.op("go.verify.one_receipt", both, dp, "--identity", ident, "--directory", dir_file(a))
    if g != r:
        a.notes.append(f"Go {g} != Rust {r} with one receipt {err}")


# ------------------------------------------------------------ witnesser

def p_witnesser(a: Agent):
    """Background Witnesser: request() never blocks; flush() reaches WITNESSED; state file written."""
    import witness_log as wl
    log = a.op("open", wl.open, a.journal, a.seed)
    w = wl.Witnesser(log, dir_file(a), a.journal, max_witnesses=6, min_cosignatures=MIN_WITNESSES)
    for i in range(10):
        a.op("append_intent", log.append_intent, b"bg")
        t0 = time.perf_counter()
        w.request()
        ms = (time.perf_counter() - t0) * 1000
        a.ops.append({"op": "witnesser.request", "ms": ms, "ok": ms < 50, **({} if ms < 50 else {"error": f"request() blocked {ms:.0f} ms"})})
    ok = a.op("witnesser.flush", w.flush, 60)
    st = w.status()
    d = w.dossier()
    if d:
        rep = verify_py(a, d, log.identity_pubkey_hex(), a.directory())
        if rep["verdict"] != "witnessed":
            a.notes.append(f"Witnesser dossier verifies {rep['verdict']} ({st})")
    else:
        a.notes.append(f"Witnesser produced no dossier: flush={ok} status={st}")
    if not os.path.exists(a.journal + ".witnesses.json"):
        a.notes.append("Witnesser wrote no state file")
    log.close()


PERSONAS = dict(base.PERSONAS)
PERSONAS.update({
    "cli_nocode": p_cli_nocode, "strict_verifier": p_strict_verifier, "journal_serve": p_journal_serve,
    "directory_builder": p_directory_builder, "c2sp_export": p_c2sp_export, "discloser": p_discloser,
    "submitter": p_submitter, "sealed": p_sealed, "jcs_user": p_jcs_user, "handoff_pair": p_handoff_pair,
    "commerce": p_commerce, "recorder": p_recorder, "evidence_window": p_evidence_window, "mcp_0_4": p_mcp_0_4,
    "mcp_proxy_user": p_mcp_proxy_user, "hook_user": p_hook_user, "node_user": p_node_user,
    "go_verifier": p_go_verifier, "witnesser": p_witnesser,
})
WEIGHTS = dict(base.WEIGHTS)
WEIGHTS.update({
    "cli_nocode": 6, "strict_verifier": 3, "journal_serve": 2, "directory_builder": 2, "c2sp_export": 2,
    "discloser": 6, "submitter": 6, "sealed": 4, "jcs_user": 4, "handoff_pair": 4, "commerce": 4,
    "recorder": 4, "evidence_window": 2, "mcp_0_4": 2, "mcp_proxy_user": 1, "hook_user": 2, "node_user": 2,
    "go_verifier": 2, "witnesser": 4,
    # Operators serve for --operator-serve-seconds each and run first; keep them rare so
    # a hundred thousand agents do not spend their first hour waiting on them.
    "operator": 1,
})
base.PERSONAS = PERSONAS  # run_agent dispatches through the module table


def assign_personas(n: int) -> list[str]:
    names = list(WEIGHTS)
    out = [random.Random(1000 + i).choices(names, weights=[WEIGHTS[k] for k in names])[0] for i in range(n)]
    out.sort(key=lambda p: 0 if p == "operator" else 1 if p != "auditor" else 2)
    return out


KEEP_CRASHED = 200
SHARED_CAP = 3000


def run_one(args):
    idx, persona, cfg = args
    r = base.run_agent((idx, persona, cfg))
    d = os.path.join(cfg["work"], f"a{idx:04d}-{persona}")
    try:
        if r["status"] == "ok" or idx % 50 != 0:
            shutil.rmtree(d, ignore_errors=True)
    except Exception:
        pass
    return r


def worker_process(batch, cfg, threads, out_path):
    with cf.ThreadPoolExecutor(max_workers=threads) as ex, gzip.open(out_path, "at") as f:
        n = 0
        for r in ex.map(run_one, [(i, p, dict(cfg)) for i, p in batch]):
            f.write(json.dumps(r) + "\n")
            n += 1
        return n


def trim_shared(shared: str):
    try:
        files = sorted(os.listdir(shared), key=lambda x: os.path.getmtime(os.path.join(shared, x)))
        for x in files[:-SHARED_CAP]:
            os.unlink(os.path.join(shared, x))
    except Exception:
        pass


def iter_results(out: str):
    for f in sorted(os.listdir(out)):
        if f.startswith("results-") and f.endswith(".jsonl.gz"):
            with gzip.open(os.path.join(out, f), "rt") as fh:
                for line in fh:
                    if line.strip():
                        yield json.loads(line)


def report(out: str, cfg: dict, elapsed: float):
    n = crashed = 0
    by_persona = collections.defaultdict(lambda: {"n": 0, "crashed": 0, "notes": 0})
    ops = collections.defaultdict(list)
    op_fail, op_total, sigs, statuses, verdicts = collections.Counter(), collections.Counter(), collections.Counter(), collections.Counter(), collections.Counter()
    examples, example_agents = {}, {}
    secs = []
    for r in iter_results(out):
        n += 1
        secs.append(r["secs"])
        crashed += r["status"] != "ok"
        b = by_persona[r["persona"]]
        b["n"] += 1
        b["crashed"] += r["status"] != "ok"
        b["notes"] += len(r["notes"])
        for o in r["ops"]:
            op_total[o["op"]] += 1
            if o["op"] == "witness.add-checkpoint":
                statuses[o.get("status")] += 1
            if o["ok"]:
                if o["ms"]:
                    ops[o["op"]].append(o["ms"])
            else:
                op_fail[o["op"]] += 1
                sig = f"{o['op']}: {base.signature(o.get('error', ''))}"
                sigs[sig] += 1
                examples.setdefault(sig, o.get("error", ""))
                example_agents.setdefault(sig, f"{r['persona']}#{r['idx']}")
        if r["error"]:
            sig = f"{r['persona']} crashed: {base.signature(r['error'])}"
            sigs[sig] += 1
            examples.setdefault(sig, r["error"])
            example_agents.setdefault(sig, f"{r['persona']}#{r['idx']}")
        for note in r["notes"]:
            sig = f"{r['persona']} note: {base.signature(note)}"
            sigs[sig] += 1
            examples.setdefault(sig, note)
            example_agents.setdefault(sig, f"{r['persona']}#{r['idx']}")
        for v in r["verdicts"]:
            verdicts[v] += 1
    total_ops = sum(op_total.values())
    lines = [f"# Outside swarm: {n:,} agents, {len(PERSONAS)} personas, {cfg['witness_count']} witnesses (0.4.0)", "",
             f"- target: `{cfg['cli']}` ({cfg['cli_version']}), witness_log {cfg['py_version']}, {cfg['host']}",
             f"- {n:,} agents in {elapsed:.0f} s ({n / max(elapsed, 1):.1f} agents/s), {cfg['processes']} x {cfg['threads']} in flight, {total_ops:,} operations, {sum(verdicts.values()):,} verdicts",
             f"- agents finished cleanly: {n - crashed:,}/{n:,}; operations failed: {sum(op_fail.values()):,}/{total_ops:,}",
             f"- witness add-checkpoint statuses: {dict(sorted(statuses.items(), key=lambda kv: -kv[1]))}",
             f"- verdicts: {dict(verdicts.most_common())}",
             f"- per-agent wall time: p50 {base.pct(secs, 50):.2f} s, p95 {base.pct(secs, 95):.2f} s, max {max(secs) if secs else 0:.1f} s", ""]
    lines += ["## Findings (clustered by signature, most frequent first)", ""]
    if not sigs:
        lines.append("None.")
    for sig, c in sigs.most_common(60):
        lines.append(f"- **{c:,}x** `{sig}`  \n  e.g. ({example_agents[sig]}) `{examples[sig][:240]}`")
    lines += ["", "## Per persona", "", "| persona | agents | crashed | notes |", "|---|---|---|---|"]
    for p, b in sorted(by_persona.items()):
        lines.append(f"| {p} | {b['n']:,} | {b['crashed']} | {b['notes']} |")
    lines += ["", "## Latency per operation (ms; successful calls)", "", "| op | n | p50 | p95 | p99 | max | failed |", "|---|---|---|---|---|---|---|"]
    for op, xs in sorted(ops.items(), key=lambda kv: -len(kv[1])):
        lines.append(f"| {op} | {len(xs):,} | {base.pct(xs, 50):.2f} | {base.pct(xs, 95):.2f} | {base.pct(xs, 99):.2f} | {max(xs):.1f} | {op_fail[op]} |")
    for op, c in op_fail.items():
        if op not in ops:
            lines.append(f"| {op} | 0 | - | - | - | - | {c} |")
    open(os.path.join(out, "REPORT.md"), "w").write("\n".join(lines) + "\n")
    print("\n".join(lines[:14]))
    print(f"\nreport: {os.path.join(out, 'REPORT.md')}")
    return crashed, sum(op_fail.values())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--agents", type=int, default=100000)
    ap.add_argument("--directory", required=True)
    ap.add_argument("--cli", default=os.environ.get("WL_BIN", os.path.join(REPO, "target", "release", "witness-log")))
    ap.add_argument("--out", default=None)
    ap.add_argument("--processes", type=int, default=2)
    ap.add_argument("--threads", type=int, default=24)
    ap.add_argument("--batch", type=int, default=500)
    ap.add_argument("--operator-serve-seconds", type=int, default=20)
    ap.add_argument("--agent-witness-base-port", type=int, default=21000)
    ap.add_argument("--only", help="comma-separated personas")
    ap.add_argument("--report-only", action="store_true", help="rebuild REPORT.md from the JSONL files in --out")
    args = ap.parse_args()
    import witness_log as wl
    out = args.out or tempfile.mkdtemp(prefix="outside04-")
    os.makedirs(out, exist_ok=True)
    directory = json.load(open(args.directory))
    ver = subprocess.run([args.cli, "--version"], capture_output=True, text=True).stdout.strip()
    cfg = {"work": os.path.join(out, "work"), "shared": os.path.join(out, "shared-dossiers"), "agent_dir": os.path.join(out, "agent-witnesses"),
           "directory": directory, "cli": args.cli, "cli_version": ver, "py_version": getattr(wl, "__version__", "?"), "run_id": int(time.time()),
           "witness_count": len(directory["witnesses"]), "processes": args.processes, "threads": args.threads,
           "operator_serve_seconds": args.operator_serve_seconds, "agent_witness_base_port": args.agent_witness_base_port,
           "host": f"{os.cpu_count()} cpu, {os.uname().sysname} {os.uname().machine}"}
    for d in (cfg["work"], cfg["shared"], cfg["agent_dir"]):
        os.makedirs(d, exist_ok=True)
    if args.report_only:
        meta = json.load(open(os.path.join(out, "run.json")))
        report(out, meta["cfg"], meta["elapsed"])
        return 0
    personas = assign_personas(args.agents)
    if args.only:
        keep = set(args.only.split(","))
        personas = [p for p in personas if p in keep]
    jobs = list(enumerate(personas))
    print(f"{len(jobs):,} agents, {len(set(personas))} personas, {cfg['witness_count']} witnesses; target {ver}, witness_log {cfg['py_version']}")
    print(f"out: {out}", flush=True)
    batches = [jobs[i:i + args.batch] for i in range(0, len(jobs), args.batch)]
    t0 = time.time()
    done = agents = 0
    ctx = mp.get_context("spawn")
    with cf.ProcessPoolExecutor(max_workers=args.processes, mp_context=ctx) as ex:
        pending = set()
        it = iter(enumerate(batches))
        for bi, b in it:
            pending.add(ex.submit(worker_process, b, cfg, args.threads, os.path.join(out, f"results-{bi:05d}.jsonl.gz")))
            if len(pending) >= args.processes:
                break
        while pending:
            finished, pending = cf.wait(pending, return_when=cf.FIRST_COMPLETED)
            for f in finished:
                done += 1
                agents += f.result()
            trim_shared(cfg["shared"])
            el = time.time() - t0
            print(f"  batch {done}/{len(batches)} done, {agents:,} agents, {el:.0f}s, {agents / max(el, 1):.1f}/s, eta {((len(jobs) - agents) / max(agents / max(el, 1), 1e-9)) / 60:.0f} min", flush=True)
            json.dump({"cfg": {k: v for k, v in cfg.items() if k != "directory"}, "elapsed": el, "agents": agents}, open(os.path.join(out, "run.json"), "w"))
            for bi, b in it:
                pending.add(ex.submit(worker_process, b, cfg, args.threads, os.path.join(out, f"results-{bi:05d}.jsonl.gz")))
                break
    elapsed = time.time() - t0
    json.dump({"cfg": {k: v for k, v in cfg.items() if k != "directory"}, "elapsed": elapsed, "agents": agents}, open(os.path.join(out, "run.json"), "w"))
    crashed, failed_ops = report(out, cfg, elapsed)
    print(f"agents crashed: {crashed}; operations failed: {failed_ops}")
    return min(99, crashed + (1 if failed_ops else 0))


if __name__ == "__main__":
    sys.exit(main())
