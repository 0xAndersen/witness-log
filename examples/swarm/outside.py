#!/usr/bin/env python3
"""A thousand agents, from the outside, all at once.

Every agent is a separate identity with its own journal, running one of
sixteen personas (a coder, a trader, a support bot redacting PII, a
crash-and-restart loop, an auditor checking someone else's dossier, an
adversary trying to fork, an operator standing up its own witness, ...)
against a live witness network, using only what a developer installs:
the `witness_log` wheel and the `witness-log` binary.

Every operation an agent performs is timed and recorded; every exception
is kept with its message. The report clusters failures by signature, so
the common problems surface first, and gives latency percentiles per
operation and the verdict distribution.

    python deploy/witness/fleet.py init /tmp/fleet --count 100 --org "Example Org" ...
    python deploy/witness/fleet.py serve /tmp/fleet --open-enrollment &
    python examples/swarm/outside.py --agents 1000 --directory /tmp/fleet/directory.json --out /tmp/outside

Processes x threads give the in-flight concurrency (default 8 x 16 = 128
agents at any moment); the witnesses see all of them.
"""
from __future__ import annotations

import argparse
import base64
import collections
import concurrent.futures as cf
import hashlib
import json
import multiprocessing as mp
import os
import random
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))

# ------------------------------------------------------------ framework


class Agent:
    """One agent: identity, workspace, operation log."""

    def __init__(self, idx: int, persona: str, cfg: dict):
        self.idx, self.persona, self.cfg = idx, persona, cfg
        self.dir = os.path.join(cfg["work"], f"a{idx:04d}-{persona}")
        os.makedirs(self.dir, exist_ok=True)
        self.journal = os.path.join(self.dir, "agent.jsonl")
        self.seed = hashlib.sha256(f"swarm-seed-{cfg['run_id']}-{idx}".encode()).digest()
        self.ops: list[dict] = []
        self.notes: list[str] = []
        self.verdicts: list[str] = []
        self.rng = random.Random(idx)

    def op(self, name: str, fn, *a, **kw):
        t = time.perf_counter()
        try:
            out = fn(*a, **kw)
            self.ops.append({"op": name, "ms": (time.perf_counter() - t) * 1000, "ok": True})
            return out
        except Exception as e:  # noqa: BLE001
            self.ops.append({"op": name, "ms": (time.perf_counter() - t) * 1000, "ok": False,
                             "error": f"{type(e).__name__}: {e}"[:400]})
            raise

    def directory(self) -> dict:
        return self.cfg["directory"]

    def pick_witnesses(self, log, want: int) -> list[dict]:
        """A diverse subset of the network for this log, plus any witnesses
        other agents in the swarm are running right now."""
        import witness_log as wl
        picked = json.loads(wl.select_witnesses(json.dumps(self.directory()), log.identity_pubkey_hex(), want, False))
        return picked + self.cfg.get("agent_witnesses", [])


RETRY_AFTER = {}  # thread-local-ish scratch: last Retry-After seen per URL


def http(method, url, body=None, timeout=15):
    req = urllib.request.Request(url, data=body.encode() if isinstance(body, str) else body, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(), r.headers.get("Content-Type") or ""
    except urllib.error.HTTPError as e:
        try:
            RETRY_AFTER[url] = int(e.headers.get("Retry-After") or 0)
        except ValueError:
            RETRY_AFTER[url] = 0
        return e.code, e.read().decode(), e.headers.get("Content-Type") or ""
    except Exception as e:  # noqa: BLE001
        return 0, f"{type(e).__name__}: {e}", ""


def submit_py(agent: Agent, log, witnesses: list[dict], old: dict | None = None):
    """Pure-Python submission to a list of witness entries; records per-witness status."""
    old = old or {}
    responses, statuses = [], collections.Counter()
    for w in witnesses:
        o = old.get(w["pubkey"], 0)
        st, body, ct = 0, "", ""
        t0 = time.perf_counter()
        for attempt in range(6):
            st, body, ct = http("POST", w["url"].rstrip("/") + "/add-checkpoint", log.add_checkpoint_body(o))
            if st == 409:
                try:
                    o = int(body.strip())
                except ValueError:
                    agent.notes.append(f"409 without a size from {w['name']}: {body[:60]!r}")
                    break
                continue
            if st in (429, 503):
                wait = RETRY_AFTER.get(w["url"].rstrip("/") + "/add-checkpoint", 0)
                time.sleep(min(wait, 60) if wait else 0.5 * (attempt + 1))
                continue
            if st == 0:
                time.sleep(0.2 * (attempt + 1))
                continue
            break
        statuses[st] += 1
        agent.ops.append({"op": "witness.add-checkpoint", "ms": (time.perf_counter() - t0) * 1000, "ok": st == 200, "status": st,
                          **({} if st == 200 else {"error": f"HTTP {st}: {body[:120]}"})})
        if st == 200:
            responses.append((w["pubkey"], body))
            old[w["pubkey"]] = log.tree_size()
    return responses, statuses, old


MIN_WITNESSES = 3  # the verifier's absolute gate against a registry-sized directory


def verify_py(agent: Agent, dossier_json: str, ident: str, directory: dict | None, threshold=0.66) -> dict:
    import witness_log as wl
    rep = json.loads(agent.op("verify_dossier_json", wl.verify_dossier_json, dossier_json, threshold, ident,
                              json.dumps(directory) if directory else None,
                              MIN_WITNESSES if directory else None))
    agent.verdicts.append(rep["verdict"])
    return rep


def cli(agent: Agent, *args, timeout=120):
    r = subprocess.run([agent.cfg["cli"], *args], capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


# -------------------------------------------------------------- personas

def p_coder(a: Agent):
    """An agent writing code: 30 decorated tool calls, export, verify, witness."""
    import witness_log as wl
    log = a.op("open", wl.open, a.journal, a.seed)

    @wl.step(log)
    def edit_file(path, lines):
        return {"path": path, "written": lines}

    @wl.step(log)
    def run_tests(suite):
        if suite == "flaky" and a.rng.random() < 0.3:
            raise RuntimeError("2 tests failed")
        return {"suite": suite, "passed": a.rng.randint(10, 90)}

    for i in range(15):
        a.op("step.edit_file", edit_file, f"src/mod{i}.rs", a.rng.randint(1, 400))
        try:
            run_tests(a.rng.choice(["unit", "integration", "flaky"]))  # a failing tool call is the point
        except RuntimeError:
            pass
    a.op("sync", log.sync)
    ident = log.identity_pubkey_hex()
    dossier = a.op("to_dossier_json", log.to_dossier_json)
    verify_py(a, dossier, ident, None)
    responses, statuses, _ = submit_py(a, log, a.pick_witnesses(log, 8))
    dossier, n = a.op("dossier_from_responses", log.dossier_from_responses, responses)
    rep = verify_py(a, dossier, ident, a.directory())
    open(os.path.join(a.dir, "dossier.json"), "w").write(dossier)
    log.close()
    if rep["verdict"] != "witnessed":
        a.notes.append(f"expected witnessed, got {rep['verdict']} with {n} receipts {dict(statuses)}")


def p_researcher(a: Agent):
    """Long payloads: 40 KB notes, memory leaves, checkpoint every 10."""
    import witness_log as wl
    log = a.op("open", wl.open, a.journal, a.seed)
    for i in range(40):
        a.op("append_memory.40k", log.append_memory, (f"note {i}: " + "lorem ipsum " * 3500).encode())
        if i % 10 == 9:
            a.op("checkpoint", log.checkpoint)
    a.op("sync", log.sync)
    ident = log.identity_pubkey_hex()
    responses, statuses, _ = submit_py(a, log, a.pick_witnesses(log, 5))
    dossier, _ = a.op("dossier_from_responses", log.dossier_from_responses, responses)
    verify_py(a, dossier, ident, a.directory())
    log.close()


def p_trader(a: Agent):
    """High frequency: 600 appends, sync every 50, random inclusion proofs checked."""
    import witness_log as wl
    log = a.op("open", wl.open, a.journal, a.seed)
    for i in range(300):
        a.op("append_intent", log.append_intent, json.dumps({"order": i, "qty": a.rng.randint(1, 500)}).encode())
        a.op("append_result", log.append_result, json.dumps({"order": i, "fill": "ok"}).encode())
        if i % 50 == 49:
            a.op("sync", log.sync)
    for _ in range(10):
        idx = a.rng.randrange(600)
        size, root, path = a.op("inclusion_proof", log.inclusion_proof, idx)
        ok = a.op("verify_inclusion", wl.verify_inclusion, log.leaf_hash_hex(idx), idx, size, path, root)
        if not ok:
            a.notes.append(f"inclusion proof for leaf {idx} failed to verify")
    ident = log.identity_pubkey_hex()
    responses, statuses, _ = submit_py(a, log, a.pick_witnesses(log, 6))
    dossier, _ = a.op("dossier_from_responses", log.dossier_from_responses, responses)
    verify_py(a, dossier, ident, a.directory())
    log.close()


def p_support(a: Agent):
    """PII logged, then erased; verify still consistent; redaction after a restart too."""
    import witness_log as wl
    log = a.op("open", wl.open, a.journal, a.seed)
    pii = [a.op("append_memory", log.append_memory, f"customer{i}@example.com".encode()) for i in range(5)]
    a.op("append_intent", log.append_intent, b"refund approved")
    a.op("sync", log.sync)
    for i in pii[:3]:
        if not a.op("forget", log.forget, i):
            a.notes.append(f"forget({i}) returned False on a live leaf")
    log.close()
    log, dropped = a.op("resume", wl.JournaledLog.resume, a.journal)
    if dropped:
        a.notes.append(f"resume dropped {dropped} lines after a clean close")
    if not a.op("can_forget", log.can_forget, pii[3]):
        a.notes.append("salt for a pre-restart leaf is gone")
    if not a.op("forget.after_restart", log.forget, pii[3]):
        a.notes.append("forget after restart returned False")
    ident = log.identity_pubkey_hex()
    dossier = a.op("to_dossier_json", log.to_dossier_json)
    rep = verify_py(a, dossier, ident, None)
    if not rep["internally_consistent"]:
        a.notes.append("dossier inconsistent after redactions")
    salts = open(a.journal + ".salts").read().splitlines()
    if len(salts) != 2:
        a.notes.append(f"salt sidecar holds {len(salts)} records, expected 2")
    log.close()


def p_pipeline(a: Agent):
    """Two-stage pipeline: this agent hands state to a second identity it also runs."""
    import witness_log as wl
    log_a = a.op("open", wl.open, a.journal, a.seed)
    log_b = a.op("open.b", wl.open, os.path.join(a.dir, "stage2.jsonl"))
    state = json.dumps({"batch": a.idx, "rows": a.rng.randint(100, 9000)}).encode()
    a.op("append_handoff_sent", log_a.append_handoff_sent, state, log_b.identity_pubkey_hex())
    a.op("append_handoff_received", log_b.append_handoff_received, state, log_a.identity_pubkey_hex())
    da = json.loads(log_a.to_dossier_json())
    db = json.loads(log_b.to_dossier_json())
    ha = da["leaves"][-1]["handoff_state_hash"]
    hb = db["leaves"][-1]["handoff_state_hash"]
    if ha != hb or ha != hashlib.sha256(state).hexdigest():
        a.notes.append("handoff state hashes disagree")
    a.op("sync", log_a.sync)
    a.op("sync", log_b.sync)
    for log in (log_a, log_b):
        responses, _, _ = submit_py(a, log, a.pick_witnesses(log, 4))
        dossier, _ = a.op("dossier_from_responses", log.dossier_from_responses, responses)
        verify_py(a, dossier, log.identity_pubkey_hex(), a.directory())
    log_a.close()
    log_b.close()


def p_mcp_user(a: Agent):
    """Drives the MCP server over stdio with the official client."""
    import anyio
    from mcp.client.client import Client
    from mcp.client.stdio import StdioServerParameters
    server = os.path.join(REPO, "integrations", "mcp", "witness_mcp_server.py")
    params = StdioServerParameters(command=sys.executable, args=[server], env={**os.environ, "WITNESS_LOG_HOME": os.path.join(a.dir, "mcp-home")})

    def data(r):
        sc = getattr(r, "structured_content", None)
        if sc:
            return sc.get("result", sc)
        return json.loads("".join(getattr(c, "text", "") for c in r.content))

    async def go():
        async with Client(params) as c:
            sid = f"agent-{a.idx}"
            init = data(await c.call_tool("initialize_witness_chain", {"session_id": sid, "metadata": {"persona": "mcp"}}))
            for i in range(5):
                r = data(await c.call_tool("append_audit_step", {"session_id": sid, "intent": f"step {i}", "tool_name": "search",
                                                                "payload": {"q": i}, "state_transition": {"hits": i * 3}}))
                if r["checkpoint"]["tree_size"] != 1 + 2 * (i + 1) or r["result_index"] != r["intent_index"] + 1:
                    a.notes.append(f"MCP indices off: {r['intent_index']}/{r['result_index']} size {r['checkpoint']['tree_size']}")
            red = data(await c.call_tool("redact_audit_entry", {"session_id": sid, "entry_index": 1}))
            if not red["erased"]:
                a.notes.append("MCP redaction did not erase")
            v = data(await c.call_tool("verify_chain_integrity", {"session_id": sid}))
            if v["tamper_alerts"]:
                a.notes.append(f"MCP tamper alerts: {v['tamper_alerts']}")
            sub = data(await c.call_tool("submit_to_witnesses", {"session_id": sid, "directory": a.directory(), "max_witnesses": 6, "min_witnesses": MIN_WITNESSES}))
            a.verdicts.append(sub["verdict"])
            return init["identity_pubkey"]

    a.op("mcp.session", lambda: anyio.run(go))


def p_cli_only(a: Agent):
    """Uses the binary for everything it can: submit, verify, diff, explain."""
    import witness_log as wl
    log = a.op("open", wl.open, a.journal, a.seed)
    for i in range(12):
        log.append_intent(f"cli agent op {i}".encode())
    log.sync()
    ident = log.identity_pubkey_hex()
    sub = {"witnesses": a.pick_witnesses(log, 6)}
    log.close()
    dpath = os.path.join(a.dir, "directory.json")
    json.dump(sub, open(dpath, "w"))
    out = os.path.join(a.dir, "dossier.json")
    code, so, se = a.op("cli.submit", cli, a, "witness", "submit", a.journal, "--directory", dpath, "--out", out)
    if code != 0:
        a.notes.append(f"cli submit exit {code}: {se.strip()[-200:]}")
        return
    code, so, se = a.op("cli.verify", cli, a, "verify", out, "--identity", ident, "--directory", dpath, "--json", "--min-witnesses", str(MIN_WITNESSES))
    rep = json.loads(so)
    a.verdicts.append(rep["verdict"].lower().replace("-", "_"))
    if code != 0:
        a.notes.append(f"cli verify exit {code}: {rep['verdict']}")
    code, so, se = a.op("cli.diff", cli, a, "diff", out, out)
    if code != 0:
        a.notes.append(f"diff of identical copies exit {code}")
    code, so, se = a.op("cli.explain", cli, a, "explain", rep["verdict"].lower(), "--json")
    if code != 0:
        a.notes.append(f"explain {rep['verdict']} exit {code}")


def p_crash_restart(a: Agent):
    """Supervisor pattern: child process dies mid-session, parent resumes."""
    import witness_log as wl
    log = a.op("open", wl.open, a.journal, a.seed)
    log.append_intent(b"session 0")
    log.sync()
    log.close()
    code = (
        "import witness_log, os, sys\n"
        f"log = witness_log.JournaledLog.resume({a.journal!r})[0]\n"
        "for i in range(20): log.append_intent(b'crashy %d' % i)\n"
        "log.sync(); os._exit(137)\n"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    if r.returncode != 137:
        a.notes.append(f"child exited {r.returncode}: {r.stderr[-200:]}")
    t = time.perf_counter()
    try:
        log, dropped = wl.JournaledLog.resume(a.journal)
        a.ops.append({"op": "resume.after_crash", "ms": (time.perf_counter() - t) * 1000, "ok": True})
    except Exception as e:  # noqa: BLE001
        a.ops.append({"op": "resume.after_crash", "ms": (time.perf_counter() - t) * 1000, "ok": False, "error": str(e)[:300]})
        raise
    if log.tree_size() != 21:
        a.notes.append(f"tree size {log.tree_size()} after crash, expected 21")
    bindings = json.loads(log.to_dossier_json())["key_bindings"]
    if len(bindings) != 3:
        a.notes.append(f"{len(bindings)} bindings after 3 sessions")
    ident = log.identity_pubkey_hex()
    responses, _, _ = submit_py(a, log, a.pick_witnesses(log, 4))
    dossier, _ = log.dossier_from_responses(responses)
    verify_py(a, dossier, ident, a.directory())
    log.close()


def p_auditor(a: Agent):
    """Verifies a stranger's dossier offline, then a tampered copy, with the binary."""
    shared = a.cfg["shared"]
    cands = [f for f in os.listdir(shared) if f.endswith(".json")] if os.path.isdir(shared) else []
    if not cands:
        a.notes.append("no dossiers to audit yet")
        time.sleep(1)
        cands = [f for f in os.listdir(shared) if f.endswith(".json")] if os.path.isdir(shared) else []
        if not cands:
            return
    pick = os.path.join(shared, a.rng.choice(cands))
    d = json.load(open(pick))
    dpath = os.path.join(a.dir, "directory.json")
    json.dump(a.directory(), open(dpath, "w"))
    code, so, se = a.op("cli.verify.other", cli, a, "verify", pick, "--identity", d["identity_pubkey"], "--directory", dpath, "--json", "--min-witnesses", str(MIN_WITNESSES))
    try:
        rep = json.loads(so)
    except Exception:
        a.notes.append(f"verify produced no JSON: {se[-200:]}")
        return
    a.verdicts.append(rep["verdict"].lower().replace("-", "_"))
    # Against the whole registry a handful of cosigners is not a strict
    # majority: WITNESSED exits 11 by default since 0.5.0 (RFC-0002).
    if code not in (0, 10, 11):
        a.notes.append(f"stranger's dossier verified {rep['verdict']} (exit {code})")
    if code == 11 and not rep["report"].get("split_view_unsafe"):
        a.notes.append("exit 11 without split_view_unsafe in the report")
    d["leaves"][a.rng.randrange(len(d["leaves"]))]["payload_hash"] = "ab" * 32
    tp = os.path.join(a.dir, "tampered.json")
    json.dump(d, open(tp, "w"))
    code2, so2, _ = a.op("cli.verify.tampered", cli, a, "verify", tp, "--identity", d["identity_pubkey"], "--directory", dpath, "--json", "--min-witnesses", str(MIN_WITNESSES))
    if code2 != 40:
        a.notes.append(f"tampered dossier exit {code2}, expected 40 (INVALID)")
    code3, so3, _ = a.op("cli.diff", cli, a, "diff", pick, tp)
    if code3 != 40:
        a.notes.append(f"diff of tampered copy exit {code3}, expected 40")
    # A head the verifier holds that the dossier does not reproduce: DIVERGED.
    size = len(d["leaves"])
    code4, so4, _ = a.op("cli.verify.known_head", cli, a, "verify", pick, "--identity", d["identity_pubkey"], "--known-head", f"{max(size - 1, 1)}:{'cd' * 32}", "--json")
    if code4 != 30:
        a.notes.append(f"contradicted --known-head exit {code4}, expected 30")


def p_adversary(a: Agent):
    """Tries to get a fork cosigned, then junk, then an impersonation."""
    import witness_log as wl
    honest = a.op("open", wl.open, a.journal, a.seed)
    for i in range(6):
        honest.append_intent(f"honest {i}".encode())
    honest.sync()
    ws = a.pick_witnesses(honest, 5)
    responses, statuses, _ = submit_py(a, honest, ws)
    honest.close()
    forked = wl.JournaledLog.create(os.path.join(a.dir, "fork.jsonl"), a.seed)
    for i in range(6):
        forked.append_intent(f"forged {i}".encode())
    got = collections.Counter()
    for w in ws:
        st, body, _ = http("POST", w["url"] + "/add-checkpoint", forked.add_checkpoint_body(0))
        if st == 409:
            st, body, _ = http("POST", w["url"] + "/add-checkpoint", forked.add_checkpoint_body(int(body.strip())))
        got[st] += 1
    a.ops.append({"op": "fork.attempt", "ms": 0, "ok": 200 not in got, **({} if 200 not in got else {"error": "a fork was cosigned"})})
    if got[422] != len(ws):
        a.notes.append(f"fork statuses {dict(got)}")
    forked.close()
    for w in ws[:2]:
        st, _, _ = http("POST", w["url"] + "/add-checkpoint", os.urandom(40).hex())
        if st != 400:
            a.notes.append(f"junk body got {st}")
        st, _, _ = http("POST", w["url"] + "/add-checkpoint", "a" * 70000)
        if st != 413:
            a.notes.append(f"70 KiB body got {st}")


def p_operator(a: Agent):
    """This agent runs a witness of its own and offers it to the swarm."""
    import witness_log as wl
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    port = a.cfg["agent_witness_base_port"] + a.idx % 1000
    sp = os.path.join(a.dir, "state.json")
    wl.WitnessService.create_state(sp)
    svc = wl.WitnessService.new(f"agent{a.idx}.witness.test/w", a.seed, sp, True)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *x):
            pass

        def do_GET(self):
            b = json.dumps({"pubkey_hex": svc.pubkey_hex(), "directory_entry": entry}).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode(errors="replace")
            st, ct, out = svc.handle_add_checkpoint_http(body)
            b = out.encode()
            self.send_response(st); self.send_header("Content-Type", ct); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    entry = json.loads(wl.witness_entry_independent(f"agent{a.idx}.witness.test/w", f"Agent Collective {a.idx % 7}",
                                                    f"http://127.0.0.1:{port}", svc.pubkey_hex(), "agent-host"))
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    srv.request_queue_size = 128
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    deadline = time.time() + a.cfg["operator_serve_seconds"]
    with open(os.path.join(a.cfg["agent_dir"], f"{a.idx}.json"), "w") as f:
        json.dump({"entry": entry, "until": deadline - 20}, f)
    # Serve for a while so other agents can use it, then cosign our own log.
    log = a.op("open", wl.open, a.journal, a.seed)
    log.append_intent(b"operator online")
    log.sync()
    while time.time() < deadline:
        time.sleep(0.5)
    responses, _, _ = submit_py(a, log, a.pick_witnesses(log, 4) + [entry])
    dossier, n = log.dossier_from_responses(responses)
    rep = verify_py(a, dossier, log.identity_pubkey_hex(), {"witnesses": a.directory()["witnesses"] + [entry]})
    a.ops.append({"op": "operator.logs_served", "ms": float(svc.log_count()), "ok": True})
    log.close()
    srv.shutdown()


def p_snapshot(a: Agent):
    """In-memory WitnessLog with snapshot persistence, no journal."""
    import witness_log as wl
    log = a.op("generate", wl.WitnessLog.generate)
    for i in range(50):
        log.append_intent(f"snap {i}".encode())
    p = os.path.join(a.dir, "snap.json")
    a.op("save_snapshot", log.save_snapshot, p)
    back = a.op("load_snapshot", wl.WitnessLog.load_snapshot, p)
    if back.root_hex() != log.root_hex():
        a.notes.append("snapshot root mismatch")
    cp = a.op("checkpoint", back.checkpoint)
    a.op("verify_continuity", back.verify_continuity, cp)
    verify_py(a, back.to_dossier_json(), back.identity_pubkey_hex(), None)


def p_multisession(a: Agent):
    """Five open/close cycles; bindings must accumulate and verify."""
    import witness_log as wl
    for s in range(5):
        log = a.op("open", wl.open, a.journal, a.seed)
        for i in range(10):
            log.append_result(f"s{s}-{i}".encode())
        a.op("sync", log.sync)
        if s == 4:
            ident = log.identity_pubkey_hex()
            d = json.loads(log.to_dossier_json())
            if len(d["key_bindings"]) != 5:
                a.notes.append(f"{len(d['key_bindings'])} bindings after 5 sessions")
            responses, _, _ = submit_py(a, log, a.pick_witnesses(log, 5))
            dossier, _ = log.dossier_from_responses(responses)
            verify_py(a, dossier, ident, a.directory())
        log.close()


def p_big_payload(a: Agent):
    """2 MiB payloads and a 300-leaf burst without sync, then sync once."""
    import witness_log as wl
    log = a.op("open", wl.open, a.journal, a.seed)
    for _ in range(3):
        a.op("append_result.2MiB", log.append_result, os.urandom(2 * 1024 * 1024))
    for i in range(300):
        log.append_intent(b"burst %d" % i)
    a.op("sync.after_burst", log.sync)
    responses, _, _ = submit_py(a, log, a.pick_witnesses(log, 3))
    dossier, _ = log.dossier_from_responses(responses)
    verify_py(a, dossier, log.identity_pubkey_hex(), a.directory())
    log.close()


def p_c2sp_user(a: Agent):
    """Wants a C2SP signed note it can hand to a CT-ecosystem witness."""
    import witness_log as wl
    log = a.op("open", wl.open, a.journal, a.seed)
    for i in range(4):
        log.append_intent(f"c2sp {i}".encode())
    log.sync()
    ident = log.identity_pubkey_hex()
    origin = log.canonical_origin()
    note = a.op("sign_c2sp_checkpoint", log.sign_c2sp_checkpoint, origin)
    vkey = log.c2sp_vkey(origin)
    dossier = log.to_dossier_json()
    log.close()
    np_ = os.path.join(a.dir, "note.txt")
    open(np_, "w").write(note)
    code, so, se = a.op("cli.c2sp.verify", cli, a, "c2sp", "verify", np_, "--vkey", vkey)
    if code != 0:
        a.notes.append(f"c2sp verify exit {code}: {se[-200:]}")
    dp = os.path.join(a.dir, "d.json")
    open(dp, "w").write(dossier)
    code, raw, se = a.op("cli.c2sp.show", cli, a, "c2sp", "show", dp, "--origin", origin, "--raw", "--sign-with", a.journal)
    if code != 0 or not raw.startswith(origin):
        a.notes.append(f"c2sp show --raw --sign-with exit {code}")


def p_schema(a: Agent):
    """Validates its own dossier against the published JSON Schema."""
    import witness_log as wl
    try:
        import jsonschema
    except ImportError:
        a.notes.append("jsonschema not installed; skipped")
        return
    log = a.op("open", wl.open, a.journal, a.seed)
    log.append_intent(b"schema")
    log.append_memory(b"pii")
    log.forget(1)
    log.append_handoff_sent(b"state", "ab" * 32)
    dossier = json.loads(log.to_dossier_json())
    log.close()
    schema = json.load(open(os.path.join(REPO, "spec", "dossier.schema.json")))
    a.op("jsonschema.validate", jsonschema.Draft202012Validator(schema).validate, dossier)


def p_verifier_only(a: Agent):
    """Never logs anything: just verifies the sample dossier and the swarm's shared ones with the library."""
    import witness_log as wl
    sample = open(os.path.join(REPO, "examples", "sample-dossier.json")).read()
    trusted = json.load(open(os.path.join(REPO, "examples", "trusted-directory.json")))
    ident = json.loads(sample)["identity_pubkey"]
    rep = verify_py(a, sample, ident, trusted)
    if rep["verdict"] != "witnessed":
        a.notes.append(f"sample dossier {rep['verdict']}")
    rep2 = verify_py(a, sample, ident, None)
    if rep2["verdict"] != "unanchored":
        a.notes.append(f"sample without directory {rep2['verdict']}")
    with_bad = json.loads(sample)
    with_bad["checkpoint"]["timestamp_ms"] += 1
    rep3 = verify_py(a, json.dumps(with_bad), ident, trusted)
    if rep3["verdict"] != "invalid":
        a.notes.append(f"edited checkpoint is {rep3['verdict']}, not invalid")


def p_rollback_victim(a: Agent):
    """Restores a journal from an old backup by mistake; submit must stop it."""
    import witness_log as wl
    log = a.op("open", wl.open, a.journal, a.seed)
    for i in range(5):
        log.append_intent(b"before backup %d" % i)
    log.sync()
    log.close()
    for f in (a.journal, a.journal + ".salts"):
        shutil.copy(f, f + ".bak")
    log = wl.JournaledLog.resume(a.journal)[0]
    log.append_intent(b"after backup")
    log.sync()
    dpath = os.path.join(a.dir, "directory.json")
    json.dump({"witnesses": a.pick_witnesses(log, 4)}, open(dpath, "w"))
    log.close()
    code, _, se = a.op("cli.submit", cli, a, "witness", "submit", a.journal, "--directory", dpath, "--out", os.path.join(a.dir, "d1.json"))
    if code != 0:
        a.notes.append(f"first submit failed: {se[-200:]}")
        return
    for f in (a.journal, a.journal + ".salts"):
        shutil.copy(f + ".bak", f)
    log = wl.JournaledLog.resume(a.journal)[0]
    log.append_intent(b"divergent after restore")
    log.sync()
    log.close()
    code2, _, se2 = a.op("cli.submit.after_rollback", cli, a, "witness", "submit", a.journal, "--directory", dpath, "--out", os.path.join(a.dir, "d2.json"))
    if code2 == 0:
        a.notes.append("submit published a rolled-back history")
    a.ops[-1]["ok"] = code2 != 0


PERSONAS = {
    "coder": p_coder, "researcher": p_researcher, "trader": p_trader, "support": p_support,
    "pipeline": p_pipeline, "mcp_user": p_mcp_user, "cli_only": p_cli_only, "crash_restart": p_crash_restart,
    "auditor": p_auditor, "adversary": p_adversary, "operator": p_operator, "snapshot": p_snapshot,
    "multisession": p_multisession, "big_payload": p_big_payload, "c2sp_user": p_c2sp_user,
    "schema": p_schema, "verifier_only": p_verifier_only, "rollback_victim": p_rollback_victim,
}
# Weights: most agents are ordinary workloads; the rare ones are rare.
WEIGHTS = {"coder": 20, "researcher": 8, "trader": 8, "support": 10, "pipeline": 6, "mcp_user": 2, "cli_only": 8,
           "crash_restart": 6, "auditor": 6, "adversary": 4, "operator": 2, "snapshot": 4, "multisession": 5,
           "big_payload": 3, "c2sp_user": 3, "schema": 2, "verifier_only": 2, "rollback_victim": 1}


def assign_personas(n: int) -> list[str]:
    names = list(WEIGHTS)
    total = sum(WEIGHTS.values())
    out = []
    for i in range(n):
        out.append(random.Random(1000 + i).choices(names, weights=[WEIGHTS[k] for k in names])[0])
    # Operators go first so their witnesses exist for everyone else.
    out.sort(key=lambda p: 0 if p == "operator" else 1 if p != "auditor" else 2)
    return out


def run_agent(args) -> dict:
    idx, persona, cfg = args
    a = Agent(idx, persona, cfg)
    t = time.perf_counter()
    # Agent witnesses announced so far become part of everyone's directory.
    cfg["agent_witnesses"] = []
    try:
        for f in os.listdir(cfg["agent_dir"]):
            if f.endswith(".json"):
                rec = json.load(open(os.path.join(cfg["agent_dir"], f)))
                if rec["until"] > time.time() + 60:  # still serving for the whole of this agent's run
                    cfg["agent_witnesses"].append(rec["entry"])
    except Exception:
        pass
    status, err = "ok", None
    try:
        PERSONAS[persona](a)
    except Exception as e:  # noqa: BLE001
        status, err = "crashed", f"{type(e).__name__}: {e}"[:400] + " @ " + traceback.format_exc().strip().splitlines()[-3].strip()[:200]
    # Share dossiers for auditors.
    dp = os.path.join(a.dir, "dossier.json")
    if os.path.exists(dp):
        try:
            shutil.copy(dp, os.path.join(cfg["shared"], f"{idx}.json"))
        except Exception:
            pass
    return {"idx": idx, "persona": persona, "status": status, "error": err, "secs": round(time.perf_counter() - t, 2),
            "ops": a.ops, "notes": a.notes, "verdicts": a.verdicts}


def worker_process(batch, cfg, threads):
    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        return list(ex.map(run_agent, [(i, p, dict(cfg)) for i, p in batch]))


# --------------------------------------------------------------- report

def signature(msg: str) -> str:
    s = re.sub(r"0x[0-9a-f]+|\b[0-9a-f]{16,}\b", "<hex>", msg)
    s = re.sub(r"/[^\s:'\"]+", "<path>", s)
    s = re.sub(r"\d+", "<n>", s)
    return s[:160]


def pct(xs, p):
    if not xs:
        return 0.0
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round((p / 100) * (len(xs) - 1))))]


def report(results: list[dict], cfg: dict, out: str, elapsed: float):
    n = len(results)
    crashed = [r for r in results if r["status"] != "ok"]
    by_persona = collections.defaultdict(lambda: {"n": 0, "crashed": 0, "notes": 0})
    for r in results:
        b = by_persona[r["persona"]]
        b["n"] += 1
        b["crashed"] += r["status"] != "ok"
        b["notes"] += len(r["notes"])
    ops = collections.defaultdict(list)
    op_fail = collections.Counter()
    op_total = collections.Counter()
    sigs = collections.Counter()
    examples = {}
    statuses = collections.Counter()
    for r in results:
        for o in r["ops"]:
            op_total[o["op"]] += 1
            if o["op"] == "witness.add-checkpoint":
                statuses[o.get("status")] += 1
            if o["ok"]:
                if o["ms"]:
                    ops[o["op"]].append(o["ms"])
            else:
                op_fail[o["op"]] += 1
                sig = f"{o['op']}: {signature(o.get('error', ''))}"
                sigs[sig] += 1
                examples.setdefault(sig, o.get("error", ""))
        if r["error"]:
            sig = f"{r['persona']} crashed: {signature(r['error'])}"
            sigs[sig] += 1
            examples.setdefault(sig, r["error"])
        for note in r["notes"]:
            sig = f"{r['persona']} note: {signature(note)}"
            sigs[sig] += 1
            examples.setdefault(sig, note)
    verdicts = collections.Counter(v for r in results for v in r["verdicts"])
    total_ops = sum(op_total.values())
    lines = [f"# Outside swarm: {n} agents, {len(PERSONAS)} personas, {cfg['witness_count']} witnesses", "",
             f"- target: `{cfg['cli']}` ({cfg['cli_version']}), witness_log {cfg['py_version']}",
             f"- {n} agents in {elapsed:.0f} s, {cfg['processes']} x {cfg['threads']} in flight, {total_ops} operations, "
             f"{sum(len(r['verdicts']) for r in results)} verdicts",
             f"- agents finished cleanly: {n - len(crashed)}/{n}; operations failed: {sum(op_fail.values())}/{total_ops}",
             f"- witness add-checkpoint statuses: {dict(sorted(statuses.items(), key=lambda kv: -kv[1]))}",
             f"- verdicts: {dict(verdicts.most_common())}", ""]
    lines += ["## Common issues (clustered by signature, most frequent first)", ""]
    if not sigs:
        lines.append("None.")
    for sig, c in sigs.most_common(40):
        lines.append(f"- **{c}x** `{sig}`  \n  e.g. `{examples[sig][:220]}`")
    lines += ["", "## Per persona", "", "| persona | agents | crashed | notes |", "|---|---|---|---|"]
    for p, b in sorted(by_persona.items()):
        lines.append(f"| {p} | {b['n']} | {b['crashed']} | {b['notes']} |")
    lines += ["", "## Latency per operation (ms; successful calls)", "", "| op | n | p50 | p95 | p99 | max | failed |", "|---|---|---|---|---|---|---|"]
    for op, xs in sorted(ops.items(), key=lambda kv: -len(kv[1])):
        lines.append(f"| {op} | {len(xs)} | {pct(xs, 50):.2f} | {pct(xs, 95):.2f} | {pct(xs, 99):.2f} | {max(xs):.1f} | {op_fail[op]} |")
    for op, c in op_fail.items():
        if op not in ops:
            lines.append(f"| {op} | 0 | - | - | - | - | {c} |")
    open(os.path.join(out, "REPORT.md"), "w").write("\n".join(lines) + "\n")
    json.dump({"config": {k: v for k, v in cfg.items() if k not in ("directory",)}, "elapsed": elapsed, "results": results},
              open(os.path.join(out, "results.json"), "w"))
    print("\n".join(lines[:12]))
    print(f"\nreport: {os.path.join(out, 'REPORT.md')}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--agents", type=int, default=1000)
    ap.add_argument("--directory", required=True, help="witness directory JSON of the live network")
    ap.add_argument("--cli", default=os.environ.get("WL_BIN", os.path.join(REPO, "target", "release", "witness-log")))
    ap.add_argument("--out", default=None)
    ap.add_argument("--processes", type=int, default=8)
    ap.add_argument("--threads", type=int, default=16)
    ap.add_argument("--operator-serve-seconds", type=int, default=90)
    ap.add_argument("--agent-witness-base-port", type=int, default=21000)
    ap.add_argument("--only", help="comma-separated personas")
    args = ap.parse_args()
    import witness_log as wl
    out = args.out or tempfile.mkdtemp(prefix="outside-")
    os.makedirs(out, exist_ok=True)
    work = tempfile.mkdtemp(prefix="work-", dir=out)
    shared = os.path.join(out, "shared-dossiers")
    agent_dir = os.path.join(out, "agent-witnesses")
    os.makedirs(shared, exist_ok=True)
    os.makedirs(agent_dir, exist_ok=True)
    directory = json.load(open(args.directory))
    ver = subprocess.run([args.cli, "--version"], capture_output=True, text=True).stdout.strip()
    cfg = {"work": work, "shared": shared, "agent_dir": agent_dir, "directory": directory, "cli": args.cli,
           "cli_version": ver, "py_version": getattr(wl, "__version__", "?"), "run_id": int(time.time()),
           "witness_count": len(directory["witnesses"]), "processes": args.processes, "threads": args.threads,
           "operator_serve_seconds": args.operator_serve_seconds, "agent_witness_base_port": args.agent_witness_base_port}
    personas = assign_personas(args.agents)
    if args.only:
        keep = set(args.only.split(","))
        personas = [p for p in personas if p in keep]
    jobs = list(enumerate(personas))
    print(f"{len(jobs)} agents, {len(set(personas))} personas, {cfg['witness_count']} witnesses; target {ver}, witness_log {cfg['py_version']}")
    print(f"out: {out}")
    batches = [jobs[i::args.processes] for i in range(args.processes)]
    t0 = time.time()
    results = []
    ctx = mp.get_context("spawn")
    with cf.ProcessPoolExecutor(max_workers=args.processes, mp_context=ctx) as ex:
        futs = [ex.submit(worker_process, b, cfg, args.threads) for b in batches if b]
        done = 0
        for f in cf.as_completed(futs):
            results += f.result()
            done += 1
            print(f"  batch {done}/{len(futs)} done, {len(results)} agents, {time.time() - t0:.0f}s", flush=True)
    results.sort(key=lambda r: r["idx"])
    report(results, cfg, out, time.time() - t0)
    crashed = sum(r["status"] != "ok" for r in results)
    failed_ops = sum(1 for r in results for o in r["ops"] if not o["ok"])
    print(f"agents crashed: {crashed}; operations failed: {failed_ops}")
    return min(99, crashed + (1 if failed_ops else 0))


if __name__ == "__main__":
    sys.exit(main())
