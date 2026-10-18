"""witness-log-mcp-proxy against a fake stdio MCP server
(`fake_mcp_server.py`): pass-through, intent/result leaves under the
documented byte layout, injected tools, per-call timeout, restart on
crash, and periodic witnessing. Plain JSON-RPC over pipes; no MCP SDK
needed."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shlex
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import witness_log as wl
from witness_log.mcp_proxy import PROFILE

HERE = pathlib.Path(__file__).resolve().parent
FAKE = [sys.executable, str(HERE / "fake_mcp_server.py")]


class ProxyClient:
    def __init__(self, tmp_path, *extra, env=None, name="fake", command=None):
        self.journal = str(tmp_path / "proxy.jsonl")
        self.pidfile = str(tmp_path / "pids")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "witness_log.mcp_proxy", "--name", name, "--journal", self.journal, *extra, "--", *(command or FAKE)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "FAKE_MCP_PIDFILE": self.pidfile, **(env or {})},
        )
        self.next_id = 0

    def send(self, msg):
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        self.proc.stdin.flush()

    def recv(self, timeout=10.0):
        out = {}

        def read():
            out["line"] = self.proc.stdout.readline()

        t = threading.Thread(target=read, daemon=True)
        t.start()
        t.join(timeout)
        assert out.get("line"), f"no response within {timeout}s; stderr: {self.stderr_tail()}"
        return json.loads(out["line"])

    def call(self, method, params=None, timeout=10.0):
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params or {}})
        resp = self.recv(timeout)
        assert resp["id"] == self.next_id, resp
        return resp

    def handshake(self):
        r = self.call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}})
        assert r["result"]["serverInfo"]["name"] == "fake"
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def close(self, timeout=10.0):
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        self.proc.wait(timeout)
        return self.proc.returncode

    def stderr_tail(self):
        try:
            self.proc.kill()
        except OSError:
            pass
        return self.proc.stderr.read().decode(errors="replace")[-2000:]

    def pids(self):
        try:
            return pathlib.Path(self.pidfile).read_text().split()
        except OSError:
            return []


def _leaves(journal):
    log = wl.open(journal)
    try:
        return json.loads(log.leaves_json()), log
    finally:
        pass


def test_passthrough_records_intent_and_result_leaves(tmp_path):
    c = ProxyClient(tmp_path)
    try:
        c.handshake()
        tools = c.call("tools/list")["result"]["tools"]
        assert [t["name"] for t in tools] == ["echo", "audit__status", "audit__export"]
        r = c.call("tools/call", {"name": "echo", "arguments": {"x": 1, "y": "two"}})
        assert json.loads(r["result"]["content"][0]["text"]) == {"x": 1, "y": "two"}
        e = c.call("tools/call", {"name": "echo", "arguments": {"fail": True}})
        assert e["result"]["isError"] is True
        rpc = c.call("tools/call", {"name": "echo", "arguments": {"rpc_error": True}})
        assert rpc["error"]["code"] == -32602
        st = c.call("tools/call", {"name": "audit__status"})["result"]["structuredContent"]
        assert st["calls"] == 3 and st["leaf_count"] == 6 and st["restarts"] == 0 and st["witnessed"] is False
        assert st["last_verdict"] is None and st["directory_source"] is None
        ex = c.call("tools/call", {"name": "audit__export"})["result"]["structuredContent"]
        assert ex["directory_source"] is None  # no --directory: nothing to score against
        data = pathlib.Path(ex["path"]).read_bytes()
        assert ex["sha256"] == hashlib.sha256(data).hexdigest() and ex["bytes"] == len(data)
        assert ex["verdict"] == "unanchored" and ex["path"] == c.journal + ".dossier.json"
        assert json.loads(wl.verify_dossier_json(data.decode(), 0.66, st["identity"]))["verdict"] == "unanchored"
        # The fake server never saw the injected tools.
        assert c.call("tools/call", {"name": "echo", "arguments": {}})["result"]["isError"] is False
    finally:
        assert c.close() == 0
    # The leaves are exactly the documented byte layout.
    log = wl.open(c.journal, store_payloads=False)
    leaves = json.loads(log.leaves_json())
    assert [l["leaf_type"] for l in leaves] == [1, 2] * 4
    intent = wl.canonical_json(
        {"profile": PROFILE, "server": "fake", "tool": "echo", "args_sha256": hashlib.sha256(wl.canonical_json({"x": 1, "y": "two"})).hexdigest()}
    )
    d0 = log.disclose(0)
    assert wl.payload_hash(intent, bytes.fromhex(d0["salt"]), 0) == leaves[0]["payload_hash"]
    result_obj = {"content": [{"type": "text", "text": json.dumps({"x": 1, "y": "two"})}], "isError": False}
    result = wl.canonical_json(
        {"profile": PROFILE, "server": "fake", "tool": "echo", "intent_index": 0, "result_sha256": hashlib.sha256(wl.canonical_json(result_obj)).hexdigest(), "is_error": False}
    )
    d1 = log.disclose(1)
    assert wl.verify_disclosure(leaves[1], result, d1["salt"])
    # isError:true and a JSON-RPC error both record is_error: true.
    err_payload = wl.canonical_json(
        {
            "profile": PROFILE,
            "server": "fake",
            "tool": "echo",
            "intent_index": 4,
            "result_sha256": hashlib.sha256(wl.canonical_json({"error": {"code": -32602, "message": "bad params"}})).hexdigest(),
            "is_error": True,
        }
    )
    assert wl.verify_disclosure(leaves[5], err_payload, log.disclose(5)["salt"])


def test_timeout_answers_the_host_and_records_an_error_result(tmp_path):
    c = ProxyClient(tmp_path, "--timeout", "0.3")
    try:
        c.handshake()
        t0 = time.monotonic()
        r = c.call("tools/call", {"name": "echo", "arguments": {"sleep": 1.2}}, timeout=5)
        assert time.monotonic() - t0 < 1.0
        assert "timed out" in r["error"]["message"]
        # The late answer from the (single-threaded) server is dropped once
        # it arrives; the proxy still works afterwards.
        time.sleep(1.3)
        ok = c.call("tools/call", {"name": "echo", "arguments": {"n": 1}}, timeout=10)
        assert ok["result"]["isError"] is False
    finally:
        c.close()
    leaves = json.loads(wl.open(c.journal).leaves_json())
    log = wl.open(c.journal, session="reuse")
    expected = wl.canonical_json(
        {
            "profile": PROFILE,
            "server": "fake",
            "tool": "echo",
            "intent_index": 0,
            "result_sha256": hashlib.sha256(
                wl.canonical_json({"error": {"code": -32000, "message": "witness-log-mcp-proxy: timed out after 0.3s"}})
            ).hexdigest(),
            "is_error": True,
        }
    )
    assert wl.verify_disclosure(leaves[1], expected, log.disclose(1)["salt"])


def test_crash_restarts_the_server_and_fails_the_inflight_call(tmp_path):
    c = ProxyClient(tmp_path, "--max-restarts", "1")
    try:
        c.handshake()
        r = c.call("tools/call", {"name": "echo", "arguments": {"crash": True}})
        assert "exited with code 3" in r["error"]["message"]
        # Restarted and re-initialized: the next call works and the
        # server's initialize response was not forwarded to us.
        ok = c.call("tools/call", {"name": "echo", "arguments": {"after": "restart"}})
        assert json.loads(ok["result"]["content"][0]["text"]) == {"after": "restart"}
        st = c.call("tools/call", {"name": "audit__status"})["result"]["structuredContent"]
        assert st["restarts"] == 1 and st["calls"] == 2
        assert len(c.pids()) == 2
        # Second crash exceeds the limit: the proxy exits non-zero.
        c.call("tools/call", {"name": "echo", "arguments": {"crash": True}})
    finally:
        code = c.close()
    assert code != 0
    leaves = json.loads(wl.open(c.journal).leaves_json())
    assert len(leaves) == 6  # three calls, each with intent and result


def test_a_retry_right_after_a_crash_reaches_the_restarted_server(tmp_path):
    """0.5.0 (10,000-agent confirmation swarm): the crashed call's error
    went to the host before the replacement server was running, so a host
    that retried at once could get "server unavailable" (a race needing
    load to show). In-process, with a slow replacement: the crash error
    arrives only once the new server is running, and the retry reaches it."""
    from witness_log.mcp_proxy import Proxy

    host_r, proxy_in = os.pipe()  # host writes requests to proxy_in
    proxy_out, host_w = os.pipe()  # proxy writes responses to host_w
    to_proxy = os.fdopen(proxy_in, "wb", buffering=0)
    from_proxy = os.fdopen(proxy_out, "rb", buffering=0)
    proxy = Proxy(
        FAKE,
        str(tmp_path / "inproc.jsonl"),
        "fake",
        max_restarts=5,
        stdin=os.fdopen(host_r, "rb", buffering=0),
        stdout=os.fdopen(host_w, "wb", buffering=0),
    )
    spawn = proxy._spawn
    first = [True]

    def slow_spawn():
        if not first[0]:
            time.sleep(0.5)  # a replacement that takes a while to start
        first[0] = False
        spawn()

    proxy._spawn = slow_spawn
    t = threading.Thread(target=proxy.run, daemon=True)
    t.start()

    def call(i, method, params):
        to_proxy.write((json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params}) + "\n").encode())
        line = from_proxy.readline()
        return json.loads(line)

    try:
        assert "result" in call(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}})
        to_proxy.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        r = call(2, "tools/call", {"name": "echo", "arguments": {"crash": True}})
        assert "exited with code 3" in r["error"]["message"], r
        ok = call(3, "tools/call", {"name": "echo", "arguments": {"retry": 1}})
        assert "result" in ok, ok
        assert json.loads(ok["result"]["content"][0]["text"]) == {"retry": 1}
    finally:
        to_proxy.close()
        t.join(15)


def test_a_call_sent_during_a_restart_runs_once_with_its_real_result_journaled(tmp_path, monkeypatch):
    """0.5.0 (security review 3, F4): a call that arrived after the old
    server's stdout closed, but before the proxy had taken stock of the
    calls the dead server had, was counted among them. Once the replacement
    was up the call was sent to it and ran, while the proxy also answered
    the host with an error, journaled an is_error result, and dropped the
    real answer; a host retry ran it twice. Invariant: a call is journaled
    as failed only if no server ran it to an answer, and every answered
    call's real result is journaled and reaches the host. Deterministic:
    the old server keeps running, stdout closed, until the test lets it
    exit."""
    from witness_log.mcp_proxy import Proxy

    effects = tmp_path / "effects.jsonl"
    let_it_exit = tmp_path / "let-the-old-server-exit"
    monkeypatch.setenv("FAKE_MCP_EFFECTS", str(effects))
    host_r, proxy_in = os.pipe()
    proxy_out, host_w = os.pipe()
    to_proxy = os.fdopen(proxy_in, "wb", buffering=0)
    from_proxy = os.fdopen(proxy_out, "rb", buffering=0)
    journal = str(tmp_path / "inproc.jsonl")
    proxy = Proxy(
        FAKE,
        journal,
        "fake",
        max_restarts=3,
        stdin=os.fdopen(host_r, "rb", buffering=0),
        stdout=os.fdopen(host_w, "wb", buffering=0),
    )
    t = threading.Thread(target=proxy.run, daemon=True)
    t.start()
    responses = {}

    def read():
        for line in iter(from_proxy.readline, b""):
            m = json.loads(line)
            responses[m.get("id")] = m

    threading.Thread(target=read, daemon=True).start()

    def send(m):
        to_proxy.write((json.dumps(m) + "\n").encode())

    def wait_for(cond, what):
        end = time.monotonic() + 15
        while not cond():
            assert time.monotonic() < end, f"timed out waiting until {what}"
            time.sleep(0.005)

    pay = {"effect": "pay", "amount": 100}
    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}})
        wait_for(lambda: 1 in responses, "initialize is answered")
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "echo", "arguments": {"close_stdout_then_exit_when": str(let_it_exit)}}})
        wait_for(lambda: not proxy._ready.is_set(), "the proxy sees the server's stdout close")
        send({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "echo", "arguments": pay}})
        wait_for(lambda: "3" in proxy._pending, "call 3 is pending, waiting for the restart")
        let_it_exit.write_text("")
        wait_for(lambda: 2 in responses and 3 in responses, "both calls are answered")
    finally:
        to_proxy.close()
        t.join(15)

    ran = [json.loads(line) for line in effects.read_text().splitlines()]
    assert [r["id"] for r in ran] == [3], ran  # ran once, on the replacement
    assert "exited with code 3" in responses[2]["error"]["message"]
    assert "result" in responses[3], responses[3]  # 0.5.0: an error, though it ran
    assert json.loads(responses[3]["result"]["content"][0]["text"]) == pay

    log = wl.open(journal)
    results = [leaf for leaf in json.loads(log.leaves_json()) if leaf["leaf_type"] == 2]

    def journaled(intent_index, hashed, is_error):
        payload = wl.canonical_json(
            {
                "profile": PROFILE,
                "server": "fake",
                "tool": "echo",
                "intent_index": intent_index,
                "result_sha256": hashlib.sha256(wl.canonical_json(hashed)).hexdigest(),
                "is_error": is_error,
            }
        )
        return [leaf["index"] for leaf in results if wl.verify_disclosure(leaf, payload, log.disclose(leaf["index"])["salt"])]

    assert len(results) == 2
    assert len(journaled(0, {"error": responses[2]["error"]}, True)) == 1  # the call the dead server had
    assert len(journaled(1, responses[3]["result"], False)) == 1  # the real result of the call that ran
    log.close()


@pytest.mark.skipif(os.name != "posix", reason="starts the server through a shell script")
def test_a_server_that_cannot_be_started_again_fails_its_calls_and_the_proxy_exits(tmp_path):
    """0.5.0 (security review 3, F8): the respawn after a crash was
    unguarded. When the server's command could no longer be started
    (Popen raised: the binary was upgraded away, a permission changed) the
    supervisor thread died with the proxy marked not ready: the crashed
    call was answered only by the per-call timeout, every later message
    waited 10 s and failed, and the proxy never exited. A failed start now
    counts against --max-restarts; once they are used up the pending calls
    are failed at once and the proxy exits non-zero."""
    wrapper = tmp_path / "server.sh"
    wrapper.write_text(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(HERE / 'fake_mcp_server.py'))}\n")
    wrapper.chmod(0o755)
    c = ProxyClient(
        tmp_path,
        "--timeout",
        "60",
        "--max-restarts",
        "2",
        command=[str(wrapper)],
        env={"FAKE_MCP_REMOVE_ON_CRASH": str(wrapper)},
    )
    try:
        c.handshake()
        t0 = time.monotonic()
        r = c.call("tools/call", {"name": "echo", "arguments": {"crash": True}}, timeout=20)
        assert "exited with code 3" in r["error"]["message"], r
        assert time.monotonic() - t0 < 15, "answered by the per-call timeout, not by the supervisor"
        code = c.proc.wait(20)
    finally:
        err = c.stderr_tail()
    assert code == 3, err
    assert "could not start the server" in err and "restart limit (2) reached" in err, err
    leaves = json.loads(wl.open(c.journal).leaves_json())
    assert [leaf["leaf_type"] for leaf in leaves] == [1, 2]  # the crashed call's intent and its error


def _witness(i, delay=0.0):
    svc = wl.WitnessService.new(f"w{i}.test/px", os.urandom(32), None, True)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):  # noqa: N802
            time.sleep(delay)
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
            st, ct, out = svc.handle_add_checkpoint_http(body)
            b = out.encode()
            self.send_response(st)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{httpd.server_address[1]}"
    return httpd, json.loads(wl.witness_entry_independent(f"w{i}.test/px", f"Org {i}", url, svc.pubkey_hex()))


def test_periodic_witnessing(tmp_path):
    ws = [_witness(i) for i in range(2)]
    # Two live witnesses in a directory of eight: the export's verdict must
    # gate on the cosignature count submit used, not on 0.66 of the
    # directory (a 20-witness directory turned every export into
    # CONSISTENT-UNWITNESSED in the 100,000-agent run).
    dead = [
        json.loads(wl.witness_entry_independent(f"dead{i}.test/px", f"Dead Org {i}", f"http://127.0.0.1:1/{i}", "%064x" % (i + 1)))
        for i in range(6)
    ]
    directory = {"witnesses": [e for _, e in ws] + dead}
    dpath = tmp_path / "trusted.json"
    dpath.write_text(json.dumps(directory))
    c = ProxyClient(tmp_path, "--directory", str(dpath), "--submit-every", "2")
    try:
        c.handshake()
        c.call("tools/call", {"name": "echo", "arguments": {"n": 1}})
        c.call("tools/call", {"name": "echo", "arguments": {"n": 2}})
        for _ in range(100):
            st = c.call("tools/call", {"name": "audit__status"})["result"]["structuredContent"]
            if st["last_verdict"] == "witnessed":
                break
            time.sleep(0.05)
        assert st["last_verdict"] == "witnessed", st
        assert st["witnessed"] is True and st["directory_source"] == "pinned"
        c.call("tools/call", {"name": "echo", "arguments": {"n": 3}})  # one more, not yet witnessed
        # The export is what gets handed on, so it witnesses the current head
        # first (a 100,000-agent run exported CONSISTENT-UNWITNESSED heads
        # whenever the call count was not a multiple of --submit-every).
        ex = c.call("tools/call", {"name": "audit__export"}, timeout=30)["result"]["structuredContent"]
        assert ex["verdict"] == "witnessed", ex
        assert ex["directory_source"] == "pinned"  # the operator's --directory
        # Two of eight is not a strict majority: another two could have
        # cosigned a conflicting history (security review 3, F11).
        assert ex["split_view_unsafe"] is True
    finally:
        assert c.close() == 0
        for httpd, _ in ws:
            httpd.shutdown()
    state = json.loads((tmp_path / "proxy.jsonl.witnesses.json").read_text())
    assert state["cosigned_size"] == 6  # the close-time submit covered the last call


def test_export_waits_for_a_round_in_flight(tmp_path):
    """0.5.0 (100,000-agent swarm, ~1% of proxy exports): an export that
    arrived while a periodic round was still covering an older head skipped
    witnessing and handed on an unwitnessed dossier. It now waits for that
    round and then witnesses the head it did not cover."""
    ws = [_witness(i, delay=0.6) for i in range(2)]
    dpath = tmp_path / "trusted.json"
    dpath.write_text(json.dumps({"witnesses": [e for _, e in ws]}))
    c = ProxyClient(tmp_path, "--directory", str(dpath), "--submit-every", "2")
    try:
        c.handshake()
        c.call("tools/call", {"name": "echo", "arguments": {"n": 1}})
        c.call("tools/call", {"name": "echo", "arguments": {"n": 2}})  # starts a slow round for size 4
        c.call("tools/call", {"name": "echo", "arguments": {"n": 3}})  # size 6, not covered by it
        ex = c.call("tools/call", {"name": "audit__export"}, timeout=40)["result"]["structuredContent"]
        assert ex["verdict"] == "witnessed", ex
        exported = json.loads(pathlib.Path(ex["path"]).read_text())
        assert exported["checkpoint"]["tree_size"] == 6
        assert len(exported["witness_receipts"]) == 2
    finally:
        assert c.close() == 0
        for httpd, _ in ws:
            httpd.shutdown()


def _rewrite_journal(journal, n):
    """Replace `journal` with `n` leaves of different history under the
    same identity (an unsealed journal keeps the seed in its header)."""
    log = wl.open(journal)
    seed = bytes(log.identity_bytes())
    log.close()
    for suffix in ("", ".salts", ".lock"):
        try:
            os.remove(journal + suffix)
        except FileNotFoundError:
            pass
    forged = wl.open(journal, identity_seed=seed)
    for i in range(n):
        forged.append_intent(f"rewritten history {i}".encode())
    forged.close()


def test_export_flags_a_journal_rewritten_or_truncated_after_witnessing(tmp_path):
    """0.5.0 (security review 3, F2, proxy side): audit__export verified
    its dossier with no known head, and `witnessed_dossier_json` is rebuilt
    from the journal (cosignatures it no longer matches are dropped), so a
    journal rewritten after witnessing exported with no sign of it. The
    head witnesses cosigned, from <journal>.witnesses.json, is now a known
    head."""
    ws = [_witness(i) for i in range(2)]
    dpath = tmp_path / "trusted.json"
    dpath.write_text(json.dumps({"witnesses": [e for _, e in ws]}))
    try:
        c = ProxyClient(tmp_path, "--directory", str(dpath))
        try:
            c.handshake()
            c.call("tools/call", {"name": "echo", "arguments": {"n": 1}})
            c.call("tools/call", {"name": "echo", "arguments": {"n": 2}})
            ex = c.call("tools/call", {"name": "audit__export"}, timeout=30)["result"]["structuredContent"]
            assert ex["verdict"] == "witnessed" and not ex.get("tamper_alerts"), ex
            assert ex.get("split_view_unsafe", False) is False  # two of two
        finally:
            assert c.close() == 0
        cosigned = json.loads((tmp_path / "proxy.jsonl.witnesses.json").read_text())["cosigned_size"]
        assert cosigned == 4

        _rewrite_journal(c.journal, cosigned + 3)
        c = ProxyClient(tmp_path, "--directory", str(dpath))
        try:
            c.handshake()
            ex = c.call("tools/call", {"name": "audit__export"}, timeout=30)["result"]["structuredContent"]
            assert ex["verdict"] == "diverged", ex
            assert any(a.startswith("contradiction: known head") for a in ex["tamper_alerts"]), ex
        finally:
            c.close()

        _rewrite_journal(c.journal, cosigned - 1)
        c = ProxyClient(tmp_path, "--directory", str(dpath))
        try:
            c.handshake()
            ex = c.call("tools/call", {"name": "audit__export"}, timeout=30)["result"]["structuredContent"]
            assert any("truncated after witnessing" in a for a in ex["tamper_alerts"]), ex
        finally:
            c.close()
    finally:
        for httpd, _ in ws:
            httpd.shutdown()


def test_the_injected_tools_refuse_arguments(tmp_path):
    """Review III, P2: the proxy's trust anchor is the operator's --directory.
    Its injected tools ignored any arguments, so a model that passed a
    directory of its own (from a document, a tool result, the counterparty)
    got a verdict back with nothing to say its directory was not the one
    used. Arguments are refused now; the verdicts name their source."""
    ws = [_witness(i) for i in range(2)]
    attacker = [_witness(10 + i) for i in range(2)]
    dpath = tmp_path / "trusted.json"
    dpath.write_text(json.dumps({"witnesses": [e for _, e in ws]}))
    c = ProxyClient(tmp_path, "--directory", str(dpath))
    try:
        c.handshake()
        c.call("tools/call", {"name": "echo", "arguments": {"n": 1}})
        for tool in ("audit__export", "audit__status"):
            r = c.call("tools/call", {"name": tool, "arguments": {"directory": {"witnesses": [e for _, e in attacker]}}}, timeout=30)
            assert r["result"]["isError"] is True, r
            text = r["result"]["content"][0]["text"]
            assert "takes no arguments" in text and "--directory" in text, text
        ex = c.call("tools/call", {"name": "audit__export", "arguments": {}}, timeout=30)["result"]["structuredContent"]
        assert ex["verdict"] == "witnessed" and ex["directory_source"] == "pinned", ex
        receipts = json.loads(pathlib.Path(ex["path"]).read_text())["witness_receipts"]
        assert {r["witness_pubkey"] for r in receipts} == {e["pubkey"] for _, e in ws}
    finally:
        assert c.close() == 0
        for httpd, _ in ws + attacker:
            httpd.shutdown()


def test_cli_argument_errors():
    r = subprocess.run([sys.executable, "-m", "witness_log.mcp_proxy", "--name", "x", "--journal", "j"], capture_output=True, text=True)
    assert r.returncode == 2 and "no server command" in r.stderr
    r = subprocess.run(
        [sys.executable, "-m", "witness_log.mcp_proxy", "--name", "x", "--journal", "j", "--submit-every", "3", "--", "true"],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 2 and "--directory" in r.stderr
