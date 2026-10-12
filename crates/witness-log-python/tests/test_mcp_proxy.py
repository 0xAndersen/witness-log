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
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import witness_log as wl
from witness_log.mcp_proxy import PROFILE

HERE = pathlib.Path(__file__).resolve().parent
FAKE = [sys.executable, str(HERE / "fake_mcp_server.py")]


class ProxyClient:
    def __init__(self, tmp_path, *extra, env=None, name="fake"):
        self.journal = str(tmp_path / "proxy.jsonl")
        self.pidfile = str(tmp_path / "pids")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "witness_log.mcp_proxy", "--name", name, "--journal", self.journal, *extra, "--", *FAKE],
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
        ex = c.call("tools/call", {"name": "audit__export"})["result"]["structuredContent"]
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


def _witness(i):
    svc = wl.WitnessService.new(f"w{i}.test/px", os.urandom(32), None, True)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):  # noqa: N802
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
    directory = {"witnesses": [e for _, e in ws]}
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
        assert st["witnessed"] is True
        c.call("tools/call", {"name": "echo", "arguments": {"n": 3}})  # one more, not yet witnessed
        # The export is what gets handed on, so it witnesses the current head
        # first (a 100,000-agent run exported CONSISTENT-UNWITNESSED heads
        # whenever the call count was not a multiple of --submit-every).
        ex = c.call("tools/call", {"name": "audit__export"}, timeout=30)["result"]["structuredContent"]
        assert ex["verdict"] == "witnessed", ex
    finally:
        assert c.close() == 0
        for httpd, _ in ws:
            httpd.shutdown()
    state = json.loads((tmp_path / "proxy.jsonl.witnesses.json").read_text())
    assert state["cosigned_size"] == 6  # the close-time submit covered the last call


def test_cli_argument_errors():
    r = subprocess.run([sys.executable, "-m", "witness_log.mcp_proxy", "--name", "x", "--journal", "j"], capture_output=True, text=True)
    assert r.returncode == 2 and "no server command" in r.stderr
    r = subprocess.run(
        [sys.executable, "-m", "witness_log.mcp_proxy", "--name", "x", "--journal", "j", "--submit-every", "3", "--", "true"],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 2 and "--directory" in r.stderr
