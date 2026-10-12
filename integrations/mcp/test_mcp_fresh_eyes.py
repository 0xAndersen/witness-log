"""Regressions for what the 0.3.5 fresh-eyes evaluation found in the MCP
server, driven over stdio with the official client against the packaged
server (`python -m witness_log.mcp_server`, what `witness-log-mcp` runs).
Run: `pytest -q integrations/mcp -p anyio`."""

from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

try:
    from mcp.client.client import Client
    from mcp.client.stdio import StdioServerParameters
except ImportError:  # pragma: no cover
    pytest.skip("mcp>=2 not installed", allow_module_level=True)

import witness_log as wl


def _data(result):
    sc = getattr(result, "structured_content", None) or getattr(result, "structuredContent", None)
    if sc:
        return sc.get("result", sc)
    return json.loads("".join(getattr(c, "text", "") for c in result.content))


def _error_text(result) -> str:
    assert getattr(result, "is_error", None) or getattr(result, "isError", False), result
    return "".join(getattr(c, "text", "") for c in result.content)


def _witness(i: int):
    svc = wl.WitnessService.new(f"w{i}.test/fe", os.urandom(32), None, True)

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
    return httpd, json.loads(wl.witness_entry_independent(f"w{i}.test/fe", f"Org {i}", url, svc.pubkey_hex()))


def _params(home):
    return StdioServerParameters(
        command=sys.executable, args=["-m", "witness_log.mcp_server"], env={"WITNESS_LOG_HOME": str(home)}
    )


@pytest.mark.anyio
async def test_errors_tell_the_agent_what_to_fix(tmp_path):
    async with Client(_params(tmp_path)) as c:
        t = _error_text(await c.call_tool("initialize_witness_chain", {"session_id": "../etc"}))
        assert "session_id must be" in t  # 0.3.5: just "Error executing tool ..."
        await c.call_tool("initialize_witness_chain", {"session_id": "a"})
        t = _error_text(
            await c.call_tool(
                "record_handoff",
                {"session_id": "a", "direction": "sent", "counterparty_identity_pubkey": "not-a-key", "state": {}},
            )
        )
        assert "64 hex" in t  # 0.3.5 committed "not-a-key"
        t = _error_text(await c.call_tool("get_inclusion_proof", {"session_id": "a", "entry_index": -1}))
        assert ">= 0" in t
        t = _error_text(await c.call_tool("export_dossier", {"session_id": "never"}))
        assert "initialize_witness_chain first" in t


@pytest.mark.anyio
async def test_intent_then_result_in_two_calls(tmp_path):
    # 0.3.5 had no way to record a result after acting: calling
    # append_audit_step "again later" appended a second intent.
    async with Client(_params(tmp_path)) as c:
        init = _data(await c.call_tool("initialize_witness_chain", {"session_id": "a"}))
        i = _data(await c.call_tool("append_audit_step", {"session_id": "a", "intent": "pay", "tool_name": "pay"}))
        r = _data(
            await c.call_tool(
                "record_result",
                {"session_id": "a", "intent_index": i["intent_index"], "tool_name": "pay", "value": {"ok": True}},
            )
        )
        assert r["result_index"] == i["intent_index"] + 1
        d = _data(await c.call_tool("export_dossier", {"session_id": "a"}))["dossier"]
        assert [l["leaf_type"] for l in d["leaves"]] == [1, 2]
        rep = json.loads(wl.verify_dossier_json(json.dumps(d), 0.66, init["identity_pubkey"]))
        assert rep["verdict"] == "unanchored"
        bad = await c.call_tool("record_result", {"session_id": "a", "intent_index": 99, "tool_name": "pay"})
        assert "no leaf at intent_index 99" in _error_text(bad)
        bad = await c.call_tool(
            "record_result", {"session_id": "a", "intent_index": 0, "tool_name": "pay", "outcome": "maybe"}
        )
        assert "outcome must be" in _error_text(bad)


@pytest.mark.anyio
async def test_submit_never_reads_local_files(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET-CONTENT")
    entry = json.loads(wl.witness_entry_independent("x.test/w", "Org", "http://x", "11" * 32))
    entry["url"] = f"file://{secret}#"
    async with Client(_params(tmp_path / "home")) as c:
        await c.call_tool("initialize_witness_chain", {"session_id": "a"})
        r = await c.call_tool("submit_to_witnesses", {"session_id": "a", "directory": {"witnesses": [entry]}})
        text = json.dumps(_data(r)) if not getattr(r, "is_error", False) else _error_text(r)
        assert "TOP-SECRET-CONTENT" not in text  # 0.3.5 returned the file's first 200 bytes


@pytest.mark.anyio
async def test_witnessed_dossier_is_kept_and_state_is_cli_compatible(tmp_path):
    ws = [_witness(i) for i in range(2)]
    d = {"witnesses": [e for _, e in ws]}
    home = tmp_path / "home"
    try:
        async with Client(_params(home)) as c:
            init = _data(await c.call_tool("initialize_witness_chain", {"session_id": "a"}))
            await c.call_tool("append_audit_step", {"session_id": "a", "intent": "i", "tool_name": "t"})
            sub = _data(await c.call_tool("submit_to_witnesses", {"session_id": "a", "directory": d}))
            assert sub["verdict"] == "witnessed" and sub["tree_size"] == 1
            v = _data(await c.call_tool("verify_chain_integrity", {"session_id": "a", "trusted_directory": d}))
            assert v["verdict"] == "witnessed"  # 0.3.5: consistent_unwitnessed
            await c.call_tool("append_audit_step", {"session_id": "a", "intent": "j", "tool_name": "t"})
            v = _data(await c.call_tool("verify_chain_integrity", {"session_id": "a", "trusted_directory": d}))
            assert v["verdict"] == "consistent_unwitnessed"
            assert v["witnessed_size"] == 1 and v["witnessed_verdict"] == "witnessed"
            exp = _data(await c.call_tool("export_dossier", {"session_id": "a"}))
            assert exp["witnessed_size"] == 1 and len(exp["witnessed_dossier"]["witness_receipts"]) == 2
            assert len(exp["dossier"]["leaves"]) == 2
        state = json.loads((home / "a" / "journal.jsonl.witnesses.json").read_text())
        # The CLI's format: `witness-log witness submit` reads and keeps it.
        assert state["cosigned_size"] == 1 and set(state) == {"sizes", "cosigned_size", "cosigned_root"}
        assert len(state["sizes"]) == 2
        assert init["identity_pubkey"]
    finally:
        for h, _ in ws:
            h.shutdown()
