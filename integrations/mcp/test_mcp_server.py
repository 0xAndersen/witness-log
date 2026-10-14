"""End-to-end test: spawn witness_mcp_server.py over stdio with the
official MCP client and drive every tool, including tamper detection and
a live witness.  Run: `pytest -q integrations/mcp/test_mcp_server.py`."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

try:
    from mcp.client.client import Client
    from mcp.client.stdio import StdioServerParameters
except ImportError:  # pragma: no cover
    pytest.skip("mcp>=2 not installed", allow_module_level=True)

import witness_log as wl

HERE = Path(__file__).resolve().parent
SERVER = HERE / "witness_mcp_server.py"


def _data(result):
    """Structured content if present, else parsed text (SDK 1.x and 2.x)."""
    sc = getattr(result, "structured_content", None) or getattr(result, "structuredContent", None)
    if sc:
        return sc.get("result", sc)
    text = "".join(getattr(c, "text", "") for c in result.content)
    return json.loads(text)


def _is_error(result) -> bool:
    v = getattr(result, "is_error", None)
    if v is None:
        v = getattr(result, "isError", False)
    return bool(v)


class _WitnessHandler(BaseHTTPRequestHandler):
    svc: wl.WitnessService
    name: str

    def log_message(self, *a):  # quiet
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode()
        st, ct, out = self.svc.handle_add_checkpoint_http(body)
        b = out.encode()
        self.send_response(st)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


def _start_witness(i: int):
    svc = wl.WitnessService.new(f"w{i}.test/mcp", os.urandom(32), None, True)
    handler = type("H", (_WitnessHandler,), {"svc": svc, "name": f"w{i}"})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    entry = json.loads(
        wl.witness_entry_independent(
            f"w{i}.test/mcp", f"Org {i}", f"http://127.0.0.1:{port}", svc.pubkey_hex(), f"cloud-{i}"
        )
    )
    return httpd, entry


@pytest.mark.anyio
async def test_every_tool_over_stdio(tmp_path):
    home = tmp_path / "home"
    params = StdioServerParameters(
        command=sys.executable, args=[str(SERVER)], env={"WITNESS_LOG_HOME": str(home)}
    )
    witnesses = [_start_witness(i) for i in range(3)]
    directory = {"witnesses": [e for _, e in witnesses]}
    try:
        async with Client(params) as client:
            tools = {t.name for t in (await client.list_tools()).tools}
            assert {
                "initialize_witness_chain",
                "append_audit_step",
                "get_inclusion_proof",
                "verify_chain_integrity",
                "redact_audit_entry",
                "export_dossier",
                "submit_to_witnesses",
                "record_handoff",
                "record_authorization",
            } <= tools

            init = _data(
                await client.call_tool(
                    "initialize_witness_chain",
                    {"session_id": "agent-7", "metadata": {"model": "test", "team": "qa"}},
                )
            )
            assert init["resumed"] is False and init["tree_size"] == 1
            ident = init["identity_pubkey"]
            assert init["origin"] == "witness-log/" + ident

            # Bad session ids never touch the filesystem.
            bad = await client.call_tool(
                "initialize_witness_chain", {"session_id": "../etc"}
            )
            assert _is_error(bad)

            r = _data(
                await client.call_tool(
                    "append_audit_step",
                    {
                        "session_id": "agent-7",
                        "intent": "look up the balance",
                        "tool_name": "bank.balance",
                        "payload": {"account": "acc-1"},
                        "state_transition": {"balance": 42},
                    },
                )
            )
            assert r["intent_index"] == 1 and r["result_index"] == 2
            p = r["inclusion_proof"]
            assert wl.verify_inclusion(
                p["leaf_hash"], p["leaf_index"], p["tree_size"], p["path"], p["root_hash"]
            )
            assert r["checkpoint"]["tree_size"] == 3

            v = _data(await client.call_tool("verify_chain_integrity", {"session_id": "agent-7"}))
            assert v["tamper_alerts"] == [] and v["verdict"] == "unanchored"


            red = _data(
                await client.call_tool(
                    "redact_audit_entry", {"session_id": "agent-7", "entry_index": 1}
                )
            )
            assert red["erased"] is True and red["redaction_marker_index"] == 3
            again = _data(
                await client.call_tool(
                    "redact_audit_entry", {"session_id": "agent-7", "entry_index": 1}
                )
            )
            assert again["erased"] is False
            # The proof for the neighbouring leaf still verifies after redaction.
            p2 = _data(
                await client.call_tool(
                    "get_inclusion_proof", {"session_id": "agent-7", "entry_index": 2}
                )
            )
            assert wl.verify_inclusion(
                p2["leaf_hash"], 2, p2["tree_size"], p2["path"], p2["root_hash"]
            )

            sub = _data(
                await client.call_tool(
                    "submit_to_witnesses", {"session_id": "agent-7", "directory": directory}
                )
            )
            assert sub["cosignatures_accepted"] == 3, sub
            assert sub["verdict"] == "witnessed", sub

            v2 = _data(
                await client.call_tool(
                    "verify_chain_integrity",
                    {"session_id": "agent-7", "trusted_directory": directory},
                )
            )
            # The cosignatures from submit are kept: verifying right after a
            # successful submit is WITNESSED (0.3.5 said consistent_unwitnessed
            # and exported a dossier with no receipts).
            assert v2["tamper_alerts"] == []
            assert v2["verdict"] == "witnessed", v2
            assert v2["witnessed_size"] == 4

            exp = _data(await client.call_tool("export_dossier", {"session_id": "agent-7"}))
            dossier = exp["dossier"]
            assert dossier["identity_pubkey"] == ident
            assert len(dossier["witness_receipts"]) == 3
            assert json.loads(
                wl.verify_dossier_json(json.dumps(dossier), 0.66, ident, json.dumps(directory))
            )["verdict"] == "witnessed"

            # Tamper with the exported dossier: the verifier catches it.
            dossier["leaves"][2]["payload_hash"] = "00" * 32
            rep = json.loads(wl.verify_dossier_json(json.dumps(dossier), 0.66, ident))
            assert rep["verdict"] == "invalid" and rep["merkle_continuity_valid"] is False

        # New process, same home: the chain resumes with the same identity.
        async with Client(params) as client:
            init2 = _data(
                await client.call_tool("initialize_witness_chain", {"session_id": "agent-7"})
            )
            assert init2["resumed"] is True
            assert init2["identity_pubkey"] == ident and init2["tree_size"] == 4
            missing = await client.call_tool("export_dossier", {"session_id": "never-made"})
            assert _is_error(missing)
            # Cross-agent leaves from MCP: a second chain receives a handoff
            # and a grant from agent-7; the two sides bind.
            other = _data(
                await client.call_tool("initialize_witness_chain", {"session_id": "agent-8"})
            )
            h1 = _data(
                await client.call_tool(
                    "record_handoff",
                    {
                        "session_id": "agent-7",
                        "direction": "sent",
                        "counterparty_identity_pubkey": other["identity_pubkey"],
                        "state": {"task": "reconcile", "rows": 12},
                    },
                )
            )
            h2 = _data(
                await client.call_tool(
                    "record_handoff",
                    {
                        "session_id": "agent-8",
                        "direction": "received",
                        "counterparty_identity_pubkey": init["identity_pubkey"],
                        "state": {"task": "reconcile", "rows": 12},
                    },
                )
            )
            assert h1["handoff_state_hash"] == h2["handoff_state_hash"]
            g1 = _data(
                await client.call_tool(
                    "record_authorization",
                    {
                        "session_id": "agent-7",
                        "kind": "granted_by_me",
                        "counterparty_identity_pubkey": other["identity_pubkey"],
                        "scope": {"mandate_hash": "ab" * 32, "max_usd": 500},
                    },
                )
            )
            g2 = _data(
                await client.call_tool(
                    "record_authorization",
                    {
                        "session_id": "agent-8",
                        "kind": "granted_to_me",
                        "counterparty_identity_pubkey": init["identity_pubkey"],
                        "scope": {"mandate_hash": "ab" * 32, "max_usd": 500},
                    },
                )
            )
            assert g1["authorization_scope_hash"] == g2["authorization_scope_hash"]
            da = _data(await client.call_tool("export_dossier", {"session_id": "agent-7"}))["dossier"]
            db = _data(await client.call_tool("export_dossier", {"session_id": "agent-8"}))["dossier"]
            da = json.loads(da) if isinstance(da, str) else da
            db = json.loads(db) if isinstance(db, str) else db
            sent = next(l for l in da["leaves"] if l["leaf_type"] == 5)
            recv = next(l for l in db["leaves"] if l["leaf_type"] == 5)
            assert (
                wl.verify_handoff_binding(
                    da["identity_pubkey"], json.dumps(sent), db["identity_pubkey"], json.dumps(recv)
                ) is True
            )
    finally:
        for httpd, _ in witnesses:
            httpd.shutdown()
