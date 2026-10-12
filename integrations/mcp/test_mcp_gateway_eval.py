"""Regressions for what the MCP gateway evaluation of 0.3.6 asked for:
an enum for `record_authorization.kind`, string or object `scope`, file
metadata from `export_dossier`, sealing from the environment, one journal
per server process (no per-call reopen) and `audit_this_session`. Driven
over stdio with the official client against the packaged server.
Run: `pytest -q integrations/mcp -p anyio`."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
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


def _is_error(result) -> bool:
    v = getattr(result, "is_error", None)
    if v is None:
        v = getattr(result, "isError", False)
    return bool(v)


def _witness(i: int):
    svc = wl.WitnessService.new(f"w{i}.test/ge", os.urandom(32), None, True)

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
    return httpd, json.loads(wl.witness_entry_independent(f"w{i}.test/ge", f"Org {i}", url, svc.pubkey_hex()))


def _params(home, **env):
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "witness_log.mcp_server"],
        env={"WITNESS_LOG_HOME": str(home), **env},
    )


def _bindings(journal: pathlib.Path) -> int:
    return sum(1 for line in journal.read_text().splitlines() if '"session_pubkey"' in line and '"index"' not in line)


@pytest.mark.anyio
async def test_tool_schemas_and_count(tmp_path):
    async with Client(_params(tmp_path)) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        assert len(tools) == 11, sorted(tools)
        assert "audit_this_session" in tools
        t = tools["record_authorization"]
        schema = getattr(t, "input_schema", None) or getattr(t, "inputSchema")  # SDK 2.x / 1.x
        kind = schema["properties"]["kind"]
        assert set(kind.get("enum", [])) == {
            "granted_by_me",
            "granted_to_me",
            "revoked_by_me",
            "revoked_to_me",
            "scope_changed_by_me",
            "scope_changed_to_me",
        }
        scope = schema["properties"]["scope"]
        types = {alt.get("type") for alt in scope.get("anyOf", [])}
        assert types == {"string", "object"}, scope


@pytest.mark.anyio
async def test_scope_string_and_object_and_bad_kind(tmp_path):
    async with Client(_params(tmp_path)) as client:
        a = _data(await client.call_tool("initialize_witness_chain", {"session_id": "a"}))
        b = _data(await client.call_tool("initialize_witness_chain", {"session_id": "b"}))
        # Object on both sides: committed as RFC 8785 canonical JSON.
        g1 = _data(
            await client.call_tool(
                "record_authorization",
                {
                    "session_id": "a",
                    "kind": "granted_by_me",
                    "counterparty_identity_pubkey": b["identity_pubkey"],
                    "scope": {"max_usd": 500, "mandate_hash": "ab" * 32},
                },
            )
        )
        g2 = _data(
            await client.call_tool(
                "record_authorization",
                {
                    "session_id": "b",
                    "kind": "granted_to_me",
                    "counterparty_identity_pubkey": a["identity_pubkey"],
                    "scope": {"mandate_hash": "ab" * 32, "max_usd": 500},
                },
            )
        )
        assert g1["authorization_scope_hash"] == g2["authorization_scope_hash"]
        expected = hashlib.sha256(wl.canonical_json({"max_usd": 500, "mandate_hash": "ab" * 32})).hexdigest()
        assert g1["authorization_scope_hash"] == expected
        # String: committed as its UTF-8 bytes.
        s1 = _data(
            await client.call_tool(
                "record_authorization",
                {
                    "session_id": "a",
                    "kind": "revoked_by_me",
                    "counterparty_identity_pubkey": b["identity_pubkey"],
                    "scope": "ucan:eyJhbGciOi...",
                },
            )
        )
        assert s1["authorization_scope_hash"] == hashlib.sha256(b"ucan:eyJhbGciOi...").hexdigest()
        bad = await client.call_tool(
            "record_authorization",
            {
                "session_id": "a",
                "kind": "granted",
                "counterparty_identity_pubkey": b["identity_pubkey"],
                "scope": {},
            },
        )
        assert _is_error(bad)


@pytest.mark.anyio
async def test_export_writes_file_with_digest_and_audit_reports_status(tmp_path):
    ws = [_witness(i) for i in range(2)]
    directory = {"witnesses": [e for _, e in ws]}
    try:
        async with Client(_params(tmp_path)) as client:
            await client.call_tool("initialize_witness_chain", {"session_id": "s"})
            await client.call_tool(
                "append_audit_step",
                {"session_id": "s", "intent": "x", "tool_name": "t", "state_transition": {"ok": True}},
            )
            exp = _data(await client.call_tool("export_dossier", {"session_id": "s"}))
            p = pathlib.Path(exp["path"])
            assert p == tmp_path / "s" / "dossier.json" and p.exists()
            data = p.read_bytes()
            assert exp["bytes"] == len(data) and exp["sha256"] == hashlib.sha256(data).hexdigest()
            assert json.loads(data)["checkpoint"]["tree_size"] == exp["dossier"]["checkpoint"]["tree_size"]

            st = _data(await client.call_tool("audit_this_session", {"session_id": "s"}))
            assert st["leaf_count"] == 2 and st["witnessed"] is False and st["last_verdict"] is None
            assert st["root"] == exp["dossier"]["checkpoint"]["root_hash"]
            assert st["identity"] == exp["dossier"]["identity_pubkey"]

            sub = _data(await client.call_tool("submit_to_witnesses", {"session_id": "s", "directory": directory}))
            assert sub["verdict"] == "witnessed"
            st2 = _data(await client.call_tool("audit_this_session", {"session_id": "s"}))
            assert st2["witnessed"] is True and st2["last_verdict"] == "witnessed" and st2["witnessed_size"] == 2
            await client.call_tool("append_audit_step", {"session_id": "s", "intent": "y", "tool_name": "t"})
            st3 = _data(await client.call_tool("audit_this_session", {"session_id": "s"}))
            assert st3["witnessed"] is False and st3["leaf_count"] == 3 and st3["witnessed_size"] == 2
            missing = await client.call_tool("audit_this_session", {"session_id": "nope"})
            assert _is_error(missing)
    finally:
        for httpd, _ in ws:
            httpd.shutdown()


@pytest.mark.anyio
async def test_one_journal_per_process_no_reopen_per_call(tmp_path):
    journal = tmp_path / "s" / "journal.jsonl"
    async with Client(_params(tmp_path)) as client:
        await client.call_tool("initialize_witness_chain", {"session_id": "s"})
        for i in range(5):
            await client.call_tool("append_audit_step", {"session_id": "s", "intent": str(i), "tool_name": "t"})
            await client.call_tool("get_inclusion_proof", {"session_id": "s", "entry_index": i})
            await client.call_tool("audit_this_session", {"session_id": "s"})
        # Repeating initialize does not reopen either.
        init = _data(await client.call_tool("initialize_witness_chain", {"session_id": "s"}))
        assert init["resumed"] is True
        assert _bindings(journal) == 1  # one session key for the whole process
    async with Client(_params(tmp_path)) as client:
        await client.call_tool("initialize_witness_chain", {"session_id": "s"})
        assert _bindings(journal) == 2  # a new process is a new session


@pytest.mark.anyio
async def test_identity_seed_env_seals_every_session(tmp_path):
    seed = os.urandom(32)
    ident = wl.WitnessLog.resume(seed, 0).identity_pubkey_hex()
    env = {"WITNESS_LOG_IDENTITY_SEED_ENV": "AGENT_KEY", "AGENT_KEY": seed.hex()}
    async with Client(_params(tmp_path, **env)) as client:
        a = _data(await client.call_tool("initialize_witness_chain", {"session_id": "a"}))
        b = _data(await client.call_tool("initialize_witness_chain", {"session_id": "b"}))
        assert a["identity_pubkey"] == ident == b["identity_pubkey"]
    header = (tmp_path / "a" / "journal.jsonl").read_text().splitlines()[0]
    assert seed.hex() not in header and '"identity_bytes_hex":""' in header  # sealed: public key only
    # Resuming without the seed is refused: the journal does not hold it.
    async with Client(_params(tmp_path)) as client:
        r = await client.call_tool("initialize_witness_chain", {"session_id": "a"})
        assert _is_error(r)
    async with Client(_params(tmp_path, **env)) as client:
        r = _data(await client.call_tool("initialize_witness_chain", {"session_id": "a"}))
        assert r["resumed"] is True and r["identity_pubkey"] == ident
