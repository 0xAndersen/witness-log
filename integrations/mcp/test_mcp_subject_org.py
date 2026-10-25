"""The MCP server's verdicts take the organisation that operates the log
(issue #21). An organisation that runs both this agent and a witness in the
trusted directory must not count as independent of its own agent: with
`subject_org`, its witnesses still cosign but are not counted among the
independent operators WITNESSED needs. The operator can configure it once
(WITNESS_LOG_SUBJECT_ORG or --subject-org); a tool call naming a different
organisation is then refused, since that would let the operator's own
witnesses count again.
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
    assert not (getattr(result, "is_error", None) or getattr(result, "isError", False)), result
    sc = getattr(result, "structured_content", None) or getattr(result, "structuredContent", None)
    if sc:
        return sc.get("result", sc)
    return json.loads("".join(getattr(c, "text", "") for c in result.content))


def _error_text(result) -> str:
    assert getattr(result, "is_error", None) or getattr(result, "isError", False), result
    return "".join(getattr(c, "text", "") for c in result.content)


def _witness(name: str, org: str):
    svc = wl.WitnessService.new(name, os.urandom(32), None, True)

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
    return httpd, json.loads(wl.witness_entry_independent(name, org, url, svc.pubkey_hex()))


@pytest.fixture
def witnesses():
    """Three witnesses run by three organisations; "Org A" also runs the agent."""
    servers, entries = [], []
    for i, org in enumerate(("Org A", "Org B", "Org C")):
        httpd, e = _witness(f"w{i}.test/w", org)
        servers.append(httpd)
        entries.append(e)
    yield entries
    for s in servers:
        s.shutdown()


def _params(home, args=(), **env):
    # The witnesses listen on 127.0.0.1, which a directory passed in a tool
    # call may only name with the operator's switch (security sweep F9).
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "witness_log.mcp_server", *args],
        env={
            "WITNESS_LOG_HOME": str(home),
            "WITNESS_LOG_ALLOW_PRIVATE_WITNESSES": "1",
            # A source checkout under test, when PYTHONPATH points at one.
            **({"PYTHONPATH": os.environ["PYTHONPATH"]} if os.environ.get("PYTHONPATH") else {}),
            **env,
        },
    )


async def _start(c, sid="s"):
    await c.call_tool("initialize_witness_chain", {"session_id": sid})
    await c.call_tool("append_audit_step", {"session_id": sid, "intent": "pay", "tool_name": "pay", "payload": {"x": 1}})


def _independent(report) -> int:
    return report["report"]["quorum"]["distinct_independent_operators"]


@pytest.mark.anyio
async def test_the_subject_org_drops_its_own_witness_from_the_count(tmp_path, witnesses):
    directory = {"witnesses": witnesses}
    async with Client(_params(tmp_path)) as c:
        await _start(c)
        sub = _data(await c.call_tool("submit_to_witnesses", {"session_id": "s", "directory": directory}))
        assert sub["cosignatures_accepted"] == 3 and sub["verdict"] == "witnessed", sub
        assert sub["subject_org"] is None and sub["subject_org_source"] is None
        plain = _data(await c.call_tool("verify_chain_integrity", {"session_id": "s", "trusted_directory": directory}))
        # Labels are compared as the verifier compares them: trimmed, case-folded.
        own = _data(
            await c.call_tool(
                "verify_chain_integrity", {"session_id": "s", "trusted_directory": directory, "subject_org": "  org a "}
            )
        )
    assert _independent(plain) == 3
    assert _independent(own) == 2, own["report"]["quorum"]
    assert own["subject_org"] == "org a" and own["subject_org_source"] == "caller"
    assert own["verdict"] == "witnessed"  # B and C are still two independent operators


@pytest.mark.anyio
async def test_with_two_operators_one_of_them_the_subject_is_not_witnessed(tmp_path, witnesses):
    directory = {"witnesses": witnesses[:2]}  # Org A (the agent's) and Org B
    async with Client(_params(tmp_path)) as c:
        await _start(c)
        sub = _data(await c.call_tool("submit_to_witnesses", {"session_id": "s", "directory": directory}))
        assert sub["verdict"] == "witnessed", sub
        sub = _data(
            await c.call_tool("submit_to_witnesses", {"session_id": "s", "directory": directory, "subject_org": "Org A"})
        )
        assert sub["verdict"] != "witnessed", sub
        v = _data(
            await c.call_tool(
                "verify_chain_integrity", {"session_id": "s", "trusted_directory": directory, "subject_org": "Org A"}
            )
        )
    assert v["verdict"] != "witnessed" and _independent(v) == 1, v["report"]["quorum"]
    assert v["witnessed_verdict"] != "witnessed"


@pytest.mark.anyio
async def test_the_operators_subject_org_is_used_and_cannot_be_swapped(tmp_path, witnesses):
    directory = {"witnesses": witnesses}
    for how in ({"args": ()}, {"args": ("--subject-org", "Org A")}):
        env = {"WITNESS_LOG_SUBJECT_ORG": "Org A"} if not how["args"] else {}
        home = tmp_path / ("env" if env else "flag")
        async with Client(_params(home, how["args"], **env)) as c:
            await _start(c)
            await c.call_tool("submit_to_witnesses", {"session_id": "s", "directory": directory})
            v = _data(await c.call_tool("verify_chain_integrity", {"session_id": "s", "trusted_directory": directory}))
            assert v["subject_org"] == "Org A" and v["subject_org_source"] == "operator", v
            assert _independent(v) == 2
            # The same organisation, spelled differently: fine.
            same = _data(
                await c.call_tool(
                    "verify_chain_integrity", {"session_id": "s", "trusted_directory": directory, "subject_org": "ORG  a"}
                )
            )
            assert same["subject_org_source"] == "operator" and _independent(same) == 2
            # Another organisation would let Org A's witness count again: refused.
            err = _error_text(
                await c.call_tool(
                    "verify_chain_integrity", {"session_id": "s", "trusted_directory": directory, "subject_org": "Org Z"}
                )
            )
            assert "`subject_org` refused" in err and "WITNESS_LOG_SUBJECT_ORG" in err, err
            err = _error_text(
                await c.call_tool("submit_to_witnesses", {"session_id": "s", "directory": directory, "subject_org": "Org Z"})
            )
            assert "`subject_org` refused" in err, err


@pytest.mark.anyio
async def test_tool_descriptions_explain_subject_org(tmp_path):
    async with Client(_params(tmp_path)) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
    for name in ("verify_chain_integrity", "submit_to_witnesses"):
        t = tools[name]
        schema = getattr(t, "input_schema", None) or getattr(t, "inputSchema", None) or {}
        assert "subject_org" in schema.get("properties", {}), name
        d = " ".join((t.description or "").split())
        assert "never count as independent" in d and "WITNESS_LOG_SUBJECT_ORG" in d, (name, d)


def test_log_submit_and_the_proxy_take_subject_org(tmp_path, witnesses):
    from witness_log.mcp_proxy import Proxy

    directory = {"witnesses": witnesses[:2]}
    log = wl.open(str(tmp_path / "a.wlog"), store_payloads=False)
    log.append_intent(b"x")
    assert log.submit(directory)["verdict"] == "witnessed"
    assert log.submit(directory, subject_org="org a")["verdict"] != "witnessed"
    p = Proxy([sys.executable, "-c", "pass"], str(tmp_path / "p.wlog"), "t", subject_org="  Org   A ")
    assert p.subject_org == "Org A"
