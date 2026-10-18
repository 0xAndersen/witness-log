"""What a directory passed to submit_to_witnesses may make the server
contact (security sweep F9). The model may supply that directory, so its
URLs must not turn the server into a way to reach the host's metadata
service or private network: link-local and metadata addresses are always
refused for it, loopback and private ones unless the operator set
WITNESS_LOG_ALLOW_PRIVATE_WITNESSES=1, and redirects are never followed.
The operator's own directories (pinned, $WITNESS_LOG_HOME/witnesses.json)
may name a local testnet. Run: `pytest -q integrations/mcp -p anyio`."""

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


class _Witness:
    """A witness on 127.0.0.1 that counts the requests it gets; with
    ``redirect_to`` it answers 302 instead of cosigning."""

    def __init__(self, i, redirect_to=None):
        self.svc = wl.WitnessService.new(f"t{i}.test/w", os.urandom(32), None, True)
        self.hits = 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _answer(self):
                outer.hits += 1
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
                if redirect_to:
                    self.send_response(302)
                    self.send_header("Location", redirect_to)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                st, ct, out = outer.svc.handle_add_checkpoint_http(body)
                b = out.encode()
                self.send_response(st)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            do_GET = do_POST = _answer  # noqa: N815

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.entry = json.loads(wl.witness_entry_independent(f"t{i}.test/w", f"Org {i}", self.url, self.svc.pubkey_hex()))


@pytest.fixture
def witnesses():
    ws = [_Witness(i) for i in range(3)]
    yield ws
    for w in ws:
        w.httpd.shutdown()


def _params(home, **env):
    return StdioServerParameters(
        command=sys.executable, args=["-m", "witness_log.mcp_server"], env={"WITNESS_LOG_HOME": str(home), **env}
    )


async def _start(c):
    await c.call_tool("initialize_witness_chain", {"session_id": "s"})
    await c.call_tool("append_audit_step", {"session_id": "s", "intent": "x", "tool_name": "t"})


@pytest.mark.anyio
async def test_a_callers_directory_may_not_name_private_addresses(tmp_path, witnesses):
    d = {"witnesses": [w.entry for w in witnesses]}
    async with Client(_params(tmp_path / "home")) as c:
        await _start(c)
        sub = _data(await c.call_tool("submit_to_witnesses", {"session_id": "s", "directory": d}))
    assert sub["cosignatures_accepted"] == 0 and sub["verdict"] != "witnessed", sub
    for o in sub["outcomes"]:
        assert o["status"] == 0 and "loopback or private" in o["error"], o
        assert "WITNESS_LOG_ALLOW_PRIVATE_WITNESSES" in o["error"]
    assert [w.hits for w in witnesses] == [0, 0, 0]  # nothing was sent


@pytest.mark.anyio
async def test_the_operators_switch_allows_a_local_testnet(tmp_path, witnesses):
    d = {"witnesses": [w.entry for w in witnesses]}
    async with Client(_params(tmp_path / "home", WITNESS_LOG_ALLOW_PRIVATE_WITNESSES="1")) as c:
        await _start(c)
        sub = _data(await c.call_tool("submit_to_witnesses", {"session_id": "s", "directory": d}))
    assert sub["cosignatures_accepted"] == 3 and sub["verdict"] == "witnessed", sub


@pytest.mark.anyio
async def test_the_operators_directories_may_name_a_local_testnet(tmp_path, witnesses):
    """No switch needed for the operator's own configuration."""
    d = {"witnesses": [w.entry for w in witnesses]}
    pinned = tmp_path / "trusted.json"
    pinned.write_text(json.dumps(d))
    async with Client(_params(tmp_path / "a", WITNESS_LOG_TRUSTED_DIRECTORY=str(pinned))) as c:
        await _start(c)
        sub = _data(await c.call_tool("submit_to_witnesses", {"session_id": "s"}))
        assert sub["directory_source"] == "pinned" and sub["cosignatures_accepted"] == 3, sub
    home = tmp_path / "b"
    home.mkdir()
    (home / "witnesses.json").write_text(json.dumps(d))
    async with Client(_params(home)) as c:
        await _start(c)
        sub = _data(await c.call_tool("submit_to_witnesses", {"session_id": "s"}))
        assert sub["directory_source"] == "default" and sub["cosignatures_accepted"] == 3, sub


@pytest.mark.anyio
async def test_metadata_and_link_local_are_refused_even_with_the_switch(tmp_path):
    entries = [
        json.loads(wl.witness_entry_independent("m0.test/w", "Org M0", "http://169.254.169.254", "ab" * 32)),
        json.loads(wl.witness_entry_independent("m1.test/w", "Org M1", "http://[fe80::1]:80", "cd" * 32)),
    ]
    async with Client(_params(tmp_path / "home", WITNESS_LOG_ALLOW_PRIVATE_WITNESSES="1")) as c:
        await _start(c)
        sub = _data(await c.call_tool("submit_to_witnesses", {"session_id": "s", "directory": {"witnesses": entries}}))
    assert len(sub["outcomes"]) == 2
    for o in sub["outcomes"]:
        assert o["status"] == 0 and "link-local, metadata" in o["error"], o


@pytest.mark.anyio
async def test_a_redirect_from_a_witness_is_not_followed(tmp_path, witnesses):
    """A directory entry that answers 302 towards another address: the
    server reports it and contacts nothing else, whatever the directory's
    source."""
    target = witnesses[0]
    bouncer = _Witness(9, redirect_to=target.url + "/add-checkpoint")
    try:
        d = {"witnesses": [bouncer.entry]}
        async with Client(_params(tmp_path / "home", WITNESS_LOG_ALLOW_PRIVATE_WITNESSES="1")) as c:
            await _start(c)
            sub = _data(await c.call_tool("submit_to_witnesses", {"session_id": "s", "directory": d}))
        o = sub["outcomes"][0]
        assert o["status"] == 302 and "redirect not followed" in o["error"], o
        assert bouncer.hits == 1 and target.hits == 0
    finally:
        bouncer.httpd.shutdown()
