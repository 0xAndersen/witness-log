"""Where the witness client sends a checkpoint (security sweep F9).

The MCP server's submit_to_witnesses contacts URLs from a directory the
model may supply. urllib followed a 301/302/303 to a POST with a GET to
wherever Location pointed, and up to 200 bytes of a non-200 answer went
back to the model, so a directory entry could make the server fetch from
an address no entry could name (the cloud metadata service, the host's
private network). The client no longer follows redirects, and a guard
vets the addresses a caller-supplied URL resolves to and pins the
connection to them."""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import witness_log as wl
from witness_log import witnessing
from witness_log.witnessing import _post, submit_round, witness_address_guard


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch):
    for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.delenv(k, raising=False)


class _Server:
    """A local HTTP server that answers every request with ``status`` (and
    ``Location`` for a redirect) and counts what it received."""

    def __init__(self, status=200, location=None, body=b"ok"):
        self.hits = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _answer(self):
                n = int(self.headers.get("Content-Length") or 0)
                outer.hits.append((self.command, self.path, self.rfile.read(n)))
                self.send_response(status)
                if location:
                    self.send_header("Location", location)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = _answer  # noqa: N815

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self):
        self.httpd.shutdown()


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_redirects_are_not_followed(code):
    target = _Server(body=b"secret from the metadata service")
    bouncer = _Server(status=code, location=target.url + "/latest/meta-data/iam")
    try:
        status, text, _ = _post(bouncer.url, "checkpoint", 5)
        assert status == code and "redirect not followed" in text, (status, text)
        assert "secret" not in text
        assert target.hits == []  # nothing was fetched from where Location pointed
        assert [h[0] for h in bouncer.hits] == ["POST"]
    finally:
        target.close()
        bouncer.close()


def test_a_redirecting_witness_is_a_failed_outcome(tmp_path):
    target = _Server(body=b"secret")
    bouncer = _Server(status=302, location=target.url + "/")
    log = wl.open(str(tmp_path / "j.jsonl"))
    try:
        log.append_intent(b"x")
        entry = json.loads(wl.witness_entry_independent("r.test/w", "Org R", bouncer.url, "ab" * 32))
        r = submit_round(log, {"witnesses": [entry]}, str(tmp_path / "state.json"))
        assert r.cosignatures == 0
        assert r.outcomes[0]["status"] == 302 and "redirect not followed" in r.outcomes[0]["error"], r.outcomes
        assert target.hits == []
    finally:
        log.close()
        target.close()
        bouncer.close()


ALWAYS_REFUSED = ["169.254.169.254", "169.254.170.2", "169.254.1.1", "fe80::1", "fd00:ec2::254", "100.100.100.200",
                  "::ffff:169.254.169.254", "0.0.0.0", "224.0.0.1",
                  # IPv6 forms that carry 169.254.169.254 to a translator or
                  # tunnel (re-audit of the 0.6.1 fixes): NAT64, IPv4-compatible,
                  # SIIT, 6to4, Teredo (client address is stored inverted).
                  "64:ff9b::a9fe:a9fe", "::a9fe:a9fe", "::ffff:0:a9fe:a9fe", "2002:a9fe:a9fe::1",
                  "2001:0:4136:e378:8000:63bf:5601:5601"]
PRIVATE = ["127.0.0.1", "10.0.0.5", "172.16.1.1", "192.168.1.1", "100.64.0.1", "::1", "fc00::1", "localhost",
           "64:ff9b::7f00:1", "64:ff9b::a00:5", "::7f00:1", "2002:a00:5::1"]


@pytest.mark.parametrize("host", ALWAYS_REFUSED)
@pytest.mark.parametrize("allow_private", [False, True])
def test_link_local_and_metadata_addresses_are_never_a_witness(host, allow_private):
    with pytest.raises(ValueError, match="link-local, metadata"):
        witness_address_guard(allow_private)(host, 80)


@pytest.mark.parametrize("host", PRIVATE)
def test_private_addresses_need_the_operators_switch(host):
    with pytest.raises(ValueError, match="loopback or private.*WITNESS_LOG_ALLOW_PRIVATE_WITNESSES"):
        witness_address_guard(False)(host, 80)
    assert witness_address_guard(True)(host, 80)


def test_a_public_address_passes():
    infos = witness_address_guard(False)("93.184.216.34", 443)
    assert infos[0][4][0] == "93.184.216.34"


def test_a_host_with_one_bad_address_among_good_ones_is_refused(monkeypatch):
    real = socket.getaddrinfo

    def fake(host, port, *a, **kw):
        if host == "mixed.test":
            return real("93.184.216.34", port, *a, **kw) + real("169.254.169.254", port, *a, **kw)
        return real(host, port, *a, **kw)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    with pytest.raises(ValueError, match="169.254.169.254"):
        witness_address_guard(True)("mixed.test", 80)


def test_the_connection_goes_to_the_vetted_address_not_a_second_lookup(monkeypatch):
    """DNS rebinding: the name answers an allowed address when vetted and
    the metadata address afterwards. The connection must use the first."""
    witness = _Server(body=b"cosigned")
    port = witness.httpd.server_address[1]
    real = socket.getaddrinfo
    lookups = []

    def rebinding(host, p, *a, **kw):
        if host == "witness.rebind.test":
            lookups.append(host)
            return real("127.0.0.1" if len(lookups) == 1 else "169.254.169.254", p, *a, **kw)
        return real(host, p, *a, **kw)

    monkeypatch.setattr(socket, "getaddrinfo", rebinding)
    try:
        status, text, _ = _post(f"http://witness.rebind.test:{port}", "checkpoint", 5, guard=witness_address_guard(True))
        assert (status, text) == (200, "cosigned")
        assert len(lookups) == 1 and len(witness.hits) == 1
    finally:
        witness.close()


def test_submit_round_sends_nothing_to_a_refused_witness(tmp_path):
    witness = _Server()
    log = wl.open(str(tmp_path / "j.jsonl"))
    try:
        log.append_intent(b"x")
        entry = json.loads(wl.witness_entry_independent("p.test/w", "Org P", witness.url, "ab" * 32))
        r = submit_round(log, {"witnesses": [entry]}, str(tmp_path / "state.json"), url_guard=witness_address_guard(False))
        assert r.outcomes[0]["status"] == 0 and "loopback or private" in r.outcomes[0]["error"], r.outcomes
        assert witness.hits == []
    finally:
        log.close()
        witness.close()


def test_the_operator_switch_name():
    assert witnessing.ALLOW_PRIVATE_ENV == "WITNESS_LOG_ALLOW_PRIVATE_WITNESSES"
