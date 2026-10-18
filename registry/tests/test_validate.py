"""Tests for registry/validate.py: offline shape checks and the live
cross-check against what a witness serves at GET /, using a local
http.server that answers like `witness-log witness serve` does."""
import http.server
import importlib.util
import json
import os
import sys
import threading

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("validate", os.path.join(HERE, "..", "validate.py"))
validate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validate)

KEY = "540a4adcd02d9d59e046f9927c10f243d3836e33fe676f2ab58bc6bb10bd5e00"
KEY2 = "8398197cbf2a794802b51f31e03dacae98a32c0e93aaaef572c5474210332f4a"


def entry(**over):
    e = {
        "name": "w1.example.org/witness",
        "operator_org": "Example Org A",
        "url": "https://w1.example.org",
        "pubkey": KEY,
        "runtime": "human",
        "compute_provider": "hetzner",
        "is_project_operated": False,
    }
    e.update(over)
    return e


def served(e, **over):
    """What `GET /` on a witness returns (shape from witness_cmd.rs)."""
    info = {
        "software": "witness-log 0.3.6",
        "protocol": "c2sp.org/tlog-witness",
        "key_name": e["name"],
        "pubkey_hex": e["pubkey"],
        "vkey": e["name"] + "+2a1af9ae+BFQKStzQLZ1Z4Eb5knwQ8kPTg24z/mdvKrWLxrsQvV4A",
        "directory_entry": dict(e),
        "logs": 0,
        "open_enrollment": True,
    }
    info.update(over)
    return info


class _Handler(http.server.BaseHTTPRequestHandler):
    body = b"{}"
    status = 200

    def do_GET(self):  # noqa: N802
        self.send_response(self.status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *a):  # quiet
        pass


@pytest.fixture
def server():
    """A local witness-shaped server; set server.body / server.status per test."""
    handler = type("H", (_Handler,), {})
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    srv.url = f"http://127.0.0.1:{srv.server_port}"
    srv.handler = handler
    yield srv
    srv.shutdown()
    srv.server_close()


def write_registry(tmp_path, *entries):
    d = tmp_path / "witnesses"
    d.mkdir(exist_ok=True)
    for i, e in enumerate(entries):
        (d / f"e{i}.json").write_text(json.dumps(e))
    return str(d)


def run(tmp_path, *entries, **kw):
    reg = write_registry(tmp_path, *entries)
    return validate.validate(reg, **kw)


# ---- offline shape checks -------------------------------------------------


def test_valid_entry_offline(tmp_path):
    files, problems, notes = run(tmp_path, entry(), offline=True)
    assert len(files) == 1 and problems == [] and notes == []


def test_http_url_refused_without_allow_insecure(tmp_path):
    _, problems, _ = run(tmp_path, entry(url="http://w1.example.org"), offline=True)
    assert any("plain http" in p for p in problems)


def test_http_url_allowed_with_allow_insecure(tmp_path):
    _, problems, _ = run(tmp_path, entry(url="http://w1.example.org"), offline=True, allow_insecure=True)
    assert problems == []


def test_loopback_refused(tmp_path):
    _, problems, _ = run(tmp_path, entry(url="https://127.0.0.1:7380"), offline=True)
    assert any("loopback" in p for p in problems)


@pytest.mark.parametrize("org", ["", "   ", "unspecified", "Unspecified", " Example Org", "Example  Org"])
def test_bad_org_labels(tmp_path, org):
    _, problems, _ = run(tmp_path, entry(operator_org=org), offline=True)
    assert any("operator_org" in p for p in problems)


def test_uppercase_pubkey_refused(tmp_path):
    _, problems, _ = run(tmp_path, entry(pubkey=KEY.upper()), offline=True)
    assert any("lowercase" in p for p in problems)


def test_duplicate_key_and_name(tmp_path):
    _, problems, _ = run(tmp_path, entry(), entry(), offline=True)
    assert any("duplicate pubkey" in p for p in problems)
    assert any("duplicate name" in p for p in problems)


def test_unknown_field_and_missing_field(tmp_path):
    e = entry(extra=1)
    del e["runtime"]
    _, problems, _ = run(tmp_path, e, offline=True)
    assert any("missing" in p for p in problems)


def test_not_json(tmp_path):
    d = tmp_path / "witnesses"
    d.mkdir()
    (d / "bad.json").write_text("{")
    _, problems, _ = validate.validate(str(d), offline=True)
    assert any("not JSON" in p for p in problems)


# ---- live cross-check against a local server -----------------------------


def test_live_match_passes(tmp_path, server):
    e = entry(url=server.url)
    server.handler.body = json.dumps(served(e)).encode()
    _, problems, notes = run(tmp_path, e, allow_insecure=True)
    assert problems == [] and notes == []


def test_live_org_mismatch_is_refused(tmp_path, server):
    e = entry(url=server.url)
    server.handler.body = json.dumps(served(e, directory_entry=dict(e, operator_org="Example Org B"))).encode()
    _, problems, _ = run(tmp_path, e, allow_insecure=True)
    assert len(problems) == 1 and "operator_org" in problems[0] and "'Example Org B'" in problems[0]


def test_live_org_is_case_sensitive(tmp_path, server):
    e = entry(url=server.url)
    server.handler.body = json.dumps(served(e, directory_entry=dict(e, operator_org="example org a"))).encode()
    _, problems, _ = run(tmp_path, e, allow_insecure=True)
    assert len(problems) == 1 and "case-sensitive" in problems[0]


def test_live_key_mismatch_is_refused(tmp_path, server):
    e = entry(url=server.url)
    server.handler.body = json.dumps(served(e, pubkey_hex=KEY2)).encode()
    _, problems, _ = run(tmp_path, e, allow_insecure=True)
    assert any("serves key" in p for p in problems)


def test_live_missing_directory_entry_is_refused(tmp_path, server):
    e = entry(url=server.url)
    info = served(e)
    del info["directory_entry"]
    server.handler.body = json.dumps(info).encode()
    _, problems, _ = run(tmp_path, e, allow_insecure=True)
    assert any("directory_entry" in p for p in problems)


def test_unreachable_is_a_note_unless_required(tmp_path, server):
    e = entry(url=server.url)
    server.handler.status = 503
    server.handler.body = b"down"
    _, problems, notes = run(tmp_path, e, allow_insecure=True)
    assert problems == [] and len(notes) == 1 and "not reachable" in notes[0]
    _, problems, notes = run(tmp_path, e, allow_insecure=True, require_live=True)
    assert len(problems) == 1 and notes == []


def test_offline_skips_live(tmp_path, server):
    e = entry(url=server.url)
    server.handler.body = json.dumps(served(e, pubkey_hex=KEY2)).encode()
    _, problems, _ = run(tmp_path, e, offline=True, allow_insecure=True)
    assert problems == []


def test_main_exit_codes(tmp_path, server, capsys):
    e = entry(url=server.url)
    server.handler.body = json.dumps(served(e, directory_entry=dict(e, operator_org="Other"))).encode()
    reg = write_registry(tmp_path, e)
    assert validate.main(["--registry-dir", reg, "--allow-insecure"]) == 1
    out = capsys.readouterr().out
    assert "error:" in out and "1 entries, 1 problems" in out
    assert validate.main(["--registry-dir", reg, "--offline", "--allow-insecure"]) == 0
    assert validate.main(["--help"]) == 0
    assert validate.main(["--bogus"]) == 2


def test_real_registry_offline():
    """The committed registry (possibly empty) must pass its own checks."""
    assert validate.main(["--offline"]) == 0


def test_pubkey_with_a_trailing_newline_refused(tmp_path):
    """Security sweep I3: HEX32 ended in `$`, which matches before a
    trailing newline, so a key with one passed validate.py (and
    build_directory.py)."""
    _, problems, _ = run(tmp_path, entry(pubkey=KEY + "\n"), offline=True)
    assert any("64 hex" in p for p in problems), problems


# ---- re-audit of the 0.6.1 fixes ------------------------------------------


@pytest.mark.parametrize("field,value", [("operator_org", ["Org A"]), ("name", 7), ("url", None),
                                         ("pubkey", 1), ("compute_provider", 123)])
def test_fields_must_have_their_json_type(tmp_path, field, value):
    # str() used to turn these into text that passed, and the directory
    # built from them could not be loaded by the verifiers.
    _, problems, _ = run(tmp_path, entry(**{field: value}), offline=True)
    assert any(f"{field} must be a string" in p for p in problems), problems


@pytest.mark.parametrize("org", ["Org​A", "Org A‍", "﻿Org A", "Org­A", "Org⁦A⁩",
                                 "OrgㅤA", "Org A️", "Org\x07A", "OrgA"])
def test_invisible_characters_in_a_label_are_refused(tmp_path, org):
    # The verifier compares labels exactly: "Org​A" and "OrgA" look
    # the same and would count as two independent operators.
    _, problems, _ = run(tmp_path, entry(operator_org=org), offline=True)
    assert any("invisible or control characters" in p for p in problems), problems


def test_international_labels_are_fine(tmp_path):
    files, problems, _ = run(tmp_path, entry(operator_org="株式会社 Ejemplo Ñandú"), offline=True)
    assert problems == []


@pytest.mark.parametrize("url", ["https://169.254.169.254/", "https://2130706433/", "https://0x7f.1/",
                                 "https://127.1/", "https://[::ffff:127.0.0.1]/", "https://[64:ff9b::a9fe:a9fe]/",
                                 "https://10.0.0.5/", "https://100.64.0.1/", "https://[fe80::1]/",
                                 "https://[fc00::1]/", "https://169.254.169.254./", "https://01.2.3.4/"])
def test_non_public_or_disguised_ip_literals_are_refused(tmp_path, url):
    _, problems, _ = run(tmp_path, entry(url=url), offline=True)
    assert any("url" in p for p in problems), problems
    _, problems, _ = run(tmp_path, entry(url=url), offline=True, allow_insecure=True)
    assert problems == []


@pytest.mark.parametrize("url", ["https://93.184.216.34/", "https://[2606:4700::1]:8443/", "https://deadbeef.example/"])
def test_public_ip_literals_are_fine(tmp_path, url):
    _, problems, _ = run(tmp_path, entry(url=url), offline=True)
    assert problems == [], problems
