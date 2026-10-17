"""Disclosure (SPEC §8), the payload sidecar, RFC 8785 canonical JSON,
`open()`'s sealing-from-environment and session reuse, and `log.submit`.
Each test fails on 0.3.6, where none of these exist."""

from __future__ import annotations

import asyncio
import gc
import hashlib
import json
import os
import pathlib
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import witness_log as wl

CORPUS = pathlib.Path(__file__).resolve().parents[3] / "corpus" / "11_payload_hash.json"


# --- payload_hash / verify_disclosure --------------------------------------


def _reference_payload_hash(payload: bytes, salt: bytes, index: int) -> str:
    """SPEC §8 written out in Python, independently of the Rust core:
    SHA256(len(payload) as u64 BE || payload || zeros to (len//256+1)*256
    || salt || index as u64 BE)."""
    bucket = (len(payload) // 256 + 1) * 256
    padded = struct.pack(">Q", len(payload)) + payload + b"\0" * (bucket - len(payload))
    return hashlib.sha256(padded + salt + struct.pack(">Q", index)).hexdigest()


@pytest.mark.skipif(not CORPUS.exists(), reason="corpus not checked out")
def test_payload_hash_matches_corpus_vector_11():
    for case in json.loads(CORPUS.read_text())["cases"]:
        payload, salt = bytes.fromhex(case["payload_hex"]), bytes.fromhex(case["salt_hex"])
        assert wl.payload_hash(payload, salt, case["leaf_index"]) == case["payload_hash"], case["name"]
        assert _reference_payload_hash(payload, salt, case["leaf_index"]) == case["payload_hash"], case["name"]


def test_payload_hash_bucket_boundaries_agree_with_reference():
    salt = bytes(range(32))
    for n in (0, 1, 255, 256, 257, 511, 512, 1000):
        payload = bytes([0x61]) * n
        assert wl.payload_hash(payload, salt, 7) == _reference_payload_hash(payload, salt, 7)
    assert wl.payload_hash(b"x", salt, 0) != wl.payload_hash(b"x", salt, 1)  # index is in the hash
    with pytest.raises(wl.MalformedError):
        wl.payload_hash(b"x", b"short", 0)


def test_disclose_returns_what_a_rust_written_leaf_committed_to(tmp_path):
    p = str(tmp_path / "a.jsonl")
    log = wl.open(p, store_payloads=True)
    payload = wl.canonical_json({"tool": "pay", "amount": 12.5})
    i = log.append_intent(payload)
    d = log.disclose(i)
    assert d["index"] == i and d["payload"] == payload
    assert d["leaf"]["payload_hash"] == d["payload_hash"]
    assert len(bytes.fromhex(d["salt"])) == 32
    # The leaf from the dossier, the disclosed salt and the payload agree
    # with the hash the Rust core committed into the tree.
    leaf = json.loads(log.to_dossier_json())["leaves"][i]
    assert wl.payload_hash(payload, bytes.fromhex(d["salt"]), i) == leaf["payload_hash"]
    assert wl.verify_disclosure(leaf, payload, d["salt"]) is True
    assert wl.verify_disclosure(json.dumps(leaf), payload, d["salt"]) is True
    assert wl.verify_disclosure(leaf, payload + b" ", d["salt"]) is False
    assert wl.verify_disclosure(leaf, payload, "00" * 32) is False
    assert wl.verify_disclosure({"index": i}, payload, d["salt"]) is False  # malformed: False, no raise
    assert wl.verify_disclosure("not json", payload, d["salt"]) is False


def test_disclose_without_payload_store_omits_payload(tmp_path):
    log = wl.open(str(tmp_path / "a.jsonl"))
    i = log.append_result(b"r")
    d = log.disclose(i)
    assert "payload" not in d and d["salt"] and d["payload_hash"]
    assert log.payload(i) is None and log.payload_store_path() is None


def test_disclose_errors_for_missing_and_forgotten_leaves(tmp_path):
    p = str(tmp_path / "a.jsonl")
    log = wl.open(p, store_payloads=True)
    i = log.append_intent(b"secret")
    assert log.payload(i) == b"secret"
    with pytest.raises(IndexError):
        log.disclose(99)
    assert log.forget(i) is True
    with pytest.raises(ValueError):
        log.disclose(i)  # salt gone
    assert log.payload(i) is None  # payload record gone too
    marker = log.tree_size() - 1
    with pytest.raises(ValueError):
        log.disclose(marker)  # a redaction marker has no payload
    sidecar = pathlib.Path(log.payload_store_path()).read_bytes()
    assert b"secret".hex().encode() not in sidecar
    if os.name == "posix":
        assert oct(os.stat(log.payload_store_path()).st_mode & 0o777) == "0o600"


def test_payload_store_survives_resume_and_drops_redacted_records(tmp_path):
    p = str(tmp_path / "a.jsonl")
    log = wl.open(p, store_payloads=True)
    a = log.append_intent(b"keep")
    b = log.append_intent(b"drop")
    log.close()
    # Simulate a crash between forget and the sidecar rewrite: the
    # redaction marker is in the journal, the payload record is not gone.
    log = wl.open(p)
    assert log.forget(b) is True
    log.close()
    sidecar = pathlib.Path(p + ".payloads").read_text()
    assert b"drop".hex() in sidecar
    log = wl.open(p, store_payloads=True)
    assert log.payload(a) == b"keep"
    assert log.payload(b) is None
    assert b"drop".hex() not in pathlib.Path(p + ".payloads").read_text()


def _recorded(sidecar: str) -> set:
    """Indices with a record in a payload sidecar. Lines that do not parse
    (a file being zero-overwritten by `forget`) are skipped."""
    out = set()
    with open(sidecar, "rb") as f:
        for line in f:
            try:
                out.add(json.loads(line)["i"])
            except (ValueError, KeyError, TypeError):
                pass
    return out


def test_a_leaf_is_never_visible_before_its_payload_record(tmp_path):
    """0.5.0 (security review 3, F7): appending a leaf and recording its
    payload were two steps, and the GIL could be released between them
    (when the sidecar was busy). A `forget(i)` in that gap erased the salt,
    found no record, returned True, and the late record then put the
    payload back in `.payloads` (2 of 1,229 forgets in a two-minute race).
    Both steps now happen under the sidecar lock, which `forget` holds from
    erasing the salt to rewriting the sidecar. Deterministic view of the
    gap: while one `forget` rewrites a large sidecar, an append's leaf must
    not be visible before its record is in the file."""
    import time

    p = str(tmp_path / "a.jsonl")
    log = wl.open(p, store_payloads=True)
    big = os.urandom(1 << 20)
    for _ in range(8):
        log.append_intent(big)
    n_before = log.tree_size()
    holder = threading.Thread(target=log.forget, args=(0,))  # rewrites ~16 MB
    holder.start()
    time.sleep(0.05)
    appender = threading.Thread(target=log.append_intent, args=(b"SECRET",))
    appender.start()
    early = []
    checked = set()
    while appender.is_alive() or holder.is_alive():
        for j in range(n_before, log.tree_size()):
            if j in checked:
                continue
            checked.add(j)
            if json.loads(log.leaf_json(j))["leaf_type"] != 1:
                continue  # the holder's redaction marker
            if j not in _recorded(p + ".payloads"):
                early.append(j)
        time.sleep(0.001)
    holder.join()
    appender.join()
    assert not early, f"leaf {early} was visible before its payload record: a forget() there leaks the payload"
    (i,) = [j for j in range(n_before, log.tree_size()) if json.loads(log.leaf_json(j))["leaf_type"] == 1]
    assert log.payload(i) == b"SECRET"
    assert log.forget(i) is True
    assert log.payload(i) is None and i not in _recorded(p + ".payloads")


def test_payload_is_none_for_a_forgotten_leaf_even_if_a_record_lands_late(tmp_path):
    """Defence in depth for F7 (security review 3): once leaf i is
    redacted, `payload(i)` (and so `disclose`) returns nothing, even if a
    record for i is in the sidecar, as the 0.5.0 race left one."""
    p = str(tmp_path / "a.jsonl")
    log = wl.open(p, store_payloads=True)
    i = log.append_intent(b"SECRET")
    keep = log.append_intent(b"public")
    assert log.forget(i) is True
    with open(p + ".payloads", "a") as f:  # the record the race wrote after forget
        f.write(json.dumps({"i": i, "p": b"SECRET".hex()}) + "\n")
    assert log.payload(i) is None
    with pytest.raises(ValueError):
        log.disclose(i)
    assert log.payload(keep) == b"public"
    log.close()
    # And after a restart, enabling the store drops that record from disk.
    log = wl.open(p, store_payloads=True)
    assert log.payload(i) is None and i not in _recorded(p + ".payloads")
    assert log.payload(keep) == b"public"


# --- canonical_json (RFC 8785) and sorted_json --------------------------------


def _double(bits: str) -> float:
    return struct.unpack(">d", bytes.fromhex(bits))[0]


@pytest.mark.parametrize(
    "bits,expected",
    [
        ("0000000000000000", "0"),
        ("8000000000000000", "0"),
        ("0000000000000001", "5e-324"),
        ("8000000000000001", "-5e-324"),
        ("7fefffffffffffff", "1.7976931348623157e+308"),
        ("ffefffffffffffff", "-1.7976931348623157e+308"),
        ("4340000000000000", "9007199254740992"),
        ("c340000000000000", "-9007199254740992"),
        ("4430000000000000", "295147905179352830000"),
        ("44b52d02c7e14af5", "9.999999999999997e+22"),
        ("44b52d02c7e14af6", "1e+23"),
        ("44b52d02c7e14af7", "1.0000000000000001e+23"),
        ("444b1ae4d6e2ef4e", "999999999999999700000"),
        ("444b1ae4d6e2ef4f", "999999999999999900000"),
        ("444b1ae4d6e2ef50", "1e+21"),
        ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
        ("3eb0c6f7a0b5ed8d", "0.000001"),
        ("41b3de4355555553", "333333333.3333332"),
        ("41b3de4355555554", "333333333.33333325"),
        ("41b3de4355555555", "333333333.3333333"),
        ("41b3de4355555556", "333333333.3333334"),
        ("41b3de4355555557", "333333333.33333343"),
        ("becbf647612f3696", "-0.0000033333333333333333"),
        ("43143ff3c1cb0959", "1424953923781206.2"),
    ],
)
def test_canonical_json_numbers_follow_rfc_8785_appendix_b(bits, expected):
    assert wl.canonical_json(_double(bits)).decode() == expected


def test_canonical_json_rfc_8785_section_3_2_3_example():
    src = (
        '{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],'
        ' "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",'
        ' "literals": [null, true, false]}'
    )
    want = (
        '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
    )
    assert wl.canonical_json(json.loads(src)).decode() == want


def test_canonical_json_sorts_keys_by_utf16_code_units():
    # RFC 8785 §3.2.3: U+1F600 (surrogate pair, first unit 0xD83D) sorts
    # before U+FB33; a code-point sort would put it last.
    src = {
        "€": "Euro Sign",
        "\r": "Carriage Return",
        "דּ": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\U0001f600": "Emoji: Grinning Face",
        "\u0080": "Control",
        "ö": "Latin Small Letter O With Diaeresis",
    }
    out = wl.canonical_json(src).decode()
    assert list(json.loads(out)) == ["\r", "1", "\u0080", "ö", "€", "\U0001f600", "דּ"]
    assert out.startswith('{"\\r":"Carriage Return","1":"One","\u0080":"Control"')
    # Python's default sort would differ; `sorted_json` keeps the old order.
    assert list(json.loads(wl.sorted_json(src))) == sorted(src)


def test_canonical_json_integers_and_whole_floats():
    assert wl.canonical_json({"a": 10.0, "b": 10, "c": -0.0, "d": 2**53}) == b'{"a":10,"b":10,"c":0,"d":9007199254740992}'
    assert wl.canonical_json(2**53 + 1) == b"9007199254740992"  # the nearest double, as JCS requires
    assert wl.canonical_json(1e21) == b"1e+21" and wl.canonical_json(1e20) == b"100000000000000000000"
    assert wl.canonical_json(1e-7) == b"1e-7" and wl.canonical_json(-1.5e-10) == b"-1.5e-10"


def test_canonical_json_never_raises_and_is_valid_json():
    cyc: list = []
    cyc.append(cyc)
    for v in [float("nan"), {"k": float("inf")}, {(1, 2): 3}, {1: {2: [3, {None: 4}]}}, cyc, object(), 10**400, "\ud800"]:
        out = wl.canonical_json(v)
        json.loads(out)
    assert wl.canonical_json({"b": 1, "a": [1, 2]}) == b'{"a":[1,2],"b":1}'
    assert json.loads(wl.canonical_json(float("nan"))) == "nan"
    assert wl.canonical_json({1: "x", "1": "y"}) == b'{"1":"y"}'


def test_sorted_json_is_the_pre_0_4_0_encoding():
    v = {"z": "€", "a": [1.0, 1e-7, 10**20], "m": {"k": None}}
    assert wl.sorted_json(v) == json.dumps(v, sort_keys=True, separators=(",", ":")).encode()
    assert wl.sorted_json(v) != wl.canonical_json(v)  # € escaped vs literal; 1.0 vs 1
    assert json.loads(wl.sorted_json(v)) == json.loads(wl.canonical_json(v))


# --- open(): sealing from the environment, session reuse ----------------------


def test_identity_seed_env_seals_the_journal(tmp_path, monkeypatch):
    seed = os.urandom(32)
    monkeypatch.setenv("AGENT_KEY", seed.hex())
    monkeypatch.setenv(wl.IDENTITY_SEED_ENV, "AGENT_KEY")
    p = str(tmp_path / "sealed.jsonl")
    log = wl.open(p)
    ident = log.identity_pubkey_hex()
    log.append_intent(b"x")
    log.close()
    header = pathlib.Path(p).read_text().splitlines()[0]
    assert seed.hex() not in header  # the seed is not in the journal
    assert wl.open(p).identity_pubkey_hex() == ident  # resumes through the env var
    monkeypatch.delenv("AGENT_KEY")
    with pytest.raises(ValueError, match="not set"):
        wl.open(p)
    monkeypatch.setenv("AGENT_KEY", "zz")
    with pytest.raises(ValueError, match="64 hex"):
        wl.open(p)


def test_identity_seed_from_env_helper():
    assert wl.identity_seed_from_env({}) is None
    assert wl.identity_seed_from_env({wl.IDENTITY_SEED_ENV: "K", "K": "ab" * 32}) == b"\xab" * 32
    with pytest.raises(ValueError):
        wl.identity_seed_from_env({wl.IDENTITY_SEED_ENV: "K", "K": "ab" * 31})


def test_session_reuse_returns_the_open_log_without_a_new_binding(tmp_path):
    p = str(tmp_path / "a.jsonl")
    log = wl.open(p)
    log.append_intent(b"x")
    bindings_before = len(pathlib.Path(p).read_text().splitlines())
    again = wl.open(p, session="reuse")
    assert again is log
    assert len(pathlib.Path(p).read_text().splitlines()) == bindings_before  # no new session binding
    # "new" while it is still open is the existing single-writer error.
    with pytest.raises(OSError):
        wl.open(p)
    with pytest.raises(ValueError):
        wl.open(p, session="later")
    # Once nothing holds it, reuse falls back to a resume.
    log.close()
    del log, again
    gc.collect()
    resumed = wl.open(p, session="reuse")
    assert resumed.tree_size() == 1
    assert len(pathlib.Path(p).read_text().splitlines()) == bindings_before + 1
    # reuse can turn the payload store on for an already-open log.
    reused = wl.open(p, session="reuse", store_payloads=True)
    assert reused is resumed and reused.payload_store_path() == p + ".payloads"


# --- log.submit / await log.asubmit ----------------------------------------------


def _witness(i: int):
    svc = wl.WitnessService.new(f"w{i}.test/sub", os.urandom(32), None, True)

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
    return httpd, json.loads(wl.witness_entry_independent(f"w{i}.test/sub", f"Org {i}", url, svc.pubkey_hex()))


@pytest.fixture
def directory():
    ws = [_witness(i) for i in range(2)]
    yield {"witnesses": [e for _, e in ws]}
    for httpd, _ in ws:
        httpd.shutdown()


def test_submit_returns_dossier_and_verdict(tmp_path, directory):
    p = str(tmp_path / "a.jsonl")
    log = wl.open(p)
    log.append_intent(b"one")
    out = log.submit(directory)
    assert out["verdict"] == "witnessed", out["outcomes"]
    assert out["cosignatures"] == 2 and out["contacted"] == 2 and out["tree_size"] == 1
    assert len(out["dossier"]["witness_receipts"]) == 2
    assert json.loads(pathlib.Path(p + ".witnesses.json").read_text())["cosigned_size"] == 1
    # min above what the directory can provide: the verdict says so.
    log.append_intent(b"two")
    assert log.submit(directory, min=3)["verdict"] == "consistent_unwitnessed"
    # A directory file path is accepted too.
    (tmp_path / "d.json").write_text(json.dumps(directory))
    log.append_intent(b"three")
    assert log.submit(str(tmp_path / "d.json"), want=1)["contacted"] == 1


def test_asubmit_runs_off_the_event_loop(tmp_path, directory):
    log = wl.open(str(tmp_path / "a.jsonl"))
    log.append_intent(b"one")

    async def main():
        ticks = 0

        async def ticker():
            nonlocal ticks
            while True:
                ticks += 1
                await asyncio.sleep(0.001)

        t = asyncio.ensure_future(ticker())
        out = await log.asubmit(directory)
        t.cancel()
        return out, ticks

    out, ticks = asyncio.run(main())
    assert out["verdict"] == "witnessed" and ticks > 0


def test_submit_refuses_a_journal_that_does_not_extend_the_witnessed_head(tmp_path, directory):
    p = str(tmp_path / "a.jsonl")
    log = wl.open(p)
    log.append_intent(b"one")
    log.submit(directory)
    log.close()
    # A different journal under the same witness state file.
    other = wl.open(str(tmp_path / "b.jsonl"))
    other.append_intent(b"different")
    with pytest.raises(RuntimeError, match="refusing to submit"):
        other.submit(directory, state_path=p + ".witnesses.json")


def test_in_memory_log_needs_state_path(directory):
    log = wl.WitnessLog.generate()
    log.append_intent(b"x")
    with pytest.raises(ValueError, match="state_path"):
        log.submit(directory)


@pytest.mark.skipif(sys.platform == "win32", reason="mode bits")
def test_bad_directory_values_raise(tmp_path):
    log = wl.open(str(tmp_path / "a.jsonl"))
    with pytest.raises(ValueError):
        log.submit({"witnesses": []}, want=0)
    with pytest.raises(ValueError):
        log.submit({"witnesses": []})


def test_canonical_json_fast_path_matches_the_full_encoder():
    """The ASCII/int fast path must be byte-identical to the RFC 8785
    encoder; the control characters, quotes, backslashes and nesting
    below are where json.dumps and JCS could plausibly disagree."""
    import witness_log
    from witness_log import _jcs

    def full(v):
        out = []
        _jcs(v, out, set(), 0)
        return "".join(out).encode("utf-8")

    cases = [
        {"b": 1, "a": [True, None, False, 0, -1, 2**53 - 1], "A": "x"},
        {"k": "quote \" backslash \\ nl \n tab \t ctl \x1f del \x7f"},
        {"k": "lone surrogate \ud800 falls back to the full encoder"},
        {"nested": [{"z": [], "y": {}}, [[[]]]], "": ""},
        {"ascii key": "é € 😀 literal utf-8 in values is fine"},
        [],
        {},
        "plain",
        12345,
    ]
    for v in cases:
        assert witness_log.canonical_json(v) == full(v), v
    # out of the fast path: floats, big ints, non-ASCII keys
    for v in [{"a": 1.5}, {"a": 2**53}, {"é": 1}, {"a": float("nan")}]:
        assert witness_log.canonical_json(v) == full(v) or v.get("a") != v.get("a")


def test_revoke_json_v1_and_rfc0005_index(tmp_path):
    """`revoke_json` signs SPEC §5 revocations; an index cut-off (RFC-0005)
    needs experimental=True and is enforced by `verify_dossier_json` when
    the verifier passes it, even if the dossier omits it."""
    import json

    import witness_log as wl

    log = wl.open(str(tmp_path / "a.jsonl"))
    for i in range(3):
        log.append_intent(b"x%d" % i)
    before = log.to_dossier_json()
    ident = log.identity_pubkey_hex()
    with pytest.raises(ValueError, match="experimental"):
        log.revoke_json("rotated", as_of_index=-1)
    rev = json.loads(log.revoke_json("rotated", as_of_index=-1, experimental=True))
    assert rev["as_of_index"] == 3 and rev["identity_pubkey"] == ident
    v1 = json.loads(log.revoke_json("rotated"))
    assert "as_of_index" not in v1
    rep = json.loads(wl.verify_dossier_json(before, 0.66, ident, None, None, json.dumps(rev)))
    assert rep["bindings_valid"] and rep["verdict"] == "unanchored"
    log.append_intent(b"after")
    after = log.to_dossier_json()
    rep = json.loads(wl.verify_dossier_json(after, 0.66, ident, None, None, json.dumps([rev])))
    assert not rep["bindings_valid"], rep
    log.close()
