"""``witness_log.profiles._disclose``: the Python recomputation of SPEC §8
``payload_hash`` against the conformance corpus, and a disclosure round
trip against a real journal's salt sidecar."""

from __future__ import annotations

import json
import os

import witness_log as wl
from witness_log.profiles import _disclose

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "..", "..", "..", "corpus", "11_payload_hash.json")


def test_payload_hash_matches_corpus_vector_11():
    with open(CORPUS, encoding="utf-8") as f:
        cases = json.load(f)["cases"]
    assert len(cases) >= 4
    for c in cases:
        got = _disclose.payload_hash_hex(bytes.fromhex(c["payload_hex"]), bytes.fromhex(c["salt_hex"]), c["leaf_index"])
        assert got == c["payload_hash"], c["name"]


def test_disclosure_round_trip_and_forget(tmp_path):
    path = str(tmp_path / "a.jsonl")
    log = wl.open(path)
    p0 = wl.canonical_json({"tool": "pay", "amount": 12})
    p1 = wl.canonical_json({"tool": "pay", "outcome": "ok"})
    log.append_intent(p0)
    log.append_result(p1)
    log.sync()
    leaves = json.loads(log.leaves_json())
    salts = _disclose.read_salts(path)
    assert set(salts) == {0, 1}

    d0 = _disclose.disclosure(leaves[0], p0, salts[0])
    assert d0["complete"] and d0["verified"] is True
    assert _disclose.check_disclosure(d0)
    # The disclosure is self-contained JSON a third party can re-check.
    assert _disclose.check_disclosure(json.loads(json.dumps(d0)))

    # Wrong payload or wrong salt does not verify.
    bad = dict(d0, payload=p1.decode())
    assert _disclose.check_disclosure(bad) is False
    bad = dict(d0, salt=salts[1])
    assert _disclose.check_disclosure(bad) is False

    # After forget the salt is gone from the sidecar: disclosure is incomplete.
    assert log.forget(0)
    log.sync()
    salts = _disclose.read_salts(path)
    assert 0 not in salts and 1 in salts
    d0b = _disclose.disclosure(leaves[0], p0, salts.get(0))
    assert d0b["complete"] is False and d0b["verified"] is None and "salt" not in d0b


def test_binary_payload_is_hex_encoded():
    leaf = {"index": 0, "payload_hash": "00" * 32}
    salt = "11" * 32
    payload = b"\xff\xfe\x00"
    d = _disclose.disclosure(leaf, payload, salt)
    assert d["payload_encoding"] == "hex" and d["payload"] == "fffe00"
    d["leaf"]["payload_hash"] = _disclose.payload_hash_hex(payload, bytes.fromhex(salt), 0)
    assert _disclose.check_disclosure(d)
