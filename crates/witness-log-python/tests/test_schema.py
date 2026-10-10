"""spec/dossier.schema.json must accept every dossier the code produces
and reject malformed ones. The schema is documentation that cannot
drift: this test runs in CI."""
import json
import os
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")
import witness_log  # noqa: E402

REPO = Path(__file__).resolve().parents[3]
SCHEMA = json.loads((REPO / "spec" / "dossier.schema.json").read_text())


def _validator():
    return jsonschema.Draft202012Validator(SCHEMA)


def test_schema_accepts_real_dossiers_and_rejects_bad_ones(tmp_path):
    v = _validator()
    sample = json.loads((REPO / "examples" / "sample-dossier.json").read_text())
    assert not list(v.iter_errors(sample))

    log = witness_log.open(str(tmp_path / "a.jsonl"))
    for i in range(3):
        log.append_intent(b"i%d" % i)
        log.append_result(b"r%d" % i)
    log.append_memory(b"m")
    log.forget(1)
    log.append_handoff_sent(b"s", "11" * 32)
    svc = witness_log.WitnessService.new("w/1", os.urandom(32), None, True)
    st, _ct, body = svc.handle_add_checkpoint_http(log.add_checkpoint_body(0))
    assert st == 200
    dossier, n = log.dossier_from_responses([(svc.pubkey_hex(), body)])
    assert n == 1
    doc = json.loads(dossier)
    assert not list(v.iter_errors(doc)), list(v.iter_errors(doc))[0].message

    bad = json.loads(dossier)
    bad["leaves"][0]["payload_hash"] = "not-hex"
    assert list(v.iter_errors(bad))
    bad = json.loads(dossier)
    bad["unexpected"] = 1
    assert list(v.iter_errors(bad))
    bad = json.loads(dossier)
    bad["checkpoint"]["sig_alg"] = "rsa"
    assert list(v.iter_errors(bad))


def test_schema_accepts_every_corpus_leaf():
    v = jsonschema.Draft202012Validator(
        {"$schema": SCHEMA["$schema"], "$defs": SCHEMA["$defs"], "$ref": "#/$defs/leaf"}
    )
    seen = 0

    def walk(x):
        nonlocal seen
        if isinstance(x, dict):
            if {"leaf_type", "payload_hash", "session_pubkey"} <= set(x):
                seen += 1
                assert not list(v.iter_errors(x)), list(v.iter_errors(x))[0].message
            for y in x.values():
                walk(y)
        elif isinstance(x, list):
            for y in x:
                walk(y)

    for f in sorted((REPO / "corpus").glob("*.json")):
        walk(json.loads(f.read_text()))
    assert seen >= 16  # every leaf fixture in the corpus
