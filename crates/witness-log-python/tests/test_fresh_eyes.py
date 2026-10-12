"""Regressions for what the 0.3.5 fresh-eyes evaluation found in the
Python layer (hostile-input and integrator personas). Each test fails on
0.3.5."""

from __future__ import annotations

import json
import math
import time

import pytest

import witness_log as wl


def _verdict(log) -> str:
    return json.loads(wl.verify_dossier_json(log.to_dossier_json(), 0.66, log.identity_pubkey_hex()))["verdict"]


# --- @step must never break the agent's call path -----------------------


def test_step_returns_value_with_mixed_key_types():
    log = wl.WitnessLog.generate()

    @wl.step(log)
    def tool(x):
        return {1: "a", "b": 2, None: 3}

    assert tool(1) == {1: "a", "b": 2, None: 3}  # 0.3.5: TypeError after the tool ran
    assert log.tree_size() == 2


def test_step_runs_tool_with_self_referencing_arguments():
    log = wl.WitnessLog.generate()
    ran = []
    x: list = []
    x.append(x)

    @wl.step(log)
    def tool(arg):
        ran.append(True)
        return "ok"

    assert tool(x) == "ok"  # 0.3.5: ValueError("Circular reference") before the tool ran
    assert ran == [True]
    assert log.tree_size() == 2


def test_canonical_json_is_always_valid_json():
    for v in [float("nan"), {"k": float("inf")}, {(1, 2): 3}, {1: {2: [3, {None: 4}]}}]:
        out = wl.canonical_json(v)
        json.loads(out)  # 0.3.5 emitted bare NaN / Infinity for the first two
    assert wl.canonical_json({"b": 1, "a": [1, 2]}) == b'{"a":[1,2],"b":1}'
    assert math.isnan(float(json.loads(wl.canonical_json(float("nan"))))) is True


# --- inputs that used to be committed and could never verify or bind ----


def test_bad_anchor_url_is_refused_and_journal_stays_usable(tmp_path):
    p = str(tmp_path / "a.jsonl")
    log = wl.open(p)
    with pytest.raises(OSError, match="http:// or https://"):
        log.append_external_anchor("javascript:alert(1)", "{}")
    assert log.tree_size() == 0
    assert _verdict(log) == "unanchored"
    log.close()
    assert wl.open(p).tree_size() == 0  # 0.3.5: resume refused the journal


@pytest.mark.parametrize("bad", ["zz", "", "not-a-key", "g" * 64])
def test_counterparty_must_be_a_key(tmp_path, bad):
    log = wl.open(str(tmp_path / "h.jsonl"))
    with pytest.raises(OSError, match="64 hex"):
        log.append_handoff_sent(b"x", bad)
    with pytest.raises(OSError, match="64 hex"):
        log.append_authorization_event("granted_by_me", b"x", bad)
    assert log.tree_size() == 0


def test_uppercase_counterparty_binds(tmp_path):
    a = wl.open(str(tmp_path / "a.jsonl"))
    b = wl.open(str(tmp_path / "b.jsonl"))
    ia, ib = a.identity_pubkey_hex(), b.identity_pubkey_hex()
    sa = a.append_handoff_sent(b"task", ib.upper())
    sb = b.append_handoff_received(b"task", ia.upper())
    la = json.loads(a.leaves_json())[sa]
    lb = json.loads(b.leaves_json())[sb]
    assert wl.verify_handoff_binding(ia, json.dumps(la), ib, json.dumps(lb)) is None


def test_ttl_expiry_rotates_session_instead_of_diverging():
    log = wl.WitnessLog.resume_with_ttl(b"\x07" * 32, 1, 0)
    time.sleep(0.005)
    log.append_intent(b"x")
    assert _verdict(log) == "unanchored"  # 0.3.5: "diverged"


# --- directory entries -----------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        ("w", "Org", "http://x", "zz"),
        ("w", "", "http://x", "00" * 32),
        ("w", "  ", "http://x", "00" * 32),
        ("", "Org", "http://x", "00" * 32),
        ("w", "Org", "file:///etc/passwd", "00" * 32),
    ],
)
def test_witness_entry_rejects_malformed_fields(args):
    with pytest.raises(wl.MalformedError):
        wl.witness_entry_independent(*args)


def test_select_witnesses_accepts_a_bare_list():
    e = json.loads(wl.witness_entry_independent("w", "Org", "http://x", "00" * 32))
    assert json.loads(wl.select_witnesses(json.dumps([e]), "11" * 32, 1)) == [e]


# --- star import -----------------------------------------------------------


def test_star_import_does_not_shadow_builtin_open():
    ns: dict = {}
    exec("from witness_log import *", ns)
    assert "open" not in ns
    assert "step" in ns and "Witnesser" in ns
