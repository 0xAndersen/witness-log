"""Background witnessing (`witness_log.Witnesser`) against real witnesses
started from the built CLI: two healthy, one down, one behind a proxy
that answers 429 first."""

from __future__ import annotations

import asyncio
import json
import pathlib
import subprocess
import sys
import time

import pytest

import witness_log as wl

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from cli_witnesses import CliWitness, FlakyProxy, find_cli, free_port  # noqa: E402

CLI = find_cli()
pytestmark = pytest.mark.skipif(CLI is None, reason="witness-log CLI not built (cargo build --release -p witness-log-cli)")


@pytest.fixture(scope="module")
def witnesses(tmp_path_factory):
    root = tmp_path_factory.mktemp("witnesses")
    ws = [CliWitness(CLI, root, "w1", "Org One"), CliWitness(CLI, root, "w2", "Org Two")]
    yield ws
    for w in ws:
        w.stop()


def _verify(dossier: str, ident: str, directory: dict) -> str:
    return json.loads(wl.verify_dossier_json(dossier, 0.66, ident, json.dumps(directory), 2))["verdict"]


def test_background_witnessing_reaches_witnessed(tmp_path, witnesses):
    d = {"witnesses": [w.entry for w in witnesses]}
    p = str(tmp_path / "agent.jsonl")
    log = wl.open(p)

    @wl.step(log)
    def tool(x):
        return x * 2

    with wl.Witnesser(log, d, p) as w:
        for i in range(5):
            tool(i)
            w.request()  # never blocks
        assert w.flush(timeout=20), w.status()
        st = w.status()
        assert st.witnessed_size == log.tree_size() == 10
        assert st.cosignatures == 2 and st.last_error is None
        assert _verify(w.dossier(), log.identity_pubkey_hex(), d) == "witnessed"
    # State is the CLI's format and file, so the CLI can take over.
    state = json.loads(pathlib.Path(p + ".witnesses.json").read_text())
    assert state["cosigned_size"] == 10 and len(state["sizes"]) == 2
    (tmp_path / "d.json").write_text(json.dumps(d))
    out = subprocess.run(
        [CLI, "witness", "submit", p, "--directory", str(tmp_path / "d.json"), "--out", str(tmp_path / "o.json")],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    assert out.returncode == 0, out.stderr
    assert "cosigned size 10" in out.stderr


def test_head_is_pinned_while_the_agent_keeps_appending(tmp_path, witnesses):
    d = {"witnesses": [w.entry for w in witnesses]}
    p = str(tmp_path / "agent.jsonl")
    log = wl.open(p)
    for i in range(3):
        log.append_intent(b"%d" % i)
    r = wl.submit_round(log, d, p + ".witnesses.json")
    log.append_intent(b"later")  # the head moved on after the round
    assert r.tree_size == 3 and r.cosignatures == 2
    assert _verify(r.dossier_json, log.identity_pubkey_hex(), d) == "witnessed"
    assert len(json.loads(r.dossier_json)["leaves"]) == 3


def test_down_witness_and_429_witness(tmp_path, witnesses):
    w1, w2 = witnesses
    proxy = FlakyProxy(w2.url, n429=1)
    try:
        down = dict(w1.entry, name="down.test/w", operator_org="Org Down", url=f"http://127.0.0.1:{free_port()}",
                    pubkey="ab" * 32)
        flaky = dict(w2.entry, url=proxy.url)
        d = {"witnesses": [w1.entry, flaky, down]}
        p = str(tmp_path / "agent.jsonl")
        log = wl.open(p)
        log.append_intent(b"x")
        with wl.Witnesser(log, d, p, timeout=2) as w:
            t0 = time.monotonic()
            assert w.flush(timeout=20), w.status()
            assert time.monotonic() - t0 >= 1.0, "Retry-After: 1 must be honoured"
            st = w.status()
            assert st.cosignatures == 2
            by = {o["witness"]: o for o in st.last_outcomes}
            assert by["down.test/w"]["status"] == 0 and by["down.test/w"]["error"]
        assert proxy.hits == 2  # one 429, then the real request
        assert _verify(w.dossier(), log.identity_pubkey_hex(), d) == "witnessed"
    finally:
        proxy.stop()


def test_failures_never_raise_and_are_reported(tmp_path):
    down = [
        json.loads(wl.witness_entry_independent(f"d{i}.test/w", f"Org {i}", f"http://127.0.0.1:{free_port()}", f"{i:02x}" * 32))
        for i in (1, 2)
    ]
    p = str(tmp_path / "agent.jsonl")
    log = wl.open(p)
    log.append_intent(b"x")
    w = wl.Witnesser(log, {"witnesses": down}, p, timeout=1, backoff_initial=0.05, backoff_max=0.2)
    try:
        t0 = time.monotonic()
        w.request()
        assert time.monotonic() - t0 < 0.05, "request() must not block"
        assert w.flush(timeout=1.5) is False
        st = w.status()
        assert st.witnessed_size == 0 and st.failures_in_a_row >= 1
        assert st.last_error["kind"] == "no_cosignatures"
        assert all(o["status"] == 0 for o in st.last_error["outcomes"])
        log.close()  # even a closed journal must not raise into the caller
        w.request()
        assert w.flush(timeout=0.5) is False
        assert w.status().running
    finally:
        w.close()


def test_refuses_a_journal_that_contradicts_what_was_cosigned(tmp_path, witnesses):
    d = {"witnesses": [w.entry for w in witnesses]}
    a = str(tmp_path / "a.jsonl")
    log = wl.open(a)
    log.append_intent(b"common")
    log.sync()
    log.close()
    b = str(tmp_path / "b.jsonl")
    for suffix in ("", ".salts"):
        pathlib.Path(b + suffix).write_bytes(pathlib.Path(a + suffix).read_bytes())
    la = wl.open(a)
    la.append_intent(b"A")
    assert wl.submit_round(la, d, a + ".witnesses.json").cosignatures == 2
    lb = wl.open(b)
    lb.append_intent(b"B-fork")
    # The fork shares a's witness state (e.g. restored from a backup).
    pathlib.Path(b + ".witnesses.json").write_bytes(pathlib.Path(a + ".witnesses.json").read_bytes())
    r = wl.submit_round(lb, d, b + ".witnesses.json")
    assert r.refused and "equivocating" in r.refused and r.contacted == 0


def test_rejects_non_http_witness_urls(tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("TOP SECRET")
    e = json.loads(wl.witness_entry_independent("w.test/w", "Org", "http://x", "11" * 32))
    e["url"] = f"file://{secret}#"
    p = str(tmp_path / "agent.jsonl")
    log = wl.open(p)
    log.append_intent(b"x")
    r = wl.submit_round(log, {"witnesses": [e]}, p + ".witnesses.json")
    assert r.cosignatures == 0
    assert "TOP SECRET" not in json.dumps(r.outcomes)
    assert "http://" in r.outcomes[0]["error"]


def test_asyncio_flush(tmp_path, witnesses):
    d = {"witnesses": [w.entry for w in witnesses]}
    p = str(tmp_path / "agent.jsonl")
    log = wl.open(p)

    @wl.step(log)
    async def tool(x):
        await asyncio.sleep(0)
        return x

    async def main():
        with wl.Witnesser(log, d, p) as w:
            await tool(1)
            ok = await w.aflush(timeout=20)
            return ok, w.dossier()

    ok, dossier = asyncio.run(main())
    assert ok and _verify(dossier, log.identity_pubkey_hex(), d) == "witnessed"


def test_witnessed_dossier_json_rebuilds_the_last_round(tmp_path, witnesses):
    """`to_dossier_json()` never carries receipts (the Rust log does not hold
    them), so an export taken after `submit` was CONSISTENT-UNWITNESSED in
    the 100,000-agent run. The round's responses are now saved with the
    client state and `witnessed_dossier_json()` rebuilds the dossier."""
    d = {"witnesses": [w.entry for w in witnesses]}
    p = str(tmp_path / "agent.jsonl")
    log = wl.open(p)
    assert log.witnessed_dossier_json() is None
    log.append_intent(b"a")
    log.sync()
    r = log.submit(d, 2, 2)
    assert r["verdict"] == "witnessed"
    assert json.loads(log.to_dossier_json())["witness_receipts"] == []  # the plain export
    wd = log.witnessed_dossier_json()
    assert wd is not None and _verify(wd, log.identity_pubkey_hex(), d) == "witnessed"
    # The head moves on: the rebuilt dossier is still the witnessed one, at its size.
    log.append_intent(b"b")
    log.sync()
    wd2 = json.loads(log.witnessed_dossier_json())
    assert wd2["checkpoint"]["tree_size"] == 1 and _verify(json.dumps(wd2), log.identity_pubkey_hex(), d) == "witnessed"
    # A fresh open reads the same state from disk.
    log.close()
    again = wl.open(p)
    assert json.loads(again.witnessed_dossier_json())["checkpoint"]["tree_size"] == 1
    again.close()


def test_request_does_not_wait_behind_other_calls_on_the_log(tmp_path):
    """0.5.0 (100,000-agent swarm: 0.8% of `request()` calls took over
    50 ms): request() read the log's size and so queued behind whatever
    another thread was doing with the same log. It no longer touches the
    log; the background thread reads the size."""
    import threading

    log = wl.open(str(tmp_path / "busy.jsonl"))
    for i in range(20000):
        log.append_memory(b"%d" % i)
    w = wl.Witnesser(log, {"witnesses": []}, str(tmp_path / "busy.jsonl"), start=False)
    stop = threading.Event()

    def busy():
        while not stop.is_set():
            log.to_dossier_json()  # holds the log for tens of ms each time

    t = threading.Thread(target=busy)
    t.start()
    try:
        time.sleep(0.2)
        worst = 0.0
        for _ in range(50):
            t0 = time.perf_counter()
            w.request()
            worst = max(worst, time.perf_counter() - t0)
            time.sleep(0.005)
    finally:
        stop.set()
        t.join(30)
        log.close()
    assert worst < 0.02, f"request() blocked {worst * 1000:.0f} ms"
