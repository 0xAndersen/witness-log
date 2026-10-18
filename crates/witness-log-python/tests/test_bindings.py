"""Python binding test suite. Previously the only Python-side coverage was
an inline `python -c "..."` smoke test in CI, and witness-log-python
declares its own [workspace] so `cargo test --workspace` never touches it
either -- effectively zero real test coverage on this binding. See the
pre-launch review, finding 19.

Run with: pip install target/wheels/*.whl && pytest tests/
"""

import json
import os
import tempfile

import pytest
import witness_log


def test_core_log_roundtrip_and_continuity():
    log = witness_log.WitnessLog.generate()
    log.append_intent(b"pytest smoke")
    cp = log.checkpoint()
    # Must not raise.
    log.verify_continuity(cp)


def test_exception_hierarchy_is_not_valueerror():
    """The README used to claim verify_continuity raises ValueError. It
    raises SignatureError/ContinuityError, both subclassing WitnessLogError.
    `except ValueError:` around a verification call catches nothing and
    silently proceeds as if verification passed -- a live footgun in a
    security library. This test pins the REAL hierarchy so a regression
    here is caught immediately, not discovered by a downstream user.
    """
    log = witness_log.WitnessLog.generate()
    log.append_intent(b"pytest exception test")

    with pytest.raises(witness_log.WitnessLogError):
        log.verify_continuity("garbage")

    with pytest.raises(witness_log.MalformedError):
        log.verify_continuity("garbage")

    # The thing the old README claimed does NOT happen:
    with pytest.raises(witness_log.MalformedError):
        try:
            log.verify_continuity("garbage")
        except ValueError:
            pytest.fail("verify_continuity must never raise plain ValueError")


def test_malformed_dossier_raises_malformed_error_not_generic_exception():
    with pytest.raises(witness_log.MalformedError):
        witness_log.verify_dossier_json("not json at all", 0.66)


def test_verify_dossier_json_without_anchors_caps_at_unanchored():
    """Mirrors finding 02's fix on the Rust side: calling
    verify_dossier_json with no expected_identity_pubkey and no
    trusted_directory_json must never reach "witnessed", regardless of
    what the dossier itself claims about its own witnesses.
    """
    log = witness_log.WitnessLog.generate()
    log.append_intent(b"unanchored check")
    dossier_json = log.to_dossier_json()
    report = json.loads(witness_log.verify_dossier_json(dossier_json, 0.66))
    assert report["verdict"] != "witnessed"


def test_snapshot_roundtrip_preserves_root():
    log = witness_log.WitnessLog.generate()
    log.append_intent(b"snapshot roundtrip")
    path = os.path.join(tempfile.gettempdir(), f"pytest-witnesslog-snapshot-{os.getpid()}.json")
    try:
        log.save_snapshot(path)
        restored = witness_log.WitnessLog.load_snapshot(path)
        assert restored.root_hex() == log.root_hex()
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_snapshot_file_permissions_are_owner_only():
    """Real filesystem check, not just a Rust-side unit test: confirms
    the wheel actually built with the 0600 fix, not just that the Rust
    source contains it. See finding 09.
    """
    if os.name != "posix":
        pytest.skip("permission bits are POSIX-specific")
    log = witness_log.WitnessLog.generate()
    log.append_intent(b"permission check")
    path = os.path.join(tempfile.gettempdir(), f"pytest-witnesslog-perm-{os.getpid()}.json")
    try:
        log.save_snapshot(path)
        mode = os.stat(path).st_mode & 0o777
        assert mode == 0o600, f"snapshot must be 0600, got {oct(mode)}"
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_full_surface_journal_selection_witness_and_equivocation():
    """Every surface added to reach parity with Rust, exercised end to end
    from Python -- including a tlog-witness service refusing an
    equivocating log, which is the whole point of the project."""
    import tempfile, json, os
    import witness_log as wl

    # 1. Identity + journaled log with restart -- the restart-as-forgery fix, from Python
    seed = wl.WitnessLog.generate().identity_bytes()
    p = os.path.join(tempfile.gettempdir(), f"pye2e-{os.getpid()}.jsonl")
    log = wl.JournaledLog.create(p, seed)
    log.append_intent(b'{"tool":"transfer","usd":250}')
    log.append_result(b'{"status":"ok"}')
    log.sync(); del log
    log, dropped = wl.JournaledLog.resume(p)
    log.append_intent(b'{"tool":"notify"}')
    log.sync()
    assert dropped == 0 and log.tree_size() == 3
    d = json.loads(log.to_dossier_json())
    assert len(d["key_bindings"]) == 2, "both sessions' bindings must be present"
    r = json.loads(wl.verify_dossier_json(json.dumps(d), 0.0, expected_identity_pubkey=log.identity_pubkey_hex()))
    assert r["verdict"] != "diverged", f"restarted log must not be Diverged: {r['verdict']}"
    assert r["bindings_valid"] and r["identity_bound"]
    print("1. journaled restart verifies ✓ (verdict:", r["verdict"] + ")")

    # 2. Witness directory with honest constructors + diverse selection
    entries = [json.loads(wl.witness_entry_independent(f"w{i}", "bigco" if i < 6 else f"small-{i}", f"https://w{i}.x", "ab"*32 if i==0 else f"{i:02x}"*32, "aws")) for i in range(10)]
    entries.append(json.loads(wl.witness_entry_project_operated("boot", "https://b.x", "ff"*32, "fly.io")))
    assert entries[-1]["is_project_operated"] is True
    directory = {"witnesses": entries}
    picked = json.loads(wl.select_diverse_witnesses(json.dumps(directory), "99"*32, 5))
    ops = {e["operator_org"] for e in picked}
    assert len(picked) == len(ops), "one per operator"
    print(f"2. selection: {len(picked)} witnesses across {len(ops)} operators ✓")

    # 3. tlog-witness round trip: log -> witness service -> cosignature
    origin = "agents.example.com/py-agent"
    svc = wl.WitnessService.new("witness.example/py1", bytes(range(32)))
    svc.add_log(origin, log.c2sp_vkey(origin))
    note = log.sign_c2sp_checkpoint(origin)
    body = f"old 0\n\n{note}"
    status, resp = svc.handle_add_checkpoint(body, 1_700_000_000)
    assert status == 200, f"expected 200, got {status}: {resp}"
    assert resp.startswith("\u2014 witness.example/py1 "), resp
    print(f"3. tlog-witness cosigned (HTTP {status}) ✓")

    # 4. Equivocation refused by the witness -- the whole point
    log2 = wl.WitnessLog.resume(seed, 0)
    log2.append_intent(b"a DIFFERENT history")
    log2.append_intent(b"x"); log2.append_intent(b"y")
    forged = log2.sign_c2sp_checkpoint(origin)
    status, resp = svc.handle_add_checkpoint(f"old 3\n\n{forged}", 1_700_000_060)
    assert status == 422, f"equivocation must be refused with 422, got {status}: {resp}"
    print(f"4. equivocation refused (HTTP {status}) ✓")

    os.remove(p)




def test_python_agent_and_witnesses_reach_witnessed_and_refuse_forks(tmp_path):
    """End to end in Python only: three witnesses (one persistent), an
    agent submitting via add_checkpoint_body, a dossier built from the raw
    responses, and a growing fork refused -- including after the
    persistent witness restarts from its state file."""
    import json, os
    seed = os.urandom(32)
    agent = witness_log.JournaledLog.create(str(tmp_path / "a.jsonl"), seed)
    for i in range(7):
        agent.append_intent(b"e%d" % i)
    state = str(tmp_path / "w0.json")
    with pytest.raises(OSError):  # a missing state file is never silently "empty"
        witness_log.WitnessService.new("w0.test/x", os.urandom(32), state, True)
    witness_log.WitnessService.create_state(state)
    seeds = [os.urandom(32) for _ in range(3)]
    ws = [witness_log.WitnessService.new(f"w{i}.test/x", seeds[i], state if i == 0 else None, True) for i in range(3)]
    directory = {"witnesses": [json.loads(witness_log.witness_entry_independent(
        f"w{i}.test/x", f"Org {i}", "http://w", w.pubkey_hex(), f"cloud-{i}")) for i, w in enumerate(ws)]}
    responses = []
    for w in ws:
        st, ctype, body = w.handle_add_checkpoint_http(agent.add_checkpoint_body(0))
        assert st == 200 and body.endswith("\n")
        responses.append((w.pubkey_hex(), body))
    dossier, n = agent.dossier_from_responses(responses + [("00" * 32, "garbage")])
    assert n == 3
    rep = json.loads(witness_log.verify_dossier_json(dossier, 0.66, agent.identity_pubkey_hex(), json.dumps(directory)))
    assert rep["verdict"] == "witnessed"
    assert agent.canonical_origin() == "witness-log/" + agent.identity_pubkey_hex()

    # Growing fork from size 7 (not a power of two): must be refused.
    fork = witness_log.JournaledLog.create(str(tmp_path / "f.jsonl"), seed)
    for i in range(9):
        fork.append_intent(b"e%d" % i if i != 3 else b"rewritten")
    for w in ws:
        st, _, _ = w.handle_add_checkpoint_http(fork.add_checkpoint_body(7))
        assert st == 422
    # Refused, but a growing fork is not provable by one witness: no evidence.
    assert not os.path.exists(state + ".evidence.jsonl")
    # Same size, different root: two log signatures for size 7 -> evidence.
    same = witness_log.JournaledLog.create(str(tmp_path / "s.jsonl"), seed)
    for i in range(7):
        same.append_intent(b"e%d" % i if i != 1 else b"other")
    st, _, _ = ws[0].handle_add_checkpoint_http(same.add_checkpoint_body(7))
    assert st == 422
    ev = [json.loads(l) for l in open(state + ".evidence.jsonl")]
    assert len(ev) == 1 and ev[0]["kind"] == "equivocation"

    # One writer per state file.
    with pytest.raises(OSError):
        witness_log.WitnessService.new("w0.test/x", seeds[0], state, True)
    # Re-adding a known log never resets it.
    assert ws[0].add_log(agent.canonical_origin(), agent.c2sp_vkey(agent.canonical_origin())) is False
    with pytest.raises(witness_log.MalformedError):
        witness_log.WitnessService.new("bad name", seeds[0], None, True)

    # The persistent witness restarts from disk and still refuses the fork.
    del ws, w
    w0 = witness_log.WitnessService.new("w0.test/x", seeds[0], state, True)
    assert w0.log_count() == 1
    st, _, _ = w0.handle_add_checkpoint_http(fork.add_checkpoint_body(7))
    assert st == 422
    # A 409 tells a client with no memory where the witness is.
    st, ctype, body = w0.handle_add_checkpoint_http(agent.add_checkpoint_body(0))
    assert st == 409 and ctype == "text/x.tlog.size" and body == "7\n"


def test_python_layer_open_step_close_and_inclusion(tmp_path):
    """The conveniences on top of the core: open() creates then resumes
    the same identity, @step records intent + result (and errors), close()
    releases the journal lock even while closures still reference the
    log, and inclusion proofs verify offline."""
    import asyncio
    p = str(tmp_path / "agent.jsonl")
    log = witness_log.open(p)

    @witness_log.step(log)
    def add(a, b):
        return a + b

    @witness_log.step(log, name="explode")
    def explode():
        raise RuntimeError("boom")

    @witness_log.step(log)
    async def later(x):
        return x * 2

    assert add(2, 3) == 5
    with pytest.raises(RuntimeError):
        explode()
    assert asyncio.run(later(4)) == 8
    assert log.tree_size() == 6
    leaves = json.loads(log.leaves_json())
    assert [l["leaf_type"] for l in leaves] == [1, 2, 1, 2, 1, 2]

    ts, root, proof = log.inclusion_proof(3)
    lh = log.leaf_hash_hex(3)
    assert witness_log.verify_inclusion(lh, 3, ts, proof, root)
    assert not witness_log.verify_inclusion(lh, 4, ts, proof, root)
    assert not witness_log.verify_inclusion("nothex", 3, ts, proof, root)
    assert log.inclusion_proof(99) is None

    ident = log.identity_pubkey_hex()
    log.close()
    assert log.is_closed()
    with pytest.raises(OSError):
        log.tree_size()
    # Closures above still hold `log`; the lock must be free anyway.
    again = witness_log.open(p)
    assert again.tree_size() == 6 and again.identity_pubkey_hex() == ident
    again.close()

    with witness_log.open(str(tmp_path / "ctx.jsonl")) as c:
        c.append_intent(b"x")
    assert c.is_closed()

    # Explicit identity survives across paths.
    seed = os.urandom(32)
    a = witness_log.open(str(tmp_path / "a.jsonl"), seed)
    b = witness_log.open(str(tmp_path / "b.jsonl"), seed)
    assert a.identity_pubkey_hex() == b.identity_pubkey_hex()


def test_release_test_findings_resume_forget_stale_lock_threshold(tmp_path):
    wl = witness_log
    """Regressions for the 0.3.1 release test: redaction after a restart,
    automatic stale-lock recovery, and argument validation."""
    import os
    import subprocess
    import sys

    p = str(tmp_path / "agent.jsonl")
    seed = os.urandom(32)
    log = wl.JournaledLog.create(p, seed)
    log.append_intent(b"alice@example.com")
    log.append_result(b"")  # empty payloads are salted too
    log.sync()
    log.close()
    assert os.path.exists(p + ".salts")

    log, dropped = wl.JournaledLog.resume(p)
    assert dropped == 0
    assert log.can_forget(0) and log.can_forget(1)
    assert log.forget(0) is True, "pre-restart leaf must be forgettable"
    assert log.can_forget(0) is False
    assert log.forget(0) is False
    assert "\"i\":0," not in open(p + ".salts").read()
    log.close()

    # A process killed while holding the journal leaves a lock naming a
    # dead PID; resume must recover without force_unlock on Linux.
    if sys.platform.startswith("linux"):
        code = (
            "import witness_log, os, sys; "
            f"log = witness_log.JournaledLog.resume({p!r})[0]; "
            "log.append_intent(b'x'); log.sync(); os._exit(0)"
        )
        subprocess.run([sys.executable, "-c", code], check=True)
        assert os.path.exists(p + ".lock")
        log, _ = wl.JournaledLog.resume(p)
        assert log.tree_size() == 4
        log.close()
        assert not os.path.exists(p + ".lock")

    # Live lock is never stolen.
    held = wl.JournaledLog.resume(p)[0]
    with pytest.raises(OSError):
        wl.JournaledLog.resume(p)
    held.close()
    wl.JournaledLog.force_unlock(p)  # no-op when no lock exists

    log = wl.JournaledLog.resume(p)[0]
    dossier = log.to_dossier_json()
    ident = log.identity_pubkey_hex()
    log.close()
    for bad in (2.0, -1.0, float("nan")):
        with pytest.raises(ValueError):
            wl.verify_dossier_json(dossier, bad, ident)
    with pytest.raises(ValueError):
        wl.verify_dossier_json(dossier, 0.5, "nothex")
    report = json.loads(wl.verify_dossier_json(dossier, 0.5, ident))
    assert report["identity_pinned"] is True
    assert report["internally_consistent"] is True
    assert report["bindings_asserted"] is True
    assert report["verdict"] == "unanchored"


def test_sealed_journal_keeps_the_seed_off_disk(tmp_path):
    """An outside evaluation of 0.3.3 flagged the identity seed sitting in
    plaintext in the journal header. seal=True keeps it out: the header
    pins only the public key, and resume needs the seed back."""
    p = str(tmp_path / "sealed.jsonl")
    seed = os.urandom(32)
    with pytest.raises(ValueError):
        witness_log.open(p, seal=True)  # no seed, nothing to seal with
    log = witness_log.open(p, identity_seed=seed, seal=True)
    pk = log.identity_pubkey_hex()
    log.append_intent(b"x")
    log.sync()
    log.close()
    text = open(p).read()
    assert seed.hex() not in text and pk in text
    with pytest.raises(OSError, match="sealed"):
        witness_log.open(p)
    with pytest.raises(OSError):
        witness_log.JournaledLog.resume_with_identity(p, os.urandom(32))
    again = witness_log.open(p, identity_seed=seed, seal=True)
    assert again.identity_pubkey_hex() == pk and again.tree_size() == 1
    again.close()
    # An unsealed journal also accepts (and checks) a supplied seed.
    q = str(tmp_path / "plain.jsonl")
    plain = witness_log.open(q, identity_seed=seed)
    plain.close()
    assert witness_log.open(q, identity_seed=seed).identity_pubkey_hex() == pk


def test_cross_agent_leaves_and_bindings_from_python(tmp_path):
    """Handoff and authorization leaves were Rust-only (outside evaluation
    of 0.3.3); both sides and the after-the-fact binding now exist here."""
    a = witness_log.open(str(tmp_path / "a.jsonl"))
    b = witness_log.open(str(tmp_path / "b.jsonl"))
    ia, ib = a.identity_pubkey_hex(), b.identity_pubkey_hex()
    scope = witness_log.canonical_json({"mandate_hash": "ab" * 32, "max_usd": 500})
    la = a.append_authorization_event("granted_by_me", scope, ib)
    lb = b.append_authorization_event("granted_to_me", scope, ia)
    leaf_a = json.dumps(json.loads(a.leaves_json())[la])
    leaf_b = json.dumps(json.loads(b.leaves_json())[lb])
    assert witness_log.verify_authorization_binding(ia, leaf_a, ib, leaf_b) is True
    assert witness_log.authorization_binding_error(ia, leaf_a, ib, leaf_b) is None
    wider = b.append_authorization_event(
        "granted_to_me", witness_log.canonical_json({"mandate_hash": "ab" * 32, "max_usd": 5000}), ia
    )
    leaf_w = json.dumps(json.loads(b.leaves_json())[wider])
    assert witness_log.verify_authorization_binding(ia, leaf_a, ib, leaf_w) is False
    assert "scope hashes do not match" in witness_log.authorization_binding_error(ia, leaf_a, ib, leaf_w)
    with pytest.raises(ValueError):
        a.append_authorization_event("granted", scope, ib)

    state = witness_log.canonical_json({"task": "reconcile"})
    ha = a.append_handoff_sent(state, ib)
    hb = b.append_handoff_received(state, ia)
    sa = json.dumps(json.loads(a.leaves_json())[ha])
    sb = json.dumps(json.loads(b.leaves_json())[hb])
    assert witness_log.verify_handoff_binding(ia, sa, ib, sb) is True
    assert witness_log.handoff_binding_error(ia, sa, ib, sb) is None
    assert witness_log.verify_handoff_binding(ib, sb, ia, sa) is False  # roles swapped
    assert witness_log.handoff_binding_error(ib, sb, ia, sa)

    # An anchor's proof JSON is bound to its hash in the leaf.
    i = a.append_external_anchor("https://rekor.sigstore.dev/api/v1/log/entries/x", '{"logIndex":1}')
    leaf = json.loads(a.leaves_json())[i]
    assert leaf["leaf_type"] == 7 and len(leaf["anchor_proof_hash"]) == 64
    d = json.loads(a.to_dossier_json())
    d["leaves"][i]["anchor_proof_json"] = '{"logIndex":2}'
    r = json.loads(witness_log.verify_dossier_json(json.dumps(d), 0.66, ia))
    assert r["verdict"] == "invalid" and r["failures"]


def test_corpus_13_verdicts_known_heads_and_evidence():
    """RFC-0002 through the binding: known heads and equivocation evidence
    make a valid dossier "diverged"; a failed check is "invalid"."""
    import os

    path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "corpus", "13_verdicts.json")
    if not os.path.exists(path):
        import pytest

        pytest.skip("corpus not available")
    v = json.load(open(path))
    seen = set()
    for c in v["cases"]:
        r = json.loads(
            witness_log.verify_dossier_json(
                json.dumps(v["dossiers"][c["dossier"]]),
                c["threshold"],
                c["expected_identity"],
                json.dumps(v["trusted_directory"]) if c["trusted_directory"] else None,
                c["min_witnesses"],
                None,
                c["known_heads"],
                json.dumps([v["evidence"][k] for k in c["evidence"]]),
                c["subject_org"],
            )
        )
        e = c["expect"]
        assert r["verdict"] == e["verdict"], c["name"]
        assert r["split_view_unsafe"] == e["split_view_unsafe"], c["name"]
        assert bool(r["failures"]) == e["has_failures"], c["name"]
        assert len(r["contradictions"]) == e["contradictions"], c["name"]
        assert len(r["known_heads_unchecked"]) == e["known_heads_unchecked"], c["name"]
        assert (r["quorum"] or {}).get("distinct_independent_operators") == e["independent_operators"], c["name"]
        seen.add(r["verdict"])
    assert seen == {"witnessed", "consistent_unwitnessed", "unanchored", "diverged", "invalid"}
    # A malformed known head is the caller's error, not a verdict.
    import pytest

    with pytest.raises(ValueError):
        witness_log.verify_dossier_json(json.dumps(v["dossiers"]["full"]), 0.66, None, None, None, None, ["7"])


def test_corpus_14_fleet_anchor():
    """RFC-0001 (EXPERIMENTAL) through the binding: accept_fleet_anchor
    counts a fleet checkpoint's cosigners; without it the field is ignored
    and the report carries no witnessed_via."""
    path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "corpus", "14_fleet_anchor.json")
    if not os.path.exists(path):
        pytest.skip("corpus not available")
    v = json.load(open(path))
    for c in v["cases"]:
        r = json.loads(
            witness_log.verify_dossier_json(
                json.dumps(v["dossiers"][c["dossier"]]),
                c["threshold"],
                None,
                json.dumps(v["trusted_directory"]) if c["trusted_directory"] else None,
                c["min_witnesses"],
                subject_org=c["subject_org"],
                accept_fleet_anchor=c["accept_fleet_anchor"],
            )
        )
        e = c["expect"]
        assert r["verdict"] == e["verdict"], c["name"]
        assert r["split_view_unsafe"] == e["split_view_unsafe"], c["name"]
        assert (r["quorum"] or {}).get("valid_receipts") == e["valid_receipts"], c["name"]
        assert (r["quorum"] or {}).get("distinct_independent_operators") == e["independent_operators"], c["name"]
        assert (r.get("fleet_anchor") or {}).get("status") == e["fleet_anchor_status"], c["name"]
        assert (r.get("fleet_anchor") or {}).get("fleet_tree_size") == e["fleet_tree_size"], c["name"]
        if c["accept_fleet_anchor"]:
            assert r["witnessed_via"] == e["witnessed_via"], c["name"]
            assert r["witness_paths"] == e["witness_paths"], c["name"]
        else:
            assert "witnessed_via" not in r and "witness_paths" not in r, c["name"]


def test_sync_releases_the_gil_and_threads_share_a_log_safely(tmp_path):
    """0.5.0 (100,000-agent swarm: `Witnesser.request()` blocked >50 ms in
    0.8% of calls): `sync`, `forget`, `close` and `open` held the GIL across
    fsync, so one thread's sync stalled every Python thread in the process.
    They now release it. Measured on a two-core host with eight threads
    syncing: a 1 ms sleep loop went from a 44 ms median gap to 1.2 ms."""
    import threading
    import time

    stop = threading.Event()
    errors = []

    def syncer(i):
        try:
            log = witness_log.open(str(tmp_path / f"s{i}.jsonl"))
            while not stop.is_set():
                log.append_intent(b"x" * 200)
                log.sync()
            log.close()
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=syncer, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    gaps = []
    last = time.perf_counter()
    end = time.monotonic() + 2.0
    while time.monotonic() < end:
        time.sleep(0.001)
        now = time.perf_counter()
        gaps.append(now - last)
        last = now
    stop.set()
    for t in threads:
        t.join(30)
    assert not errors, errors
    gaps.sort()
    assert gaps[len(gaps) // 2] < 0.010, f"median gap {gaps[len(gaps) // 2] * 1000:.1f} ms: the GIL is held across fsync"

    # One log shared by threads that append, sync, read and forget at once:
    # no deadlock between the GIL and the log's own lock, nothing lost.
    shared = witness_log.open(str(tmp_path / "shared.jsonl"))
    n_per = 200

    def appender():
        for _ in range(n_per):
            shared.append_memory(b"m")

    def reader():
        for _ in range(n_per):
            shared.tree_size()
            shared.root_hex()

    def syncer_shared():
        for _ in range(20):
            shared.sync()

    workers = [threading.Thread(target=f) for f in (appender, appender, reader, syncer_shared, syncer_shared)]
    for t in workers:
        t.start()
    for t in workers:
        t.join(60)
        assert not t.is_alive(), "deadlock between the GIL and the journal lock"
    assert shared.tree_size() == 2 * n_per
    assert shared.forget(0) is True
    shared.close()
    again, _ = witness_log.JournaledLog.resume(str(tmp_path / "shared.jsonl"))
    assert again.tree_size() == 2 * n_per + 1
    again.close()


def test_corpus_15_evidence_known_heads_and_labels():
    """Security review of 0.5.0 (F1, F5, F10, F12) through the binding:
    evidence items as `witness serve` writes them, malformed ones refused,
    equivocation proofs at the signed-note edges, known heads past 2^53 or
    wrapped in Unicode White_Space or a BOM, and operator labels that
    differ only by Unicode whitespace or case. exit_code 2 means the
    inputs are refused with an exception, never a verdict."""
    import os

    import pytest

    path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "corpus", "15_evidence_and_args.json")
    if not os.path.exists(path):
        pytest.skip("corpus not available")
    v = json.load(open(path, encoding="utf-8"))
    seen = set()
    for c in v["cases"]:
        e = c["expect"]
        seen.add(e["exit_code"])
        args = (
            json.dumps(v["dossiers"][c["dossier"]]),
            c["threshold"],
            c["expected_identity"],
            json.dumps(v["directories"][c["directory"]]) if c["directory"] else None,
            c["min_witnesses"],
            None,
            c["known_heads"],
            json.dumps([v["evidence"][k] for k in c["evidence"]]),
            c["subject_org"],
        )
        if e["exit_code"] == 2:
            with pytest.raises((ValueError, witness_log.MalformedError)):
                witness_log.verify_dossier_json(*args)
            continue
        r = json.loads(witness_log.verify_dossier_json(*args))
        exit_code = 11 if r["split_view_unsafe"] and not c["allow_sub_majority"] else {
            "witnessed": 0, "consistent_unwitnessed": 10, "unanchored": 20, "diverged": 30, "invalid": 40,
        }[r["verdict"]]
        assert r["verdict"] == e["verdict"], c["name"]
        assert exit_code == e["exit_code"], c["name"]
        assert r["split_view_unsafe"] == e["split_view_unsafe"], c["name"]
        assert bool(r["failures"]) == e["has_failures"], c["name"]
        assert len(r["contradictions"]) == e["contradictions"], c["name"]
        assert len(r["known_heads_unchecked"]) == e["known_heads_unchecked"], c["name"]
        assert (r["quorum"] or {}).get("valid_receipts") == e["valid_receipts"], c["name"]
        assert (r["quorum"] or {}).get("distinct_independent_operators") == e["independent_operators"], c["name"]
    assert seen == {2, 10, 11, 20, 30, 40}


def _corpus_case(v, c, dossier_json):
    """One corpus 16/17 case through verify_dossier_json: the report, or
    None when the binding refuses the dossier (MalformedError)."""
    args = (
        dossier_json,
        c["threshold"],
        c["expected_identity"],
        json.dumps(v["directories"][c["directory"]]) if c["directory"] else None,
        c["min_witnesses"],
        None,
        c["known_heads"],
        json.dumps([v["evidence"][k] for k in c["evidence"]]),
        c["subject_org"],
    )
    if c["expect"].get("not_a_dossier"):
        import pytest

        with pytest.raises(witness_log.MalformedError):
            witness_log.verify_dossier_json(*args)
        return None
    r = json.loads(witness_log.verify_dossier_json(*args))
    e = c["expect"]
    exit_code = 11 if r["split_view_unsafe"] and not c["allow_sub_majority"] else {
        "witnessed": 0, "consistent_unwitnessed": 10, "unanchored": 20, "diverged": 30, "invalid": 40,
    }[r["verdict"]]
    assert r["verdict"] == e["verdict"], c["name"]
    assert exit_code == e["exit_code"], c["name"]
    assert r["internally_consistent"] == e["internally_consistent"], c["name"]
    assert bool(r["failures"]) == e["has_failures"], c["name"]
    assert len(r["contradictions"]) == e["contradictions"], c["name"]
    assert (r["quorum"] or {}).get("valid_receipts") == e["valid_receipts"], c["name"]
    return r


def test_corpus_16_strict_ed25519_and_17_dossier_parsing():
    """Outside review of 0.6.0 (H2, H3/M3, P3) through the binding:
    degenerate Ed25519 signatures in dossiers (16), and texts that are or
    are not dossiers, integers above 2^53 and hex case (17). A text the
    reference cannot read raises MalformedError, never a verdict."""
    import os

    import pytest

    root = os.path.join(os.path.dirname(__file__), "..", "..", "..", "corpus")
    paths = [os.path.join(root, n) for n in ("16_ed25519_strict.json", "17_dossier_parsing.json")]
    if not all(os.path.exists(p) for p in paths):
        pytest.skip("corpus not available")
    v16 = json.load(open(paths[0], encoding="utf-8"))
    for c in v16["cases"]:
        _corpus_case(v16, c, json.dumps(v16["dossiers"][c["dossier"]]))
    v17 = json.load(open(paths[1], encoding="utf-8"))
    v17["evidence"] = {}
    refused = 0
    for c in v17["cases"]:
        if _corpus_case(v17, c, c["dossier_json"]) is None:
            refused += 1
    assert refused >= 50


_WITNESS_SERVICE_THREADS = r"""
import base64, hashlib, os, sys, threading
from witness_log import _core

tmp = sys.argv[1]
state = os.path.join(tmp, "state.json")
_core.WitnessService.create_state(state)
svc = _core.WitnessService.new("w.example/w1", os.urandom(32), state, True, 1_000_000)
bodies = []
for i in range(int(sys.argv[2])):
    j = _core.JournaledLog.create_ephemeral(os.path.join(tmp, f"log{i}.jsonl"))
    j.append_intent(b"x")
    bodies.append(j.add_checkpoint_body(0))
    j.close()
stop = False

def handle():
    for b in bodies:
        st, _, _ = svc.handle_add_checkpoint_http(b)
        assert st == 200, st

def count():
    while not stop:
        svc.log_count()

def add():
    i = 0
    while not stop:
        name = f"other.example/log{i}"
        pk = os.urandom(32)
        kid = hashlib.sha256(name.encode() + b"\n" + bytes([1]) + pk).digest()[:4]
        assert svc.add_log(name, f"{name}+{kid.hex()}+{base64.b64encode(bytes([1]) + pk).decode()}")
        i += 1

workers = [threading.Thread(target=f, daemon=True) for f in (count, count, add)]
h = threading.Thread(target=handle, daemon=True)
for t in workers + [h]:
    t.start()
h.join()
stop = True
for t in workers:
    t.join()
print("ok", svc.log_count())
"""


def test_witness_service_threads_never_deadlock_between_the_gil_and_its_lock(tmp_path):
    """0.5.0 (security review 3, F3): `add_log` waited for the service's
    lock while holding the GIL, and `log_count` waited for the GIL while
    holding that lock (a lock taken with the GIL released was kept while
    the GIL was retaken). With `handle_add_checkpoint_http` holding the
    lock across an fsync, a witness serving `log_count` and POSTs while
    `add_log` ran froze the whole process within about a second. Run in a
    child process, since a deadlocked one cannot be interrupted."""
    import subprocess
    import sys

    try:
        r = subprocess.run(
            [sys.executable, "-c", _WITNESS_SERVICE_THREADS, str(tmp_path), "150"],
            capture_output=True,
            text=True,
            timeout=60,  # about 2 s when it works
        )
    except subprocess.TimeoutExpired:
        pytest.fail("WitnessService deadlocked: handle_add_checkpoint_http + log_count + add_log froze the process")
    assert r.returncode == 0, r.stderr[-2000:]
    assert r.stdout.startswith("ok "), r.stdout
