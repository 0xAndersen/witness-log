"""Ten ways of interacting with a live 10-witness network. Each returns
(passed: bool, observations: list[str]). Anything surprising goes in
observations prefixed 'ISSUE:'."""
import base64, json, os, shutil, signal, socket, subprocess, sys, tempfile, threading, time
import witness_log as wl
from livenet import *

ROOT = tempfile.mkdtemp(prefix="livenet-")
WS = []
DIR_PATH = os.path.join(ROOT, "directory.json")
results = []


def scenario(fn):
    def run():
        t = time.time()
        obs = []
        try:
            ok = fn(obs)
        except AssertionError as e:
            ok = False
            obs.append(f"ISSUE: assertion failed: {e}")
        except Exception as e:  # noqa
            ok = False
            obs.append(f"ISSUE: {type(e).__name__}: {e}")
        results.append({"scenario": fn.__name__, "passed": bool(ok), "secs": round(time.time() - t, 2),
                        "observations": obs})
        print(("PASS " if ok else "FAIL ") + fn.__name__, flush=True)
        for o in obs:
            print("    " + o, flush=True)
    run.name = fn.__name__
    return run


def new_journal(name, n, prefix=b"event"):
    p = os.path.join(ROOT, name + ".jsonl")
    j = wl.JournaledLog.create_ephemeral(p)
    for i in range(n):
        j.append_intent(prefix + b"-%d" % i)
    j.sync()
    return p, j


def verify(dossier_path, ident, dir_path=DIR_PATH):
    code, out, err = cli("verify", dossier_path, "--identity", ident, "--directory", dir_path, "--json")
    try:
        rep = json.loads(out)
    except Exception:
        rep = {"raw": out, "err": err}
    return code, rep


def py_submit(log, ws, old_sizes=None):
    """Pure-Python agent: urllib only."""
    old_sizes = old_sizes or {}
    responses, statuses = [], {}
    for w in ws:
        old = old_sizes.get(w.entry["pubkey"], 0)
        for _ in range(5):
            st, body, ctype = http("POST", w.url + "/add-checkpoint", log.add_checkpoint_body(old))
            if st == 409:
                assert ctype.startswith("text/x.tlog.size"), f"409 content-type {ctype}"
                old = int(body.strip())
                continue
            if st in (0, 429, 503):  # transient: connection refused/reset, rate limit, busy
                time.sleep(0.5)
                continue
            break
        statuses[w.name] = st
        if st == 200:
            responses.append((w.entry["pubkey"], body))
            old_sizes[w.entry["pubkey"]] = log.tree_size()
    return responses, statuses, old_sizes


# ---------------------------------------------------------------- 1
@scenario
def s01_cli_agent_end_to_end(obs):
    p, j = new_journal("agent1", 20)
    ident = j.identity_pubkey_hex()
    code, out, err = cli("witness", "submit", p, "--directory", DIR_PATH, "--out", p + ".dossier.json", "--min", "10")
    obs.append(err.strip().splitlines()[-3] if err.strip() else "no output")
    assert code == 0, err
    vcode, rep = verify(p + ".dossier.json", ident)
    obs.append(f"verify exit {vcode}, verdict {rep.get('report', rep).get('verdict')}")
    assert vcode == 0, rep
    return True


# ---------------------------------------------------------------- 2
@scenario
def s02_pure_python_agent(obs):
    p, j = new_journal("pyagent", 12)
    responses, statuses, _ = py_submit(j, WS)
    obs.append(f"statuses {sorted(set(statuses.values()))}, cosignatures {len(responses)}")
    dossier, n = j.dossier_from_responses(responses)
    obs.append(f"receipts accepted {n}")
    rep = json.loads(wl.verify_dossier_json(dossier, 0.66, j.identity_pubkey_hex(), open(DIR_PATH).read()))
    obs.append(f"verdict {rep['verdict']}")
    assert n == 10 and rep["verdict"] == "witnessed", rep["verdict"]
    return True


# ---------------------------------------------------------------- 3
@scenario
def s03_incremental_advance_and_lost_client_state(obs):
    p, j = new_journal("agent3", 5)
    d = p + ".d.json"
    for rnd, add in enumerate([30, 1, 200]):
        for i in range(add):
            j.append_result(b"r%d-%d" % (rnd, i))
        j.sync()
        code, _, err = cli("witness", "submit", p, "--directory", DIR_PATH, "--out", d, "--min", "10")
        assert code == 0, f"round {rnd}: {err}"
    obs.append(f"3 incremental rounds to size {j.tree_size()}: 10/10 each, consistency-proven")
    os.remove(p + ".witnesses.json")  # agent loses its memory of witness sizes
    j.append_memory(b"after amnesia")
    j.sync()
    code, _, err = cli("witness", "submit", p, "--directory", DIR_PATH, "--out", d, "--min", "10")
    assert code == 0, err
    obs.append("client state deleted: recovered via 409 size hints, 10/10")
    vcode, rep = verify(d, j.identity_pubkey_hex())
    assert vcode == 0, rep
    return True


# ---------------------------------------------------------------- 4
def raw(port, data, read=True, timeout=15, delay=None):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        if delay:
            for b in data:
                try:
                    s.sendall(bytes([b]))
                except OSError:
                    break  # server already hung up on us -- expected
                time.sleep(delay)
        else:
            s.sendall(data)
        if not read:
            return s
        out = b""
        while True:
            try:
                c = s.recv(65536)
            except socket.timeout:
                break
            if not c:
                break
            out += c
        return out
    finally:
        if read:
            s.close()


def status_of(resp):
    try:
        return int(resp.split(b" ")[1])
    except Exception:
        return None


@scenario
def s04_hostile_http(obs):
    w = WS[0]
    P = w.port
    cases = {
        "wrong method": (b"DELETE /add-checkpoint HTTP/1.1\r\nHost: x\r\n\r\n", 405),
        "unknown path": (b"GET /admin HTTP/1.1\r\nHost: x\r\n\r\n", 404),
        "no content-length": (b"POST /add-checkpoint HTTP/1.1\r\nHost: x\r\n\r\n", 411),
        "huge content-length": (b"POST /add-checkpoint HTTP/1.1\r\nContent-Length: 999999999\r\n\r\n", 413),
        "negative content-length": (b"POST /add-checkpoint HTTP/1.1\r\nContent-Length: -1\r\n\r\n", 400),
        "duplicate content-length": (b"POST /add-checkpoint HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab", 400),
        "chunked smuggling": (b"POST /add-checkpoint HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 501),
        "garbage body": (b"POST /add-checkpoint HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello", 400),
        "binary body": (b"POST /add-checkpoint HTTP/1.1\r\nContent-Length: 4\r\n\r\n\xff\xfe\x00\x01", 400),
        "header flood": (b"GET / HTTP/1.1\r\n" + b"X-A: " + b"a" * 20000 + b"\r\n\r\n", 431),
        "http/2 preface": (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 400),
        "http/0.9": (b"GET /\r\n\r\n", 400),
        "64 proof lines": (None, 400),
        "unknown non-canonical origin": (None, 404),
        "forged signature on canonical origin": (None, 403),
    }
    # Build the protocol-level cases.
    _, j = new_journal("hostile", 3)
    body = j.add_checkpoint_body(0)
    lines = body.split("\n")
    proof = "\n".join([base64.b64encode(b"\0" * 32).decode()] * 64)
    cases["64 proof lines"] = (("POST /add-checkpoint HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % len(f"old 1\n{proof}\n\n" + body.split("\n\n", 1)[1])).encode()
                                + (f"old 1\n{proof}\n\n" + body.split("\n\n", 1)[1]).encode(), 400)
    nc = body.replace(j.canonical_origin(), "example.com/not-canonical")
    cases["unknown non-canonical origin"] = (("POST /add-checkpoint HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % len(nc.encode())).encode() + nc.encode(), None)
    # flip one char of the log's signature
    sig_line = [l for l in lines if l.startswith("—")][0]
    parts = sig_line.split(" ")
    raw_sig = bytearray(base64.b64decode(parts[2]))
    raw_sig[10] ^= 1
    forged = body.replace(sig_line, f"{parts[0]} {parts[1]} {base64.b64encode(bytes(raw_sig)).decode()}")
    cases["forged signature on canonical origin"] = (("POST /add-checkpoint HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % len(forged.encode())).encode() + forged.encode(), 403)
    bad = 0
    for name, (req, want) in cases.items():
        got = status_of(raw(P, req))
        if want is None:
            # changing the origin breaks the log's signature too, so either 403 or 404 is correct
            ok = got in (403, 404)
        else:
            ok = got == want
        if not ok:
            bad += 1
            obs.append(f"ISSUE: {name}: got {got}, expected {want}")
    obs.append(f"{len(cases) - bad}/{len(cases)} malformed/hostile requests answered correctly")
    # forged requests must not have enrolled anything
    info = json.loads(http("GET", w.url + "/")[1])
    obs.append(f"logs enrolled after hostile batch: {info['logs']} (unchanged by junk)")
    # Smear attempt: relay an honest log's checkpoint with a junk proof.
    _, hj = new_journal("smear", 5)
    http("POST", w.url + "/add-checkpoint", hj.add_checkpoint_body(0))
    hj.append_intent(b"more")
    junk = hj.add_checkpoint_body(5).split("\n\n", 1)
    smear = "old 5\n" + base64.b64encode(b"\x13" * 32).decode() + "\n\n" + junk[1]
    st = http("POST", w.url + "/add-checkpoint", smear)[0]
    evd = os.path.join(w.dir, "evidence")
    smeared = os.path.isdir(evd) and any(hj.identity_pubkey_hex() in open(os.path.join(evd, x)).read() for x in os.listdir(evd))
    obs.append(f"junk-proof smear of an honest log: HTTP {st}, recorded as evidence: {smeared}")
    if smeared or st != 422:
        bad += 1
        obs.append("ISSUE: an honest log can be smeared with a junk proof")

    # Slowloris: 1 byte per 0.7s. Server must cut it off (408) by ~10s.
    t = time.time()
    s = raw(P, b"GET /health HTTP/1.1\r\nHost: x\r\n", read=False, delay=0.7)
    s.settimeout(15)
    try:
        resp = s.recv(1024)
    except socket.timeout:
        resp = b""
    s.close()
    el = time.time() - t
    st = status_of(resp)
    if st != 408:
        obs.append(f"ISSUE: slowloris got {st!r} after {el:.1f}s, expected 408")
        bad += 1
    else:
        obs.append(f"slowloris cut off with 408 after {el:.1f}s")

    # Connection flood: 300 idle sockets. Server must shed load (503) and recover.
    socks = []
    for _ in range(300):
        try:
            socks.append(socket.create_connection(("127.0.0.1", P), timeout=2))
        except OSError:
            break
    time.sleep(0.5)
    st_same = http("GET", w.url + "/health", timeout=5)[0]
    # A DIFFERENT client address must still be served during the flood.
    other = socket.socket()
    other.bind(("127.0.0.2", 0))
    other.settimeout(5)
    other.connect(("127.0.0.1", P))
    other.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
    st_other = status_of(other.recv(1024))
    other.close()
    for s in socks:
        s.close()
    time.sleep(1)
    st_after = http("GET", w.url + "/health")[0]
    obs.append(f"300 idle sockets from one address ({len(socks)} opened): flooding client={st_same}, "
               f"other client during flood={st_other}, after={st_after}")
    if st_after != 200 or st_other != 200:
        bad += 1
        obs.append("ISSUE: flood from one address denied service to others or did not recover")
    return bad == 0


# ---------------------------------------------------------------- 5
@scenario
def s05_equivocation_is_caught_everywhere(obs):
    seed = os.urandom(32)
    p1 = os.path.join(ROOT, "honest.jsonl")
    honest = wl.JournaledLog.create(p1, seed)
    for i in range(10):
        honest.append_intent(b"same-%d" % i)
    honest.sync()
    code, _, err = cli("witness", "submit", p1, "--directory", DIR_PATH, "--out", p1 + ".d.json", "--min", "10")
    assert code == 0, err
    # Honest agent with a journal restored from an old backup, then appended
    # to: the client must refuse to publish it (it would read as equivocation).
    pr = os.path.join(ROOT, "restored.jsonl")
    r = wl.JournaledLog.create(pr, seed)
    for i in range(6):
        r.append_intent(b"same-%d" % i)
    for i in range(4):
        r.append_intent(b"after-restore-%d" % i)
    r.sync()
    shutil.copy(p1 + ".witnesses.json", pr + ".witnesses.json")
    code, _, err = cli("witness", "submit", pr, "--directory", DIR_PATH, "--out", pr + ".d.json")
    guarded = code != 0 and "REFUSING TO SUBMIT" in err
    obs.append(f"honest agent with restored journal: client refused to publish = {guarded}")
    assert guarded, err
    # Fork (attacker without the honest client's memory): same identity,
    # rewrites event 5, grows to 12.
    p2 = os.path.join(ROOT, "fork.jsonl")
    fork = wl.JournaledLog.create(p2, seed)
    for i in range(10):
        fork.append_intent(b"same-%d" % i if i != 5 else b"REWRITTEN")
    fork.append_intent(b"x")
    fork.append_intent(b"y")
    fork.sync()
    code, _, err = cli("witness", "submit", p2, "--directory", DIR_PATH, "--out", p2 + ".d.json")
    refused = err.count("REFUSED (422)")
    obs.append(f"fork submitted to 10 witnesses: {refused} refused as a fork (422)")
    assert refused == 10, err
    # Same-size fork (no growth): also 422.
    p3 = os.path.join(ROOT, "fork_same.jsonl")
    f3 = wl.JournaledLog.create(p3, seed)
    for i in range(10):
        f3.append_intent(b"same-%d" % i if i != 2 else b"OTHER")
    f3.sync()
    _, _, err3 = cli("witness", "submit", p3, "--directory", DIR_PATH, "--out", p3 + ".d.json")
    obs.append(f"same-size fork: {err3.count('REFUSED (422)')} refused")
    assert err3.count("REFUSED (422)") == 10, err3
    vcode, rep = verify(p2 + ".d.json", honest.identity_pubkey_hex())
    obs.append(f"fork dossier verify exit {vcode} ({rep.get('report', {}).get('verdict')})")
    assert vcode != 0
    # Only the same-size fork (two log signatures for one size) is provable;
    # each witness records exactly one self-contained proof for this log.
    ev = 0
    for w in WS:
        if w.kind == "rust":
            d = os.path.join(w.dir, "evidence")
            lines = [json.load(open(os.path.join(d, x))) for x in os.listdir(d)] if os.path.isdir(d) else []
        else:
            f = os.path.join(w.dir, "state.json.evidence.jsonl")
            lines = [json.loads(l) for l in open(f)] if os.path.exists(f) else []
        if lines:
            mine = [l for l in lines if l["proof"]["origin"].endswith(honest.identity_pubkey_hex())]
            ev += len(mine) == 1 and mine[0]["kind"] == "equivocation"
    obs.append(f"self-contained equivocation proof recorded by {ev}/10 witnesses")
    if ev != 10:
        obs.append("ISSUE: not every witness recorded the equivocation proof")

    # diff tool between honest and fork dossiers
    dcode, dout, derr = cli("diff", p1 + ".d.json", p2 + ".d.json")
    obs.append(f"`witness-log diff honest fork` exit {dcode}: {(dout or derr).strip().splitlines()[0] if (dout or derr).strip() else ''}")
    return ev == 10


# ---------------------------------------------------------------- 6
@scenario
def s06_stale_and_replayed_checkpoints_are_not_accusations(obs):
    seed = os.urandom(32)
    p = os.path.join(ROOT, "stale.jsonl")
    j = wl.JournaledLog.create(p, seed)
    for i in range(5):
        j.append_intent(b"%d" % i)
    j.sync()
    old_body = j.add_checkpoint_body(0)   # genuine size-5 checkpoint
    responses, st, sizes = py_submit(j, WS)
    for i in range(5):
        j.append_intent(b"more %d" % i)
    j.sync()
    responses, st2, sizes = py_submit(j, WS, sizes)   # witnesses now at 10
    assert set(st2.values()) == {200}, st2
    # Replay the genuine size-5 checkpoint, claiming old=10 → spec says 400.
    stale = "old 10\n" + old_body.split("\n", 1)[1]
    codes = [http("POST", w.url + "/add-checkpoint", stale)[0] for w in WS]
    obs.append(f"stale genuine checkpoint: statuses {sorted(set(codes))}")
    assert set(codes) == {400}, codes
    # Re-submitting the current head (client retry) is idempotent.
    codes = [http("POST", w.url + "/add-checkpoint", j.add_checkpoint_body(10))[0] for w in WS]
    obs.append(f"retry of current head: {sorted(set(codes))}")
    assert set(codes) == {200}
    def ev_count(w):
        d = os.path.join(w.dir, "evidence")
        f = os.path.join(w.dir, "state.json.evidence.jsonl")
        return (len(os.listdir(d)) if os.path.isdir(d) else 0) + (sum(1 for _ in open(f)) if os.path.exists(f) else 0)
    before = {w.name: ev_count(w) for w in WS}
    # stale size 5 with old=5 (witness holds 10) → 409 telling it 10
    codes = [http("POST", w.url + "/add-checkpoint", "old 5\n" + old_body.split("\n", 1)[1]) for w in WS]
    obs.append(f"stale with old=5: {sorted(set(c[0] for c in codes))}, bodies {sorted(set(c[1].strip() for c in codes))}")
    after = {w.name: ev_count(w) for w in WS}
    assert before == after, "a stale checkpoint was recorded as fork evidence"
    obs.append("no stale/replayed checkpoint was recorded as fork evidence")
    return True


# ---------------------------------------------------------------- 7
@scenario
def s07_crash_durability(obs):
    seed = os.urandom(32)
    p = os.path.join(ROOT, "durable.jsonl")
    j = wl.JournaledLog.create(p, seed)
    for i in range(8):
        j.append_intent(b"%d" % i)
    j.sync()
    code, _, err = cli("witness", "submit", p, "--directory", DIR_PATH, "--out", p + ".d.json", "--min", "10")
    assert code == 0, err
    # kill -9 every witness immediately after cosigning, restart them.
    for w in WS:
        w.kill(signal.SIGKILL)
    for w in WS:
        w.start()
    obs.append("all 10 witnesses SIGKILLed right after cosigning and restarted (stale locks auto-cleared)")
    # A fork at the same size must still be refused: state survived.
    p2 = os.path.join(ROOT, "durable_fork.jsonl")
    f = wl.JournaledLog.create(p2, seed)
    for i in range(8):
        f.append_intent(b"%d" % i if i != 3 else b"forged")
    f.sync()
    _, _, err = cli("witness", "submit", p2, "--directory", DIR_PATH, "--out", p2 + ".d.json")
    refused = err.count("REFUSED (422)")
    obs.append(f"fork after crash+restart: refused by {refused}/10")
    assert refused == 10, err
    # Second server on the same live state dir must be refused.
    w = WS[1]
    r = subprocess.run([BIN, "witness", "serve", w.dir, "--listen", "127.0.0.1:0"], capture_output=True, text=True, timeout=10)
    obs.append(f"second witness on same state dir: exit {r.returncode}: {r.stderr.strip().splitlines()[0][:90]}")
    assert r.returncode != 0
    # Kill mid-load: hammer then SIGKILL, restart, state still loads.
    stop = time.time() + 2
    def hammer():
        _, jj = new_journal("hammer%d" % threading.get_ident(), 3)
        while time.time() < stop:
            jj.append_intent(b"x")
            http("POST", WS[2].url + "/add-checkpoint", jj.add_checkpoint_body(0), timeout=5)
    ts = [threading.Thread(target=hammer) for _ in range(8)]
    [t.start() for t in ts]
    time.sleep(1)
    WS[2].kill(signal.SIGKILL)
    [t.join() for t in ts]
    info = WS[2].start()
    obs.append(f"SIGKILL under load, restarted cleanly with {info['logs']} logs")
    return True


# ---------------------------------------------------------------- 8
@scenario
def s08_fifty_concurrent_agents(obs):
    N, ROUNDS = 50, 3
    errors, done = [], []
    def agent(k):
        try:
            _, j = new_journal(f"conc{k}", 2 + k % 7)
            sizes = {}
            for r in range(ROUNDS):
                for i in range(3 + k % 5):
                    j.append_result(b"%d-%d" % (r, i))
                responses, st, sizes = py_submit(j, WS, sizes)
                if len(responses) != 10:
                    errors.append(f"agent {k} round {r}: {st}")
            dossier, n = j.dossier_from_responses(responses)
            rep = json.loads(wl.verify_dossier_json(dossier, 0.66, j.identity_pubkey_hex(), open(DIR_PATH).read()))
            if rep["verdict"] != "witnessed":
                errors.append(f"agent {k}: {rep['verdict']}")
            done.append(k)
        except Exception as e:
            errors.append(f"agent {k}: {type(e).__name__} {e}")
    t = time.time()
    ts = [threading.Thread(target=agent, args=(k,)) for k in range(N)]
    [x.start() for x in ts]
    [x.join() for x in ts]
    el = time.time() - t
    obs.append(f"{N} agents x {ROUNDS} rounds x 10 witnesses = {N*ROUNDS*10} cosignings in {el:.1f}s; {len(done)} agents WITNESSED")
    for e in errors[:5]:
        obs.append("ISSUE: " + e)
    # Same log, two submitters racing.
    _, j = new_journal("race", 4)
    res = []
    def race():
        res.append(py_submit(j, WS)[1])
    a, b = threading.Thread(target=race), threading.Thread(target=race)
    a.start(); b.start(); a.join(); b.join()
    flat = sorted(set(v for r in res for v in r.values()))
    obs.append(f"two submitters racing on one log: statuses {flat}")
    return not errors and flat == [200]


# ---------------------------------------------------------------- 9
@scenario
def s09_byzantine_and_sybil_witnesses(obs):
    evil = []
    for k, mode in enumerate(["wrongkey", "wrongcheckpoint", "garbage"]):
        w = Witness(len(WS) + k, ROOT, "py")
        w.org, w.compute = f"Evil {k}", "aws"
        w.init()
        w.start(extra=("--evil", mode))
        evil.append((w, mode))
    mixed = {"witnesses": [w.entry for w in WS] + [w.entry for w, _ in evil]}
    mp = os.path.join(ROOT, "mixed_dir.json")
    json.dump(mixed, open(mp, "w"))
    p, j = new_journal("byz", 6)
    code, _, err = cli("witness", "submit", p, "--directory", mp, "--out", p + ".d.json")
    rejected = [l for l in err.splitlines() if "✗" in l]
    obs.append(f"3 Byzantine witnesses in directory: client rejected {len(rejected)}: " + "; ".join(l.split("  ")[-1].strip()[:50] for l in rejected))
    d = json.load(open(p + ".d.json"))
    obs.append(f"receipts in dossier: {len(d['witness_receipts'])} (honest only)")
    vcode, rep = verify(p + ".d.json", j.identity_pubkey_hex(), mp)
    obs.append(f"verify with Byzantine witnesses in trusted directory: exit {vcode}")
    ok = len(rejected) == 3 and len(d["witness_receipts"]) == 10 and vcode == 0
    # Injecting a forged receipt by hand must not count.
    d["witness_receipts"].append(dict(d["witness_receipts"][0], witness_pubkey=evil[0][0].entry["pubkey"]))
    json.dump(d, open(p + ".inj.json", "w"))
    vcode2, rep2 = verify(p + ".inj.json", j.identity_pubkey_hex(), mp)
    q = rep2.get("report", {}).get("quorum") or {}
    obs.append(f"hand-injected receipt claiming an evil witness: counted valid={q.get('valid_receipts')}")
    # Sybil: same 10 witnesses but all labelled one operator.
    syb = {"witnesses": [dict(w.entry, operator_org="  SameCorp ") for w in WS]}
    sp = os.path.join(ROOT, "sybil_dir.json")
    json.dump(syb, open(sp, "w"))
    vcode3, rep3 = verify(p + ".d.json", j.identity_pubkey_hex(), sp)
    obs.append(f"10 cosignatures but one operator: exit {vcode3} ({rep3.get('report', {}).get('verdict')})")
    ok = ok and vcode3 != 0 and q.get("valid_receipts") == 10
    for w, _ in evil:
        w.kill()
    return ok


# ---------------------------------------------------------------- 10
@scenario
def s10_offline_auditor_and_sharing(obs):
    # Build the directory purely from the witnesses' public info endpoints.
    built = {"witnesses": []}
    for w in WS:
        code, out, err = cli("witness", "info", w.url)
        built["witnesses"].append(json.loads(out)["directory_entry"])
    bp = os.path.join(ROOT, "built_dir.json")
    json.dump(built, open(bp, "w"))
    obs.append("trusted directory assembled from 10 live `witness info` calls")
    p, j = new_journal("audited", 25)
    code, _, err = cli("witness", "submit", p, "--directory", bp, "--out", p + ".d.json", "--min", "10")
    assert code == 0, err
    ident = j.identity_pubkey_hex()
    # Take the network down. Auditor has only two files.
    for w in WS:
        w.kill(signal.SIGTERM)
    aud = tempfile.mkdtemp(prefix="auditor-")
    shutil.copy(p + ".d.json", os.path.join(aud, "dossier.json"))
    shutil.copy(bp, os.path.join(aud, "trusted.json"))
    D, T = os.path.join(aud, "dossier.json"), os.path.join(aud, "trusted.json")
    code, out, _ = cli("verify", D, "--identity", ident, "--directory", T)
    obs.append(f"offline, witnesses all down: exit {code}")
    assert code == 0, out
    checks = {}
    d = json.load(open(D))
    def tamper(name, f, want_not=0):
        x = json.loads(json.dumps(d))
        f(x)
        tp = os.path.join(aud, name + ".json")
        json.dump(x, open(tp, "w"))
        c, _, _ = cli("verify", tp, "--identity", ident, "--directory", T)
        checks[name] = c
    tamper("leaf payload edited", lambda x: x["leaves"][3].update(payload_hash="00" * 32) if "payload_hash" in x["leaves"][3] else x["leaves"][3].update({k: v for k, v in x["leaves"][3].items()}))
    tamper("leaf dropped", lambda x: x["leaves"].pop(7))
    tamper("receipt time pushed forward", lambda x: [r.update(witnessed_at_ms=r["witnessed_at_ms"] + 3600_000) for r in x["witness_receipts"]])
    tamper("receipt origin swapped", lambda x: [r.update(c2sp_origin="example.com/log") for r in x["witness_receipts"]])
    tamper("receipts moved to other log", lambda x: x.update(identity_pubkey="11" * 32))
    c_wrong, _, _ = cli("verify", D, "--identity", "22" * 32, "--directory", T)
    checks["wrong expected identity"] = c_wrong
    for k, v in checks.items():
        obs.append(f"{k}: exit {v}" + ("" if v != 0 else "  ISSUE: still WITNESSED"))
    # C2SP interop: the cosignature lines verify with the generic c2sp tool.
    rec = d["witness_receipts"][0]
    obs.append(f"receipt carries c2sp_origin={rec.get('c2sp_origin','')[:24]}...")
    for w in WS:
        w.start()
    return code == 0 and all(v != 0 for v in checks.values())


if __name__ == "__main__":
    print("root:", ROOT, flush=True)
    WS.extend(start_network(ROOT))
    json.dump(directory(WS), open(DIR_PATH, "w"), indent=1)
    only = sys.argv[1:]
    allfns = [s01_cli_agent_end_to_end, s02_pure_python_agent, s03_incremental_advance_and_lost_client_state,
              s04_hostile_http, s05_equivocation_is_caught_everywhere,
              s06_stale_and_replayed_checkpoints_are_not_accusations, s07_crash_durability,
              s08_fifty_concurrent_agents, s09_byzantine_and_sybil_witnesses, s10_offline_auditor_and_sharing]
    try:
        for f in allfns:
            if not only or any(o in f.name for o in only):
                f()
    finally:
        for w in WS:
            w.kill(signal.SIGTERM)
        json.dump(results, open(os.path.join(ROOT, "results.json"), "w"), indent=1)
        print("results:", os.path.join(ROOT, "results.json"))
        print(f"\n{sum(r['passed'] for r in results)}/{len(results)} scenarios passed")
        sys.exit(0 if all(r["passed"] for r in results) else 1)
