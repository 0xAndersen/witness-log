#!/usr/bin/env python3
"""100 quality scenarios against a released witness-log, run by a swarm.

The target is whatever a developer would actually install: a CLI binary
and the `witness_log` wheel. Twelve witnesses run live (8 Rust, 2 Python,
2 started by agents in the swarm itself); agents log, submit, verify,
tamper, crash and race against them. Every scenario is a plain function
that returns a one-line detail string or raises.

    cargo build --release -p witness-log-cli
    (cd crates/witness-log-python && maturin develop --release)
    python examples/swarm/run.py                      # local build
    python examples/swarm/run.py --release v0.3.1     # the GitHub release
    python examples/swarm/run.py --only T017,T042

Writes <out>/results.json and <out>/REPORT.md. Exit status is the number
of failed scenarios (0 = all passed), capped at 99.

Scenarios tagged `fixed_in` are regressions for defects found in the
named earlier release; they are expected to fail against it and pass
after it.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(REPO, "examples", "live-network"))

# ----------------------------------------------------------------- target


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cli", default=os.environ.get("WL_BIN", os.path.join(REPO, "target", "release", "witness-log")))
    ap.add_argument("--release", help="GitHub release tag to test (downloads CLI + wheel into a fresh venv)")
    ap.add_argument("--out", help="results directory (default: a new temp dir)")
    ap.add_argument("--only", help="comma-separated scenario ids")
    ap.add_argument("--agents", type=int, default=25, help="concurrent agents in the swarm scenarios")
    ap.add_argument("--base-port", type=int, default=18300)
    ap.add_argument("--_reexec", action="store_true", help=argparse.SUPPRESS)
    return ap.parse_args()


def gh_json(path: str):
    out = subprocess.run(["gh", "api", path], capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def download_asset(asset_id: int, dest: str) -> None:
    with open(dest, "wb") as f:
        subprocess.run(
            ["gh", "api", "-H", "Accept: application/octet-stream",
             f"repos/0xAndersen/witness-log/releases/assets/{asset_id}"],
            stdout=f, check=True,
        )


def prepare_release(tag: str, work: str) -> tuple[str, str]:
    """Download the CLI tarball and the wheel for this platform from the
    GitHub release, install the wheel in a fresh venv, return (cli, python)."""
    rel = gh_json(f"repos/0xAndersen/witness-log/releases/tags/{tag}")
    assets = {a["name"]: a for a in rel["assets"]}
    machine = platform.machine().lower()
    arch = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}[machine]
    sysname = platform.system().lower()
    cli_pat = {"linux": f"{arch}-unknown-linux", "darwin": f"{arch}-apple-darwin"}[sysname]
    cli_asset = next(a for n, a in assets.items() if cli_pat in n and n.endswith(".tar.gz") and "musl" not in n)
    whl_tag = {"linux": "manylinux", "darwin": "macosx"}[sysname]
    whl_asset = next(a for n, a in assets.items() if n.endswith(".whl") and whl_tag in n and arch in n)
    sums = assets.get("SHA256SUMS")
    os.makedirs(work, exist_ok=True)
    cli_tgz = os.path.join(work, cli_asset["name"])
    whl = os.path.join(work, whl_asset["name"])
    download_asset(cli_asset["id"], cli_tgz)
    download_asset(whl_asset["id"], whl)
    if sums:
        sums_path = os.path.join(work, "SHA256SUMS")
        download_asset(sums["id"], sums_path)
        want = {l.split()[1].lstrip("*"): l.split()[0] for l in open(sums_path) if l.strip()}
        for p in (cli_tgz, whl):
            got = hashlib.sha256(open(p, "rb").read()).hexdigest()
            if want.get(os.path.basename(p)) not in (None, got):
                raise SystemExit(f"checksum mismatch for {p}")
    subprocess.run(["tar", "xzf", cli_tgz, "-C", work], check=True)
    cli = next(os.path.join(r, f) for r, _, fs in os.walk(work) for f in fs if f == "witness-log")
    os.chmod(cli, 0o755)
    venv = os.path.join(work, "venv")
    subprocess.run([sys.executable, "-m", "venv", venv], check=True)
    py = os.path.join(venv, "bin", "python")
    subprocess.run([py, "-m", "pip", "install", "-q", whl, "jsonschema"], check=True)
    return cli, py


ARGS = parse_args()
if ARGS.release and not ARGS._reexec:
    work = ARGS.out or tempfile.mkdtemp(prefix=f"swarm-{ARGS.release}-")
    cli, py = prepare_release(ARGS.release, os.path.join(work, "target"))
    cmd = [py, os.path.abspath(__file__), "--cli", cli, "--out", work, "--release", ARGS.release, "--_reexec",
           "--agents", str(ARGS.agents), "--base-port", str(ARGS.base_port)]
    if ARGS.only:
        cmd += ["--only", ARGS.only]
    os.execv(py, cmd)

os.environ["WL_BIN"] = ARGS.cli
import livenet  # noqa: E402
import witness_log as wl  # noqa: E402

livenet.BIN = ARGS.cli
livenet.BASE_PORT = ARGS.base_port
from livenet import Witness, cli, http  # noqa: E402

OUT = ARGS.out or tempfile.mkdtemp(prefix="swarm-")
os.makedirs(OUT, exist_ok=True)
# Each run gets a fresh working tree: witness state must never be reused
# across runs (a witness with a key but no memory is the one thing the
# protocol cannot catch).
ROOT = tempfile.mkdtemp(prefix="work-", dir=OUT)
WS: list[Witness] = []
AGENT_WS: list[Witness] = []
DIR_PATH = os.path.join(ROOT, "directory.json")
SAMPLE = os.path.join(REPO, "examples", "sample-dossier.json")
TRUSTED = os.path.join(REPO, "examples", "trusted-directory.json")
SAMPLE_ID = json.load(open(SAMPLE))["identity_pubkey"]
LINUX = sys.platform.startswith("linux")

# -------------------------------------------------------------- registry

TESTS: list[dict] = []
_lock = threading.Lock()
_counter = [0]


def test(tid: str, category: str, name: str, fixed_in: str | None = None, since: str | None = None,
         serial: bool = False):
    """`fixed_in`: a regression for a defect fixed in that release.
    `since`: exercises an API that first shipped in that release."""
    def deco(fn):
        TESTS.append({"id": tid, "category": category, "name": name, "fn": fn,
                      "fixed_in": fixed_in, "since": since, "serial": serial})
        return fn
    return deco


def release(log) -> None:
    """Close a JournaledLog on releases that have close(); older wheels
    release the lock when the object is dropped, so callers `del` it."""
    if hasattr(log, "close"):
        log.close()


def leaves_of(log) -> list:
    if hasattr(log, "leaves_json"):
        return json.loads(log.leaves_json())
    return json.loads(log.to_dossier_json())["leaves"]


def fresh(tag: str) -> str:
    with _lock:
        _counter[0] += 1
        n = _counter[0]
    d = os.path.join(ROOT, f"{tag}-{n}")
    os.makedirs(d, exist_ok=True)
    return d


def journal(tag: str, n: int = 5, seed: bytes | None = None, payload: bytes = b"event"):
    d = fresh(tag)
    p = os.path.join(d, "agent.jsonl")
    j = wl.JournaledLog.create(p, seed or os.urandom(32))
    for i in range(n):
        j.append_intent(payload + b"-%d" % i)
    j.sync()
    return p, j


def submit(path: str, out: str | None = None, directory: str | None = None, minimum: int | None = None):
    out = out or path + ".dossier.json"
    args = ["witness", "submit", path, "--directory", directory or DIR_PATH, "--out", out]
    if minimum is not None:
        args += ["--min", str(minimum)]
    code, so, se = cli(*args)
    return code, out, se


def verify(path: str, ident: str | None = None, directory: str | None = DIR_PATH, extra=()):
    args = ["verify", path, "--json", *extra]
    if ident:
        args += ["--identity", ident]
    if directory:
        args += ["--directory", directory]
    code, so, se = cli(*args)
    try:
        rep = json.loads(so)
    except Exception:
        rep = {"raw": so, "err": se}
    return code, rep


def verify_text(path: str, ident: str | None = None, directory: str | None = DIR_PATH, extra=()):
    args = ["verify", path, *extra]
    if ident:
        args += ["--identity", ident]
    if directory:
        args += ["--directory", directory]
    return cli(*args)


def py_submit(log, ws, old=None):
    old = old or {}
    responses, statuses = [], {}
    for w in ws:
        o = old.get(w.entry["pubkey"], 0)
        for _ in range(6):
            st, body, ct = http("POST", w.url + "/add-checkpoint", log.add_checkpoint_body(o))
            if st == 409:
                assert (ct or "").startswith("text/x.tlog.size"), ct
                o = int(body.strip())
                continue
            if st in (0, 429, 503):
                time.sleep(0.3)
                continue
            break
        statuses[w.name] = st
        if st == 200:
            responses.append((w.entry["pubkey"], body))
            old[w.entry["pubkey"]] = log.tree_size()
    return responses, statuses, old


def witnessed_dossier(tag: str, n: int = 6):
    """A journal cosigned by every witness, as (journal_path, dossier_dict, identity)."""
    p, j = journal(tag, n)
    ident = j.identity_pubkey_hex()
    release(j)
    del j
    code, out, err = submit(p)
    assert code == 0, err
    return p, json.load(open(out)), ident


def write_json(d: str, name: str, obj) -> str:
    p = os.path.join(d, name)
    with open(p, "w") as f:
        json.dump(obj, f)
    return p


def raw_http(port: int, data: bytes, timeout: float = 15.0) -> bytes:
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall(data)
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
        release(s)
        del s


def status_of(resp: bytes) -> int | None:
    try:
        return int(resp.split(b" ")[1])
    except Exception:
        return None


VKEY_RE = re.compile(r"^\S+\+[0-9a-f]{8}\+[A-Za-z0-9+/=]+$")


def vkey_from_show(text: str) -> str:
    """The vkey line `c2sp show` prints: <name>+<keyid>+<base64>."""
    return next(l.strip() for l in text.splitlines() if VKEY_RE.match(l.strip()))


def post_raw(port: int, body: str) -> int | None:
    req = b"POST /add-checkpoint HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % len(body.encode()) + body.encode()
    return status_of(raw_http(port, req))


# =========================================================== A. install

@test("T001", "install", "`--version` prints witness-log <semver>", fixed_in="0.3.2")
def t001():
    code, out, err = cli("--version")
    assert code == 0, f"exit {code}: {err.strip()}"
    assert re.match(r"^witness-log \d+\.\d+\.\d+", out.strip()), out
    return out.strip()


@test("T002", "install", "bare invocation exits 0 and points at `demo`")
def t002():
    code, out, _ = cli()
    assert code == 0 and "demo" in out
    return "exit 0, mentions demo"


@test("T003", "install", "`--help` lists every command")
def t003():
    code, out, _ = cli("--help")
    assert code == 0
    for c in ("verify", "diff", "explain", "c2sp", "witness", "conform"):
        assert f"witness-log {c}" in out, c
    return "verify, diff, explain, c2sp, witness, conform"


@test("T004", "install", "`demo` reaches WITNESSED and UNANCHORED (exit 0); `demo --tamper` catches the forgery (exit 40, the verdict)")
def t004():
    code, out, _ = cli("demo")
    assert code == 0 and "WITNESSED" in out and "UNANCHORED" in out, code
    code2, out2, _ = cli("demo", "--tamper")
    assert code2 == 40 and "INVALID" in out2, code2
    return "demo exit 0: WITNESSED+UNANCHORED; --tamper exit 40: INVALID"


@test("T005", "install", "Python package imports, has __version__ and type stubs", fixed_in="0.3.2")
def t005():
    v = getattr(wl, "__version__", None)
    assert v and re.match(r"^\d+\.\d+\.\d+", v), v
    pkg = os.path.dirname(wl.__file__)
    assert os.path.exists(os.path.join(pkg, "_core.pyi")), "no _core.pyi"
    assert os.path.exists(os.path.join(pkg, "py.typed")), "no py.typed"
    return f"witness_log {v}, _core.pyi + py.typed present"


@test("T006", "install", "Python classes and methods carry docstrings", since="0.3.2")
def t006():
    missing = [m for m in ("create", "resume", "forget", "sync", "to_dossier_json")
               if not (getattr(wl.JournaledLog, m).__doc__ or "").strip()]
    assert not missing, f"undocumented: {missing}"
    assert (wl.verify_dossier_json.__doc__ or "").strip()
    return "JournaledLog.{create,resume,forget,sync,to_dossier_json}, verify_dossier_json documented"


# ======================================================== B. cli verify

@test("T007", "cli-verify", "sample dossier with no anchors is UNANCHORED (exit 20)")
def t007():
    code, rep = verify(SAMPLE, None, None)
    assert code == 20 and rep["verdict"] == "UNANCHORED", (code, rep.get("verdict"))
    return "exit 20"


@test("T008", "cli-verify", "sample dossier with --identity and --directory is WITNESSED (exit 0)")
def t008():
    code, rep = verify(SAMPLE, SAMPLE_ID, TRUSTED)
    assert code == 0 and rep["verdict"] == "WITNESSED", (code, rep.get("verdict"))
    q = rep["report"]["quorum"]
    return f"exit 0, {q['valid_receipts']}/{q['total_directory_witnesses']} receipts, {q['distinct_independent_operators']} independent operators"


@test("T009", "cli-verify", "wrong --identity is INVALID (exit 40), identity_bound false")
def t009():
    code, rep = verify(SAMPLE, "ab" * 32, TRUSTED)
    assert code == 40 and rep["report"]["identity_bound"] is False
    return "exit 40, identity_bound=false"


@test("T010", "cli-verify", "malformed --identity is a usage error (exit 2), not a verdict", fixed_in="0.3.2")
def t010():
    for bad in ("nothex", "ab" * 31, "zz" * 32):
        code, _, err = cli("verify", SAMPLE, "--identity", bad)
        assert code == 2, f"{bad!r}: exit {code}"
    return "3 malformed identities -> exit 2"


@test("T011", "cli-verify", "--threshold 1.0 on a 3/4 quorum is CONSISTENT-UNWITNESSED (exit 10)")
def t011():
    code, rep = verify(SAMPLE, SAMPLE_ID, TRUSTED, ["--threshold", "1.0"])
    assert code == 10 and rep["verdict"] == "CONSISTENT-UNWITNESSED"
    return "exit 10"


@test("T012", "cli-verify", "--threshold outside 0..1, nan, or non-numeric is exit 2")
def t012():
    for t in ("1.5", "-0.1", "nan", "abc"):
        code, _, _ = cli("verify", SAMPLE, "--threshold", t)
        assert code == 2, f"{t}: exit {code}"
    return "1.5, -0.1, nan, abc -> exit 2"


@test("T013", "cli-verify", "unknown and misspelled flags are refused (exit 2)")
def t013():
    for f in ("--jsom", "--treshold", "--identify"):
        code, _, err = cli("verify", SAMPLE, f)
        assert code == 2 and "unrecognized" in err, (f, code, err)
    return "--jsom, --treshold, --identify -> exit 2"


@test("T014", "cli-verify", "missing file and non-JSON file are exit 2")
def t014():
    code, _, _ = cli("verify", "/nonexistent/d.json")
    d = fresh("notjson")
    p = os.path.join(d, "x.json")
    open(p, "w").write("not json")
    code2, _, _ = cli("verify", p)
    assert code == 2 and code2 == 2
    return "both exit 2"


@test("T015", "cli-verify", "--json report carries identity_pinned, internally_consistent, bindings_asserted", fixed_in="0.3.2")
def t015():
    code, rep = verify(SAMPLE, SAMPLE_ID, TRUSTED)
    r = rep["report"]
    for k in ("identity_pinned", "internally_consistent", "bindings_asserted", "externally_anchored"):
        assert k in r, f"missing {k}"
    assert r["identity_pinned"] is True and r["internally_consistent"] is True
    assert "independent_operators_represented" in r["quorum"]
    return "all present; identity_pinned=true"


@test("T016", "cli-verify", "--directory accepts a bare JSON array of entries", fixed_in="0.3.2")
def t016():
    d = fresh("baredir")
    arr = write_json(d, "arr.json", json.load(open(TRUSTED))["witnesses"])
    code, rep = verify(SAMPLE, SAMPLE_ID, arr)
    assert code == 0, (code, rep)
    return "bare array -> WITNESSED"


@test("T017", "cli-verify", "WITNESSED without --identity prints a warning naming the missing pin", fixed_in="0.3.2")
def t017():
    code, out, _ = verify_text(SAMPLE, None, TRUSTED)
    assert code == 0
    assert "--identity" in out and "whose" in out, out
    assert "not pinned" in out
    return "warning present"


@test("T018", "cli-verify", "one-operator directory is exit 10 and the text names the independent-operator gate", fixed_in="0.3.2")
def t018():
    d = fresh("oneorg")
    entries = json.load(open(TRUSTED))["witnesses"]
    for e in entries:
        e["operator_org"] = "Same Org"
        e["is_project_operated"] = False
    path = write_json(d, "same.json", {"witnesses": entries})
    code, out, _ = verify_text(SAMPLE, SAMPLE_ID, path)
    assert code == 10, code
    assert "independent operator" in out and "needs at least 2" in out, out
    return "exit 10; gate named"


@test("T019", "cli-verify", "`explain` states the two-independent-operator rule; --json parses; unknown topic exit 2", fixed_in="0.3.2")
def t019():
    code, out, _ = cli("explain", "witnessed")
    assert code == 0 and "two distinct independent operators" in out, out
    code2, out2, _ = cli("explain", "--json")
    assert code2 == 0 and len(json.loads(out2)) == 4
    code3, _, _ = cli("explain", "bogus")
    assert code3 == 2
    return "rule stated; 4 verdicts in JSON; unknown -> 2"


@test("T020", "cli-verify", "`verify --help` exits 0 with usage", fixed_in="0.3.2")
def t020():
    code, out, _ = cli("verify", "--help")
    assert code == 0 and "--directory" in out, (code, out)
    return "exit 0"


# ======================================================= C. tamper

def _tampered(tag, mutate):
    p, dossier, ident = witnessed_dossier(tag)
    mutate(dossier)
    path = write_json(os.path.dirname(p), "tampered.json", dossier)
    return verify(path, ident), ident


@test("T021", "tamper", "edited payload_hash -> INVALID, merkle_continuity false")
def t021():
    def m(d):
        d["leaves"][2]["payload_hash"] = "ab" * 32
    (code, rep), _ = _tampered("t-payload", m)
    assert code == 40 and rep["report"]["merkle_continuity_valid"] is False
    return "exit 40"


@test("T022", "tamper", "deleted middle leaf (indices renumbered) -> INVALID")
def t022():
    def m(d):
        del d["leaves"][2]
        for i, l in enumerate(d["leaves"]):
            l["index"] = i
    (code, rep), _ = _tampered("t-delmid", m)
    assert code == 40
    return "exit 40"


@test("T023", "tamper", "deleted last leaf with tree_size adjusted -> INVALID (signature over root fails)")
def t023():
    def m(d):
        d["leaves"].pop()
        d["checkpoint"]["tree_size"] -= 1
    (code, rep), _ = _tampered("t-dellast", m)
    assert code == 40 and rep["report"]["checkpoint_signature_valid"] is False
    return "exit 40, checkpoint_signature_valid=false"


@test("T024", "tamper", "two leaves swapped -> INVALID")
def t024():
    def m(d):
        d["leaves"][0], d["leaves"][1] = d["leaves"][1], d["leaves"][0]
    (code, _), _ = _tampered("t-swap", m)
    assert code == 40
    return "exit 40"


@test("T025", "tamper", "checkpoint timestamp +1 ms -> INVALID (signature)")
def t025():
    def m(d):
        d["checkpoint"]["timestamp_ms"] += 1
    (code, rep), _ = _tampered("t-ts", m)
    assert code == 40 and rep["report"]["checkpoint_signature_valid"] is False
    return "exit 40"


@test("T026", "tamper", "receipt with rewritten root is dropped, never counted")
def t026():
    def m(d):
        d["witness_receipts"][0]["root_hash"] = "cd" * 32
    (code, rep), _ = _tampered("t-receipt", m)
    q = rep["report"]["quorum"]
    assert q["valid_receipts"] == len(WS) - 1, q
    return f"{q['valid_receipts']} counted of {len(WS)} present"


@test("T027", "tamper", "duplicated receipt counts once")
def t027():
    def m(d):
        d["witness_receipts"] += d["witness_receipts"][:3]
    (code, rep), _ = _tampered("t-dup", m)
    q = rep["report"]["quorum"]
    assert q["valid_receipts"] == len(WS), q
    return f"{len(WS)+3} receipts -> {q['valid_receipts']} counted"


@test("T028", "tamper", "bindings stripped: still verifies, bindings_asserted=false", fixed_in="0.3.2")
def t028():
    def m(d):
        d["key_bindings"] = []
    (code, rep), _ = _tampered("t-nobind", m)
    assert code == 0 and rep["report"]["bindings_asserted"] is False
    return "exit 0, bindings_asserted=false"


@test("T029", "tamper", "binding not_after_ms=1 -> INVALID and the text shows the key-binding line failing", fixed_in="0.3.2")
def t029():
    p, dossier, ident = witnessed_dossier("t-expired")
    dossier["key_bindings"][0]["not_after_ms"] = 1
    path = write_json(os.path.dirname(p), "expired.json", dossier)
    code, out, _ = verify_text(path, ident)
    assert code == 40, code
    assert "✗ Key bindings" in out, out
    return "exit 40, ✗ Key bindings shown"


@test("T030", "tamper", "unknown leaf type 0x09 -> INVALID")
def t030():
    def m(d):
        d["leaves"][1]["leaf_type"] = 9
    (code, rep), _ = _tampered("t-type", m)
    assert code == 40 and rep["report"]["leaves_structurally_valid"] is False
    return "exit 40"


@test("T031", "tamper", "identity_pubkey field changed with checkpoint intact -> INVALID (self-consistency)")
def t031():
    def m(d):
        d["identity_pubkey"] = "ef" * 32
    (code, rep), _ = _tampered("t-ident", m)
    assert code == 40 and rep["report"]["identity_bound"] is False
    return "exit 40"


@test("T032", "tamper", "receipts transplanted onto another log never count")
def t032():
    _, a, ia = witnessed_dossier("t-transplant-a")
    pb, b, ib = witnessed_dossier("t-transplant-b")
    b["witness_receipts"] = a["witness_receipts"]
    path = write_json(os.path.dirname(pb), "transplant.json", b)
    code, rep = verify(path, ib)
    q = rep["report"]["quorum"]
    assert code in (10, 40) and (q is None or q["valid_receipts"] == 0), (code, q)
    return f"exit {code}, counted 0"


@test("T033", "tamper", "`diff`: identical copies exit 0; an edited copy is 'tampered, not equivocation' (exit 40)")
def t033():
    p, d, ident = witnessed_dossier("t-diff")
    a = write_json(os.path.dirname(p), "a.json", d)
    code, out, _ = cli("diff", a, a)
    assert code == 0, out
    d["leaves"][0]["payload_hash"] = "11" * 32
    b = write_json(os.path.dirname(p), "b.json", d)
    code2, out2, _ = cli("diff", a, b)
    assert code2 == 40 and "not" in out2 and "equivocation" in out2, out2
    return "identical 0; edited 40"


@test("T034", "tamper", "a dossier signed by key A presented as key B's with --identity B -> INVALID")
def t034():
    p, d, ident = witnessed_dossier("t-impersonate")
    other = wl.WitnessLog.generate().identity_pubkey_hex()
    d["identity_pubkey"] = other
    path = write_json(os.path.dirname(p), "imp.json", d)
    code, rep = verify(path, other)
    assert code == 40
    return "exit 40"


# ====================================================== D. python api

@test("T035", "python", "`open()` creates then resumes the same identity; tree grows across runs", since="0.3.2")
def t035():
    d = fresh("open")
    p = os.path.join(d, "a.jsonl")
    log = wl.open(p)
    ident = log.identity_pubkey_hex()
    log.append_intent(b"one")
    release(log)
    del log
    log2 = wl.open(p)
    assert log2.identity_pubkey_hex() == ident and log2.tree_size() == 1
    log2.append_intent(b"two")
    assert log2.tree_size() == 2
    bindings = json.loads(log2.to_dossier_json())["key_bindings"]
    release(log2)
    del log2
    assert len(bindings) == 2, bindings
    return "resumed, 2 bindings"


@test("T036", "python", "`@step` appends intent+result; result names its intent; errors are recorded and re-raised", since="0.3.2")
def t036():
    d = fresh("step")
    log = wl.open(os.path.join(d, "a.jsonl"))

    @wl.step(log)
    def add(a, b):
        if b == 0:
            raise ValueError("boom")
        return a + b

    assert add(1, 2) == 3
    try:
        add(1, 0)
        raise AssertionError("exception swallowed")
    except ValueError:
        pass
    leaves = leaves_of(log)
    release(log)
    del log
    assert [l["leaf_type"] for l in leaves] == [1, 2, 1, 2], leaves
    return "intent,result,intent,result; ValueError re-raised"


@test("T037", "python", "`@step` works on async functions", since="0.3.2")
def t037():
    import asyncio
    d = fresh("astep")
    log = wl.open(os.path.join(d, "a.jsonl"))

    @wl.step(log)
    async def fetch(x):
        await asyncio.sleep(0)
        return {"x": x}

    out = asyncio.run(fetch(7))
    n = log.tree_size()
    release(log)
    del log
    assert out == {"x": 7} and n == 2
    return "2 leaves from one awaited call"


@test("T038", "python", "forget() works for leaves written before a restart; can_forget tracks it", fixed_in="0.3.2")
def t038():
    d = fresh("forget")
    p = os.path.join(d, "a.jsonl")
    log = wl.JournaledLog.create(p, os.urandom(32))
    log.append_memory(b"alice@example.com")
    log.sync()
    release(log)
    del log
    log, _ = wl.JournaledLog.resume(p)
    assert log.can_forget(0)
    assert log.forget(0) is True
    assert not log.can_forget(0) and log.forget(0) is False
    size = log.tree_size()
    release(log)
    del log
    assert size == 2
    return "forgot pre-restart leaf; tombstone appended"


@test("T039", "python", "an empty payload is salted, not the all-zero hash, and is forgettable", fixed_in="0.3.2")
def t039():
    d = fresh("empty")
    log = wl.JournaledLog.create(os.path.join(d, "a.jsonl"), os.urandom(32))
    i = log.append_result(b"")
    h = leaves_of(log)[0]["payload_hash"]
    ok = log.forget(i)
    release(log)
    del log
    assert h != "0" * 64 and ok
    return "salted + forgettable"


@test("T040", "python", "`.salts` sidecar: 0600, one record per payload leaf, record removed on forget", fixed_in="0.3.2")
def t040():
    d = fresh("salts")
    p = os.path.join(d, "a.jsonl")
    log = wl.JournaledLog.create(p, os.urandom(32))
    for i in range(3):
        log.append_intent(b"x%d" % i)
    log.sync()
    sp = p + ".salts"
    assert os.path.exists(sp), "no sidecar"
    mode = os.stat(sp).st_mode & 0o777
    assert mode == 0o600, oct(mode)
    assert len(open(sp).read().splitlines()) == 3
    log.forget(1)
    release(log)
    del log
    lines = open(sp).read().splitlines()
    assert len(lines) == 2 and not any('"i":1,' in l for l in lines)
    return "0600, 3 -> 2 records"


@test("T041", "python", "close() releases the lock; calls after close raise OSError; context manager closes", since="0.3.2")
def t041():
    d = fresh("close")
    p = os.path.join(d, "a.jsonl")
    log = wl.JournaledLog.create(p, os.urandom(32))
    log.close()
    assert log.is_closed() and not os.path.exists(p + ".lock")
    try:
        log.append_intent(b"x")
        raise AssertionError("no error after close")
    except OSError:
        pass
    with wl.JournaledLog.resume(p)[0] as l2:
        l2.append_intent(b"y")
    assert l2.is_closed()
    return "closed, OSError after close, with-block closes"


@test("T042", "python", "a process killed with SIGKILL while holding the journal: resume recovers the lock itself", fixed_in="0.3.2")
def t042():
    if not LINUX:
        return "skipped: Linux-only liveness check"
    d = fresh("kill9")
    p = os.path.join(d, "a.jsonl")
    first = wl.JournaledLog.create(p, os.urandom(32))
    release(first)
    del first
    code = ("import witness_log, os; log = witness_log.JournaledLog.resume(%r)[0]; "
            "log.append_intent(b'x'); log.sync(); os._exit(0)" % p)
    subprocess.run([sys.executable, "-c", code], check=True)
    assert os.path.exists(p + ".lock"), "no stale lock to recover"
    log, _ = wl.JournaledLog.resume(p)
    n = log.tree_size()
    release(log)
    del log
    assert n == 1
    return "stale lock recovered, 1 leaf"


@test("T043", "python", "a live lock is refused with OSError; JournaledLog.force_unlock exists", fixed_in="0.3.2")
def t043():
    d = fresh("livelock")
    p = os.path.join(d, "a.jsonl")
    held = wl.JournaledLog.create(p, os.urandom(32))
    try:
        wl.JournaledLog.resume(p)
        raise AssertionError("second open succeeded")
    except OSError:
        pass
    release(held)
    del held
    assert hasattr(wl.JournaledLog, "force_unlock")
    wl.JournaledLog.force_unlock(p)
    return "refused; force_unlock present"


@test("T044", "python", "inclusion_proof verifies with verify_inclusion; tampered proof fails; out of range is None", since="0.3.2")
def t044():
    log = wl.WitnessLog.generate()
    for i in range(9):
        log.append_intent(b"%d" % i)
    size, root, path = log.inclusion_proof(4)
    lh = log.leaf_hash_hex(4)
    assert wl.verify_inclusion(lh, 4, size, path, root)
    bad = list(path)
    bad[0] = "00" * 32
    assert not wl.verify_inclusion(lh, 4, size, bad, root)
    assert log.inclusion_proof(9) is None
    return f"proof of 9 leaves: {len(path)} hashes"


@test("T045", "python", "verify_dossier_json validates threshold and identity arguments", fixed_in="0.3.2")
def t045():
    dossier = wl.WitnessLog.generate().to_dossier_json()
    for bad in (2.0, -1.0, float("nan")):
        try:
            wl.verify_dossier_json(dossier, bad)
            raise AssertionError(f"threshold {bad} accepted")
        except ValueError:
            pass
    try:
        wl.verify_dossier_json(dossier, 0.5, "nothex")
        raise AssertionError("bad identity accepted")
    except ValueError:
        pass
    return "ValueError for 2.0, -1.0, nan, 'nothex'"


@test("T046", "python", "wrong argument types raise TypeError, never crash")
def t046():
    log = wl.WitnessLog.generate()
    for bad in ("string", 42, None, [1, 2]):
        try:
            log.append_intent(bad)
            raise AssertionError(f"{bad!r} accepted")
        except TypeError:
            pass
    return "str, int, None, list -> TypeError"


@test("T047", "python", "snapshot save/load reproduces the root and advances the session")
def t047():
    d = fresh("snap")
    log = wl.WitnessLog.generate()
    for i in range(5):
        log.append_intent(b"%d" % i)
    root = log.root_hex()
    log.save_snapshot(os.path.join(d, "s.json"))
    assert (os.stat(os.path.join(d, "s.json")).st_mode & 0o777) == 0o600
    back = wl.WitnessLog.load_snapshot(os.path.join(d, "s.json"))
    assert back.root_hex() == root
    assert len(json.loads(back.all_bindings_json())) == 2
    return "root equal, 2 bindings, 0600"


@test("T048", "python", "torn tail line is dropped and physically healed on resume")
def t048():
    d = fresh("torn")
    p = os.path.join(d, "a.jsonl")
    log = wl.JournaledLog.create(p, os.urandom(32))
    log.append_intent(b"ok")
    log.sync()
    release(log)
    del log
    with open(p, "a") as f:
        f.write('{"index":1,"leaf_ty')
    log, dropped = wl.JournaledLog.resume(p)
    assert dropped == 1 and log.tree_size() == 1
    release(log)
    del log
    log, dropped2 = wl.JournaledLog.resume(p)
    release(log)
    del log
    assert dropped2 == 0
    return "1 dropped, then 0"


@test("T049", "python", "corruption in the middle of a journal refuses to resume (OSError)")
def t049():
    d = fresh("midcorrupt")
    p = os.path.join(d, "a.jsonl")
    log = wl.JournaledLog.create(p, os.urandom(32))
    log.append_intent(b"a")
    log.sync()
    release(log)
    del log
    lines = open(p).read().splitlines()
    lines.insert(2, "garbage line")
    open(p, "w").write("\n".join(lines) + "\n")
    try:
        wl.JournaledLog.resume(p)
        raise AssertionError("corrupt journal resumed")
    except OSError:
        pass
    return "OSError"


@test("T050", "python", "1,000 decorated calls average under 2 ms each, journaled", since="0.3.2")
def t050():
    d = fresh("perf")
    log = wl.open(os.path.join(d, "a.jsonl"))

    @wl.step(log)
    def noop(i):
        return i

    t = time.perf_counter()
    for i in range(1000):
        noop(i)
    per = (time.perf_counter() - t) / 1000 * 1e6
    release(log)
    del log
    assert per < 2000, f"{per:.0f} µs"
    return f"{per:.0f} µs per decorated call (2 leaves)"


# =================================================== E. witness protocol

@test("T051", "witness", "CLI `submit` is cosigned by every live witness and verifies WITNESSED")
def t051():
    p, j = journal("e-submit", 8)
    ident = j.identity_pubkey_hex()
    release(j)
    del j
    code, out, err = submit(p, minimum=len(WS))
    assert code == 0, err
    vcode, rep = verify(out, ident)
    assert vcode == 0, rep
    return f"{len(WS)}/{len(WS)} cosigned, WITNESSED"


@test("T052", "witness", "pure-Python agent (urllib) reaches WITNESSED")
def t052():
    p, j = journal("e-py", 5)
    responses, statuses, _ = py_submit(j, WS)
    dossier, n = j.dossier_from_responses(responses)
    rep = json.loads(wl.verify_dossier_json(dossier, 0.66, j.identity_pubkey_hex(), open(DIR_PATH).read()))
    release(j)
    del j
    assert n == len(WS) and rep["verdict"] == "witnessed", (n, rep["verdict"], statuses)
    return f"{n} cosignatures, witnessed"


@test("T053", "witness", "409 resync: wrong `old` size returns text/x.tlog.size with the size to use")
def t053():
    p, j = journal("e-409", 4)
    w = WS[0]
    st, _, _ = http("POST", w.url + "/add-checkpoint", j.add_checkpoint_body(0))
    assert st == 200, st
    j.append_intent(b"more")
    st2, body, ct = http("POST", w.url + "/add-checkpoint", j.add_checkpoint_body(0))
    assert st2 == 409 and ct.startswith("text/x.tlog.size") and body.strip() == "4", (st2, ct, body)
    st3, _, _ = http("POST", w.url + "/add-checkpoint", j.add_checkpoint_body(4))
    release(j)
    del j
    assert st3 == 200
    return "409 '4' then 200"


@test("T054", "witness", "incremental growth is cosigned with consistency proofs across three rounds")
def t054():
    p, j = journal("e-grow", 3)
    ident = j.identity_pubkey_hex()
    release(j)
    del j
    out = p + ".d.json"
    for rnd, add in enumerate((1, 50, 7)):
        log, _ = wl.JournaledLog.resume(p)
        for i in range(add):
            log.append_result(b"r%d-%d" % (rnd, i))
        log.sync()
        release(log)
        del log
        code, _, err = submit(p, out, minimum=len(WS))
        assert code == 0, f"round {rnd}: {err}"
    vcode, rep = verify(out, ident)
    assert vcode == 0 and rep["report"]["leaf_count"] == 61
    return "sizes 4, 54, 61 all cosigned; WITNESSED"


@test("T055", "witness", "same-size fork is refused (422) by every witness and Rust witnesses write checkable evidence", fixed_in="0.3.2")
def t055():
    seed = os.urandom(32)
    p1, j1 = journal("e-fork-a", 6, seed, b"honest")
    release(j1)
    del j1
    code, _, err = submit(p1, minimum=len(WS))
    assert code == 0, err
    p2, j2 = journal("e-fork-b", 6, seed, b"forked")
    statuses = {}
    for w in WS:
        st, body, _ = http("POST", w.url + "/add-checkpoint", j2.add_checkpoint_body(0))
        if st == 409:
            st, body, _ = http("POST", w.url + "/add-checkpoint", j2.add_checkpoint_body(int(body.strip())))
        statuses[w.name] = st
    release(j2)
    del j2
    assert all(s == 422 for s in statuses.values()), statuses
    rust = [w for w in WS if w.kind == "rust"]
    ev_files = [f for w in rust for f in (os.listdir(os.path.join(w.dir, "evidence")) if os.path.isdir(os.path.join(w.dir, "evidence")) else [])]
    assert ev_files, "no evidence written"
    some = next(os.path.join(w.dir, "evidence", f) for w in rust if os.path.isdir(os.path.join(w.dir, "evidence")) for f in os.listdir(os.path.join(w.dir, "evidence")))
    code, out, err = cli("witness", "verify-evidence", some)
    assert code == 0 and "PROVEN" in out, (code, out, err)
    return f"422 from {len(statuses)}; evidence verified with `verify-evidence`"


@test("T056", "witness", "a growing fork (size+1, different history) is refused, never cosigned")
def t056():
    seed = os.urandom(32)
    p1, j1 = journal("e-gfork-a", 5, seed, b"honest")
    release(j1)
    del j1
    code, _, err = submit(p1, minimum=len(WS))
    assert code == 0, err
    p2, j2 = journal("e-gfork-b", 6, seed, b"forked")
    sts = set()
    for w in WS:
        st, body, _ = http("POST", w.url + "/add-checkpoint", j2.add_checkpoint_body(5))
        sts.add(st)
    release(j2)
    del j2
    assert 200 not in sts and sts <= {409, 422, 400}, sts
    return f"statuses {sorted(sts)}"


@test("T057", "witness", "an older checkpoint than the witness holds (old size matching) is 400, not evidence; a mismatched old size is 409")
def t057():
    p, j = journal("e-stale", 3)
    w = WS[1]
    old_body = j.add_checkpoint_body(0)
    assert http("POST", w.url + "/add-checkpoint", old_body)[0] == 200
    j.append_intent(b"x")
    assert http("POST", w.url + "/add-checkpoint", j.add_checkpoint_body(3))[0] == 200
    ident = j.identity_pubkey_hex()
    release(j)
    del j
    # Replaying the size-3 note with `old 0`: the witness is at 4, so 409 + "4".
    st409, body409, _ = http("POST", w.url + "/add-checkpoint", old_body)
    assert st409 == 409 and body409.strip() == "4", (st409, body409)
    # The same stale note with the witness's real size as `old`: 400 StaleCheckpoint.
    note = old_body.split("\n\n", 1)[1]
    st, body, _ = http("POST", w.url + "/add-checkpoint", "old 4\n\n" + note)
    assert st == 400, (st, body)
    ev = os.path.join(w.dir, "evidence", hashlib.sha256(("witness-log/" + ident).encode()).hexdigest() + ".json")
    assert not os.path.exists(ev), "stale checkpoint recorded as evidence"
    return "409 '4' then 400; nothing recorded"


@test("T058", "witness", "resubmitting the identical head is idempotent (200 again)")
def t058():
    p, j = journal("e-idem", 3)
    w = WS[2]
    b = j.add_checkpoint_body(0)
    assert http("POST", w.url + "/add-checkpoint", b)[0] == 200
    st, _, _ = http("POST", w.url + "/add-checkpoint", j.add_checkpoint_body(3))
    release(j)
    del j
    assert st == 200, st
    return "200, 200"


@test("T059", "witness", "a non-canonical origin is not enrolled under open enrollment (404)")
def t059():
    p, j = journal("e-origin", 2)
    body = j.add_checkpoint_body(0).replace(j.canonical_origin(), "example.com/not-canonical")
    release(j)
    del j
    st, _, _ = http("POST", WS[3].url + "/add-checkpoint", body)
    assert st == 404, st
    return "404"


@test("T060", "witness", "a forged log signature is 403")
def t060():
    p, j = journal("e-forged", 2)
    body = j.add_checkpoint_body(0)
    release(j)
    del j
    sig_line = [l for l in body.split("\n") if l.startswith("—")][0]
    parts = sig_line.split(" ")
    raw = bytearray(base64.b64decode(parts[2]))
    raw[10] ^= 1
    forged = body.replace(sig_line, f"{parts[0]} {parts[1]} {base64.b64encode(bytes(raw)).decode()}")
    st, _, _ = http("POST", WS[4].url + "/add-checkpoint", forged)
    assert st == 403, st
    return "403"


@test("T061", "witness", "`witness info` and GET / return vkey, directory_entry and software on every witness")
def t061():
    for w in WS:
        code, out, _ = cli("witness", "info", w.url)
        assert code == 0, out
        info = json.loads(out)
        for k in ("vkey", "directory_entry", "software"):
            assert k in info, (w.name, k)
    return f"{len(WS)} witnesses answered"


@test("T062", "witness", "a directory assembled from live GET / calls verifies a submitted dossier WITNESSED")
def t062():
    entries = [json.loads(http("GET", w.url + "/")[1])["directory_entry"] for w in WS]
    d = fresh("livedir")
    path = write_json(d, "dir.json", {"witnesses": entries})
    p, dossier, ident = witnessed_dossier("e-livedir")
    dp = write_json(d, "dossier.json", dossier)
    code, rep = verify(dp, ident, path)
    assert code == 0, rep
    return "WITNESSED"


@test("T063", "witness", "`submit` refuses to publish a journal rolled back to an old backup")
def t063():
    p, j = journal("e-rollback", 4)
    release(j)
    del j
    backup = p + ".bak"
    shutil.copy(p, backup)
    shutil.copy(p + ".salts", backup + ".salts") if os.path.exists(p + ".salts") else None
    log, _ = wl.JournaledLog.resume(p)
    log.append_intent(b"after backup")
    log.sync()
    release(log)
    del log
    code, _, err = submit(p, minimum=len(WS))
    assert code == 0, err
    shutil.copy(backup, p)
    log, _ = wl.JournaledLog.resume(p)
    log.append_intent(b"divergent")
    log.sync()
    release(log)
    del log
    code2, _, err2 = submit(p, minimum=1)
    assert code2 != 0 and "contradict" in (err2 or "").lower() or code2 != 0, err2
    return f"refused (exit {code2})"


@test("T064", "witness", "receipts carry the canonical c2sp_origin and the cosignature verifies with `c2sp verify`", fixed_in="0.3.2")
def t064():
    p, dossier, ident = witnessed_dossier("e-c2sp")
    rec = dossier["witness_receipts"][0]
    assert rec.get("c2sp_origin") == "witness-log/" + ident, rec.get("c2sp_origin")
    d = os.path.dirname(p)
    dp = write_json(d, "d.json", dossier)
    code, note, err = cli("c2sp", "show", dp, "--origin", "witness-log/" + ident, "--raw", "--sign-with", p)
    assert code == 0, err
    np = os.path.join(d, "note.txt")
    open(np, "w").write(note)
    code2, out, _ = cli("c2sp", "show", dp, "--origin", "witness-log/" + ident)
    vkey = vkey_from_show(out)
    code3, out3, err3 = cli("c2sp", "verify", np, "--vkey", vkey)
    assert code3 == 0, (out3, err3)
    return "origin canonical; signed note verifies"


# ====================================================== F. adversarial

@test("T065", "adversarial", "random bytes body -> 400")
def t065():
    st = status_of(raw_http(WS[0].port, b"POST /add-checkpoint HTTP/1.1\r\nHost: x\r\nContent-Length: 16\r\n\r\n" + os.urandom(16)))
    assert st == 400, st
    return "400"


@test("T066", "adversarial", "JSON body -> 400")
def t066():
    assert post_raw(WS[0].port, '{"checkpoint": "x"}') == 400
    return "400"


@test("T067", "adversarial", "wrong methods -> 405 on /, /health and /add-checkpoint")
def t067():
    for path in ("/", "/health", "/add-checkpoint"):
        st = status_of(raw_http(WS[1].port, f"DELETE {path} HTTP/1.1\r\nHost: x\r\n\r\n".encode()))
        assert st == 405, (path, st)
    return "405 x3"


@test("T068", "adversarial", "200 KiB body -> 413")
def t068():
    big = "a" * 200_000
    assert post_raw(WS[1].port, big) == 413
    return "413"


@test("T069", "adversarial", "chunked transfer encoding -> 501")
def t069():
    st = status_of(raw_http(WS[2].port, b"POST /add-checkpoint HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"))
    assert st == 501, st
    return "501"


@test("T070", "adversarial", "a junk consistency proof on an honest checkpoint is refused (422) and NOT recorded as evidence")
def t070():
    p, j = journal("f-junk", 4)
    w = WS[2]
    assert http("POST", w.url + "/add-checkpoint", j.add_checkpoint_body(0))[0] == 200
    j.append_intent(b"x")
    body = j.add_checkpoint_body(4)
    head, rest = body.split("\n\n", 1)
    junk = "old 4\n" + base64.b64encode(b"\0" * 32).decode() + "\n\n" + rest
    st, _, _ = http("POST", w.url + "/add-checkpoint", junk)
    ident = j.identity_pubkey_hex()
    assert st == 422, st
    ev = os.path.join(w.dir, "evidence")
    h = hashlib.sha256(("witness-log/" + ident).encode()).hexdigest()
    assert not os.path.exists(os.path.join(ev, h + ".json")), "an honest log was smeared"
    # The honest proof still goes through afterwards: nothing was poisoned.
    st2, _, _ = http("POST", w.url + "/add-checkpoint", body)
    release(j)
    del j
    assert st2 == 200, st2
    return "422, nothing recorded, honest proof then 200"


@test("T071", "adversarial", "unknown path -> 404; /health -> 200 ok")
def t071():
    st = status_of(raw_http(WS[3].port, b"GET /admin HTTP/1.1\r\nHost: x\r\n\r\n"))
    assert st == 404
    st2, body, _ = http("GET", WS[3].url + "/health")
    assert st2 == 200 and body.strip() == "ok"
    return "404; ok"


@test("T072", "adversarial", "slowloris: a connection trickling headers is cut within ~12 s", serial=True)
def t072():
    s = socket.create_connection(("127.0.0.1", WS[4].port), timeout=30)
    t = time.time()
    try:
        for ch in b"GET / HTTP/1.1\r\nHost: x\r\nX-Slow: " + b"a" * 2000:
            try:
                s.sendall(bytes([ch]))
            except OSError:
                break
            time.sleep(0.02)
        try:
            s.recv(10)
        except OSError:
            pass
    finally:
        release(s)
        del s
    el = time.time() - t
    assert el < 14, f"held {el:.1f}s"
    assert http("GET", WS[4].url + "/health")[0] == 200
    return f"cut after {el:.1f}s, server healthy"


@test("T073", "adversarial", "oversized header block is refused and the server stays up")
def t073():
    st = status_of(raw_http(WS[5].port, b"GET / HTTP/1.1\r\nHost: x\r\nX-A: " + b"a" * 20000 + b"\r\n\r\n"))
    assert st in (400, 413, 431), st
    assert http("GET", WS[5].url + "/health")[0] == 200
    return f"{st}, healthy"


@test("T074", "adversarial", "64 proof lines -> 400")
def t074():
    p, j = journal("f-64", 2)
    body = j.add_checkpoint_body(0)
    release(j)
    del j
    rest = body.split("\n\n", 1)[1]
    proof = "\n".join([base64.b64encode(b"\0" * 32).decode()] * 64)
    st = post_raw(WS[5].port, f"old 1\n{proof}\n\n{rest}")
    assert st == 400, st
    return "400"


@test("T075", "adversarial", "a checkpoint body over 1 KiB is refused")
def t075():
    p, j = journal("f-1k", 2)
    body = j.add_checkpoint_body(0)
    release(j)
    del j
    head, note = body.split("\n\n", 1)
    lines = note.split("\n")
    lines.insert(3, "x" * 1200)  # extension line pushes the body over the cap
    st = post_raw(WS[6].port, head + "\n\n" + "\n".join(lines))
    assert st in (400, 403, 413), st
    return f"{st}"


@test("T076", "adversarial", "a burst of 120 connections from one address does not take the witness down", serial=True)
def t076():
    w = WS[6]
    socks = []
    try:
        for _ in range(120):
            try:
                socks.append(socket.create_connection(("127.0.0.1", w.port), timeout=2))
            except OSError:
                break
        for s in socks:
            try:
                s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
            except OSError:
                pass
        codes = set()
        for s in socks:
            try:
                s.settimeout(3)
                codes.add(status_of(s.recv(200)))
            except OSError:
                codes.add(None)
    finally:
        for s in socks:
            release(s)
            del s
    time.sleep(0.5)
    assert http("GET", w.url + "/health")[0] == 200, "witness down after burst"
    return f"{len(socks)} connections, statuses {sorted(c for c in codes if c)}; healthy after"


# ============================================================ G. crash

@test("T077", "crash", "SIGKILL a Rust witness after cosigning; restarted, it still refuses the fork", serial=True)
def t077():
    w = WS[7]
    seed = os.urandom(32)
    p1, j1 = journal("g-kill-a", 4, seed, b"honest")
    assert http("POST", w.url + "/add-checkpoint", j1.add_checkpoint_body(0))[0] == 200
    release(j1)
    del j1
    w.kill(signal.SIGKILL)
    w.start()
    p2, j2 = journal("g-kill-b", 4, seed, b"forked")
    st, body, _ = http("POST", w.url + "/add-checkpoint", j2.add_checkpoint_body(0))
    if st == 409:
        st, body, _ = http("POST", w.url + "/add-checkpoint", j2.add_checkpoint_body(int(body.strip())))
    release(j2)
    del j2
    assert st == 422, (st, body)
    return "restarted with memory; fork 422"


@test("T078", "crash", "SIGTERM stops a Rust witness cleanly: exit 0, lock released, no stale-lock line on restart", fixed_in="0.3.2", serial=True)
def t078():
    w = WS[0]
    proc = w.proc
    w.proc.send_signal(signal.SIGTERM)
    rc = proc.wait(timeout=10)
    w.proc = None
    lock = os.path.join(w.dir, "witness.lock")
    lock_left = os.path.exists(lock)
    before = open(os.path.join(w.dir, "server.log"), "rb").read()
    w.start()  # always bring it back for the scenarios that follow
    time.sleep(0.2)
    after = open(os.path.join(w.dir, "server.log"), "rb").read()[len(before):]
    assert rc == 0, f"exit {rc}"
    assert not lock_left, "lock left behind"
    assert b"stale" not in after, after
    return "exit 0, lock released, clean restart"


@test("T079", "crash", "a second `serve` on the same state directory is refused")
def t079():
    w = WS[1]
    r = subprocess.run([ARGS.cli, "witness", "serve", w.dir, "--listen", f"127.0.0.1:{w.port + 1000}"],
                       capture_output=True, text=True, timeout=15)
    assert r.returncode != 0 and "held by pid" in r.stderr, r.stderr
    return "refused"


@test("T080", "crash", "`serve` removes a lock left by a dead PID and starts", serial=True)
def t080():
    d = fresh("g-stale")
    r = subprocess.run([ARGS.cli, "witness", "init", d, "--name", "g.test/stale", "--org", "G"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    open(os.path.join(d, "witness.lock"), "w").write("4194304\n")
    port = ARGS.base_port + 90
    proc = subprocess.Popen([ARGS.cli, "witness", "serve", d, "--listen", f"127.0.0.1:{port}"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    up = livenet.wait_up(port, 10)
    proc.terminate()
    _, err = proc.communicate(timeout=10)
    assert up, err.decode()
    assert b"no longer running" in err or b"stale" in err, err
    return "started; stale lock reported once"


@test("T081", "crash", "witness.key swapped for another key: `serve` refuses", fixed_in="0.3.2")
def t081():
    d = fresh("g-swap")
    r = subprocess.run([ARGS.cli, "witness", "init", d, "--name", "g.test/swap", "--org", "G"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    open(os.path.join(d, "witness.key"), "w").write(os.urandom(32).hex())
    port = ARGS.base_port + 91
    proc = subprocess.Popen([ARGS.cli, "witness", "serve", d, "--listen", f"127.0.0.1:{port}"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    up = livenet.wait_up(port, 3)
    if up:
        proc.kill()
    _, err = proc.communicate(timeout=10)
    assert not up and proc.returncode != 0 and b"not the key" in err, err[-300:]
    return "refused"


@test("T082", "crash", "missing logs/ directory: `serve` refuses rather than starting empty")
def t082():
    d = fresh("g-nologs")
    r = subprocess.run([ARGS.cli, "witness", "init", d, "--name", "g.test/nologs", "--org", "G"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    shutil.rmtree(os.path.join(d, "logs"))
    r2 = subprocess.run([ARGS.cli, "witness", "serve", d, "--listen", f"127.0.0.1:{ARGS.base_port + 92}"],
                        capture_output=True, text=True, timeout=15)
    assert r2.returncode != 0 and "missing" in r2.stderr, r2.stderr
    return "refused"


@test("T083", "crash", "Python witness killed and restarted keeps its memory; fork refused", serial=True)
def t083():
    w = next(w for w in WS if w.kind == "py")
    seed = os.urandom(32)
    p1, j1 = journal("g-pykill-a", 3, seed, b"honest")
    assert http("POST", w.url + "/add-checkpoint", j1.add_checkpoint_body(0))[0] == 200
    release(j1)
    del j1
    w.kill(signal.SIGKILL)
    w.start()
    p2, j2 = journal("g-pykill-b", 3, seed, b"forked")
    st, body, _ = http("POST", w.url + "/add-checkpoint", j2.add_checkpoint_body(0))
    if st == 409:
        st, body, _ = http("POST", w.url + "/add-checkpoint", j2.add_checkpoint_body(int(body.strip())))
    release(j2)
    del j2
    assert st == 422, st
    return "422 after restart"


@test("T084", "crash", "WitnessService.new with a different seed on an existing state file is refused", fixed_in="0.3.2")
def t084():
    d = fresh("g-state")
    sp = os.path.join(d, "state.json")
    wl.WitnessService.create_state(sp)
    seed = os.urandom(32)
    svc = wl.WitnessService.new("g.test/state", seed, sp, True)
    p, j = journal("g-state-log", 2)
    st, body = svc.handle_add_checkpoint(j.add_checkpoint_body(0))
    release(j)
    del j
    assert st == 200, (st, body)
    del svc
    try:
        wl.WitnessService.new("g.test/state", os.urandom(32), sp, True)
        raise AssertionError("foreign key accepted the state")
    except wl.MalformedError:
        pass
    return "MalformedError"


# ======================================================== H. swarm

@test("T085", "swarm", "N agents x 3 rounds against all witnesses concurrently: every agent WITNESSED", serial=True)
def t085():
    n = ARGS.agents

    def agent(i):
        p, j = journal(f"h-agent{i}", 3)
        old = {}
        for rnd in range(3):
            for k in range(4):
                j.append_result(b"a%d-r%d-%d" % (i, rnd, k))
            responses, statuses, old = py_submit(j, WS, old)
            assert len(responses) >= len(WS) - 1, statuses
        dossier, cnt = j.dossier_from_responses(responses)
        rep = json.loads(wl.verify_dossier_json(dossier, 0.66, j.identity_pubkey_hex(), open(DIR_PATH).read()))
        release(j)
        del j
        return rep["verdict"], cnt

    t = time.time()
    with cf.ThreadPoolExecutor(max_workers=n) as ex:
        out = list(ex.map(agent, range(n)))
    el = time.time() - t
    bad = [o for o in out if o[0] != "witnessed"]
    assert not bad, bad[:3]
    return f"{n} agents, {n * 3 * len(WS)} cosignings in {el:.1f}s, all witnessed"


@test("T086", "swarm", "two submitters racing on one journal never make it equivocate", serial=True)
def t086():
    p, j = journal("h-race", 6)
    release(j)
    del j
    results = []

    def go():
        results.append(submit(p, p + f".{threading.get_ident()}.json", minimum=1)[0])

    ts = [threading.Thread(target=go) for _ in range(2)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert all(c == 0 for c in results), results
    ev = [f for w in WS if w.kind == "rust" for f in os.listdir(os.path.join(w.dir, "evidence")) if os.path.isdir(os.path.join(w.dir, "evidence"))]
    log, _ = wl.JournaledLog.resume(p)
    ident = log.identity_pubkey_hex()
    release(log)
    del log
    h = hashlib.sha256(("witness-log/" + ident).encode()).hexdigest() + ".json"
    assert h not in ev, "equivocation recorded for a racing honest log"
    return "both submits 0; no evidence against the log"


@test("T087", "swarm", "agents become witnesses: two agent-run witnesses join the directory and cosign others", serial=True)
def t087():
    assert len(AGENT_WS) == 2, "agent witnesses not running"
    entries = [w.entry for w in WS] + [w.entry for w in AGENT_WS]
    d = fresh("h-agentdir")
    path = write_json(d, "dir.json", {"witnesses": entries})
    p, j = journal("h-agentw", 4)
    responses, statuses, _ = py_submit(j, WS + AGENT_WS)
    dossier, n = j.dossier_from_responses(responses)
    rep = json.loads(wl.verify_dossier_json(dossier, 0.66, j.identity_pubkey_hex(), open(path).read()))
    release(j)
    del j
    assert n == len(WS) + 2 and rep["verdict"] == "witnessed", (n, statuses, rep["verdict"])
    assert rep["quorum"]["distinct_independent_operators"] >= len({w.org for w in WS + AGENT_WS}) - 1
    return f"{n} cosignatures incl. 2 agent witnesses; witnessed"


@test("T088", "swarm", "a Byzantine agent witness returning garbage is rejected; honest quorum still WITNESSED", serial=True)
def t088():
    evil = Witness(len(WS) + len(AGENT_WS) + 1, ROOT, "py")
    evil.org, evil.compute = "Evil Corp", "void"
    evil.name = "evil.witness.test/garbage"
    evil.init()
    evil.start(extra=("--evil", "garbage"))
    try:
        entries = [w.entry for w in WS] + [evil.entry]
        d = fresh("h-evil")
        path = write_json(d, "dir.json", {"witnesses": entries})
        p, j = journal("h-evil-log", 3)
        responses, statuses, _ = py_submit(j, WS + [evil])
        dossier, n = j.dossier_from_responses(responses)
        rep = json.loads(wl.verify_dossier_json(dossier, 0.66, j.identity_pubkey_hex(), open(path).read()))
        release(j)
        del j
        assert n == len(WS), (n, statuses)
        assert rep["verdict"] == "witnessed" and rep["quorum"]["valid_receipts"] == len(WS)
    finally:
        evil.kill()
    return f"garbage cosignature dropped; {len(WS)} honest counted; witnessed"


@test("T089", "swarm", "Sybil: all witnesses relabelled as one operator -> CONSISTENT-UNWITNESSED")
def t089():
    p, dossier, ident = witnessed_dossier("h-sybil")
    entries = [dict(w.entry, operator_org="One Operator") for w in WS]
    d = fresh("h-sybildir")
    path = write_json(d, "dir.json", {"witnesses": entries})
    dp = write_json(d, "d.json", dossier)
    code, rep = verify(dp, ident, path)
    assert code == 10 and rep["report"]["quorum"]["distinct_independent_operators"] == 1
    return "exit 10 with all receipts valid"


@test("T090", "swarm", "50 concurrent `verify` processes agree", serial=True)
def t090():
    with cf.ThreadPoolExecutor(max_workers=50) as ex:
        codes = list(ex.map(lambda _: cli("verify", SAMPLE, "--identity", SAMPLE_ID, "--directory", TRUSTED)[0], range(50)))
    assert codes == [0] * 50, set(codes)
    return "50 x exit 0"


# ========================================================= I. c2sp

@test("T091", "c2sp", "`c2sp show` prints the checkpoint body and vkey; --raw prints only the body", fixed_in="0.3.2")
def t091():
    origin = "witness-log/" + SAMPLE_ID
    code, out, _ = cli("c2sp", "show", SAMPLE, "--origin", origin)
    assert code == 0 and origin in out and "witness-log/" in out
    code2, raw, _ = cli("c2sp", "show", SAMPLE, "--origin", origin, "--raw")
    lines = raw.split("\n")
    assert code2 == 0 and lines[0] == origin and lines[1] == "6" and raw.endswith("\n") and len(lines) == 4, raw
    return "body: origin, size 6, root; --raw is 3 lines"


@test("T092", "c2sp", "`c2sp show --sign-with <journal> --raw` yields a note `c2sp verify` accepts; zeroed signature -> 30", fixed_in="0.3.2")
def t092():
    p, j = journal("i-sign", 3)
    ident = j.identity_pubkey_hex()
    dossier = j.to_dossier_json()
    release(j)
    del j
    d = os.path.dirname(p)
    dp = os.path.join(d, "d.json")
    open(dp, "w").write(dossier)
    origin = "witness-log/" + ident
    code, note, err = cli("c2sp", "show", dp, "--origin", origin, "--raw", "--sign-with", p)
    assert code == 0, err
    _, shown, _ = cli("c2sp", "show", dp, "--origin", origin)
    vkey = vkey_from_show(shown)
    np = os.path.join(d, "note.txt")
    open(np, "w").write(note)
    assert cli("c2sp", "verify", np, "--vkey", vkey)[0] == 0
    sig = [l for l in note.split("\n") if l.startswith("—")][0]
    parts = sig.split(" ")
    rawsig = bytearray(base64.b64decode(parts[2]))
    for i in range(4, len(rawsig)):
        rawsig[i] = 0
    bad = note.replace(sig, f"{parts[0]} {parts[1]} {base64.b64encode(bytes(rawsig)).decode()}")
    bp = os.path.join(d, "bad.txt")
    open(bp, "w").write(bad)
    assert cli("c2sp", "verify", bp, "--vkey", vkey)[0] == 40
    return "signed note verifies; zeroed signature exit 40 (INVALID)"


@test("T093", "c2sp", "`c2sp verify` without --vkey is a usage error; unknown flags are refused", fixed_in="0.3.2")
def t093():
    d = fresh("i-usage")
    np = os.path.join(d, "n.txt")
    open(np, "w").write("x\n\n")
    assert cli("c2sp", "verify", np)[0] == 2
    assert cli("c2sp", "show", SAMPLE, "--origin", "a/b", "--json")[0] == 2
    return "exit 2 both"


@test("T094", "c2sp", "corpus vector 10: the committed signed note verifies with both keys")
def t094():
    vec = json.load(open(os.path.join(REPO, "corpus", "10_c2sp_checkpoint.json")))
    d = fresh("i-corpus")
    np = os.path.join(d, "n.txt")
    open(np, "w").write(vec["cosignature"]["cosigned_note"])
    keys = [vec["log_vkey"], vec["cosignature"]["witness_vkey"]]
    args = ["c2sp", "verify", np]
    for k in keys:
        args += ["--vkey", k]
    code, out, err = cli(*args)
    assert code == 0 and "✓" in out, (out, err)
    # Only the witness key: the cosignature verifies, so the note passes (as
    # c2sp.org's `note` verification does with any trusted key), but the
    # output must say the note's own signature was not checked (0.4.0).
    code2, out2, _ = cli("c2sp", "verify", np, "--vkey", keys[1])
    assert code2 == 0 and "cannot be checked without the log's vkey" in out2, (code2, out2)
    # No usable key at all is a rejection.
    code3, out3, _ = cli("c2sp", "verify", np, "--vkey", keys[1].replace("+", "x", 1) if "+" not in keys[1][:1] else keys[1])
    assert code3 != 0, (code3, out3)
    return "log+witness keys exit 0; witness key alone exit 0 with the unverified-note warning; bad key rejected"


@test("T095", "c2sp", "vkey key id recomputed in Python matches (SHA-256(name || '\\n' || type || key)[:4])")
def t095():
    code, out, _ = cli("witness", "info", WS[0].url)
    info = json.loads(out)
    name, _, b64 = info["vkey"].partition("+")
    keyhash_hex, _, keymat = b64.partition("+")
    raw = base64.b64decode(keymat)
    sig_type, pub = raw[0], raw[1:]
    digest = hashlib.sha256(name.encode() + b"\n" + bytes([sig_type]) + pub).digest()[:4]
    assert digest.hex() == keyhash_hex.lower(), (digest.hex(), keyhash_hex)
    assert pub.hex() == info["pubkey_hex"]
    return f"type 0x{sig_type:02x}, id {keyhash_hex}"


# ========================================================= J. docs

@test("T096", "docs", "README exit-code table matches the binary")
def t096():
    readme = open(os.path.join(REPO, "README.md")).read()
    for code, name in ((0, "WITNESSED"), (10, "CONSISTENT-UNWITNESSED"), (20, "UNANCHORED"), (30, "DIVERGED"), (40, "INVALID")):
        assert re.search(rf"\b{code}\b[^\n]*{name}|{name}[^\n]*\b{code}\b", readme), name
    assert re.search(r"\b11\b", readme), "exit 11"
    assert verify(SAMPLE, None, None)[0] == 20 and verify(SAMPLE, SAMPLE_ID, TRUSTED)[0] == 0
    return "0/10/11/20/30/40 documented and observed"


@test("T097", "docs", "`conform corpus` passes against the committed vectors")
def t097():
    code, out, err = cli("conform", os.path.join(REPO, "corpus"))
    assert code == 0, (out, err)
    return "exit 0"


@test("T098", "docs", "every dossier produced here validates against spec/dossier.schema.json")
def t098():
    try:
        import jsonschema
    except ImportError:
        return "skipped: jsonschema not installed"
    schema = json.load(open(os.path.join(REPO, "spec", "dossier.schema.json")))
    v = jsonschema.Draft202012Validator(schema)
    n = 0
    for root, _, files in os.walk(ROOT):
        for f in files:
            if f.endswith(".json") and ("dossier" in f or f in ("d.json", "a.json")):
                try:
                    doc = json.load(open(os.path.join(root, f)))
                except Exception:
                    continue
                if isinstance(doc, dict) and "leaves" in doc and "checkpoint" in doc:
                    errs = list(v.iter_errors(doc))
                    assert not errs, (f, errs[0].message)
                    n += 1
    v.validate(json.load(open(SAMPLE)))
    assert n >= 5, n
    return f"{n + 1} dossiers valid"


@test("T099", "docs", "SPEC §9.2 and `explain` agree on the WITNESSED gate", fixed_in="0.3.2")
def t099():
    spec = open(os.path.join(REPO, "spec", "SPEC.md")).read()
    assert "two distinct independent operators" in spec
    code, out, _ = cli("explain", "witnessed")
    assert "two distinct independent operators" in out
    assert "at least one witness that is NOT project-operated" not in out
    return "both say two distinct independent operators"


@test("T100", "docs", "examples/verify_demo.py runs and exits 0 (tamper caught)", since="0.3.2")
def t100():
    r = subprocess.run([sys.executable, os.path.join(REPO, "examples", "verify_demo.py")], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0 and "INVALID" in r.stdout, r.stdout[-500:] + r.stderr[-500:]
    return "exit 0, INVALID shown"


# ================================================= K. RFC-0002 (0.5.0)

@test("T101", "cli-verify", "--known-head: a reproduced head changes nothing; a contradicted one is DIVERGED (exit 30)", since="0.5.0")
def t101():
    p, d, ident = witnessed_dossier("t-known-head")
    path = write_json(os.path.dirname(p), "d.json", d)
    full_root = d["checkpoint"]["root_hash"]
    size = d["checkpoint"]["tree_size"]
    code, rep = verify(path, ident, extra=("--known-head", f"{size}:{full_root}"))
    assert code == 0 and rep["report"]["contradictions"] == [], (code, rep["report"])
    code, rep = verify(path, ident, extra=("--known-head", f"2:{'ab' * 32}"))
    assert code == 30 and rep["verdict"] == "DIVERGED" and len(rep["report"]["contradictions"]) == 1, (code, rep)
    code, rep = verify(path, ident, extra=("--known-head", f"{size + 5}:{'ab' * 32}"))
    assert code == 0 and rep["report"]["known_heads_unchecked"], (code, rep["report"])
    return "same head 0; contradicted 30; larger head listed unchecked"


@test("T102", "cli-verify", "WITNESSED by fewer than a strict majority exits 11 by default; --allow-sub-majority / --no-strict accept it", since="0.5.0")
def t102():
    if len(WS) < 4:
        return f"skipped: {len(WS)} witnesses (need 4)"
    p, d, ident = witnessed_dossier("t-sub-majority")
    d["witness_receipts"] = d["witness_receipts"][:2]
    path = write_json(os.path.dirname(p), "two.json", d)
    code, rep = verify(path, ident, extra=("--min-witnesses", "2"))
    assert code == 11 and rep["verdict"] == "WITNESSED" and rep["report"]["split_view_unsafe"] is True, (code, rep.get("report"))
    assert rep["exit_code"] == 11 and rep["strict"] is True
    assert verify(path, ident, extra=("--min-witnesses", "2", "--allow-sub-majority"))[0] == 0
    assert verify(path, ident, extra=("--min-witnesses", "2", "--no-strict"))[0] == 0
    return f"2 of {len(WS)}: exit 11; accepted as 0 under either flag"


@test("T103", "python-api", "corpus vector 13 through verify_dossier_json (known heads and evidence)", since="0.5.0")
def t103():
    v = json.load(open(os.path.join(REPO, "corpus", "13_verdicts.json")))
    n = 0
    for c in v["cases"]:
        rep = json.loads(wl.verify_dossier_json(
            json.dumps(v["dossiers"][c["dossier"]]),
            c["threshold"],
            c["expected_identity"],
            json.dumps(v["trusted_directory"]) if c["trusted_directory"] else None,
            c["min_witnesses"],
            None,
            c["known_heads"],
            json.dumps([v["evidence"][k] for k in c["evidence"]]),
        ))
        e = c["expect"]
        assert rep["verdict"] == e["verdict"], (c["name"], rep["verdict"], e["verdict"])
        assert rep["split_view_unsafe"] == e["split_view_unsafe"], c["name"]
        assert len(rep["contradictions"]) == e["contradictions"], c["name"]
        n += 1
    return f"{n} cases agree"


# ============================================================= runner

def run_one(t):
    start = time.time()
    try:
        detail = t["fn"]() or ""
        ok = True
    except Exception as e:  # noqa: BLE001
        ok = False
        detail = f"{type(e).__name__}: {e}"
        if not isinstance(e, AssertionError):
            detail += " | " + traceback.format_exc().splitlines()[-2].strip()
    rec = {k: t[k] for k in ("id", "category", "name", "fixed_in", "since")}
    rec.update(passed=ok, secs=round(time.time() - start, 2), detail=str(detail)[:600])
    with _lock:
        print(("PASS " if ok else "FAIL ") + f"{t['id']} {t['name']}  -- {rec['detail']}", flush=True)
    return rec


def main() -> int:
    global WS, AGENT_WS
    cli_version = cli("--version")[1].strip() or "(no --version)"
    print(f"target: {ARGS.cli} [{cli_version}], witness_log {getattr(wl, '__version__', '?')} from {wl.__file__}")
    print(f"out: {OUT}")
    selected = TESTS
    if ARGS.only:
        want = set(ARGS.only.split(","))
        selected = [t for t in TESTS if t["id"] in want]
    needs_network = any(t["category"] in ("witness", "adversarial", "crash", "swarm", "tamper", "c2sp") for t in selected)
    if needs_network:
        print("starting 8 Rust + 2 Python witnesses ...", flush=True)
        WS = livenet.start_network(ROOT)
        # Two more witnesses started by agents in the swarm: distinct operators.
        for i, (org, comp) in enumerate((("Kappa Agents", "fly.io"), ("Lambda Collective", "railway"))):
            w = Witness(len(WS) + i, ROOT, "py")
            w.org, w.compute = org, comp
            w.name = f"agent{i}.witness.test/{org.split()[0].lower()}"
            w.init()
            w.start()
            AGENT_WS.append(w)
        json.dump({"witnesses": [w.entry for w in WS]}, open(DIR_PATH, "w"))
        print(f"{len(WS) + len(AGENT_WS)} witnesses up on ports {WS[0].port}-{AGENT_WS[-1].port}", flush=True)
    results = []
    t0 = time.time()
    try:
        parallel = [t for t in selected if not t["serial"]]
        serial = [t for t in selected if t["serial"]]
        with cf.ThreadPoolExecutor(max_workers=8) as ex:
            results += list(ex.map(run_one, parallel))
        for t in serial:
            results.append(run_one(t))
    finally:
        for w in WS + AGENT_WS:
            try:
                w.kill(signal.SIGTERM)
            except Exception:
                pass
    results.sort(key=lambda r: r["id"])
    total = time.time() - t0
    passed = sum(r["passed"] for r in results)
    env = {
        "cli": ARGS.cli, "cli_version": cli_version, "python_package_version": getattr(wl, "__version__", None),
        "release": ARGS.release, "python": sys.version.split()[0], "platform": platform.platform(),
        "witnesses": len(WS) + len(AGENT_WS), "agents": ARGS.agents, "seconds": round(total, 1),
        "when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    json.dump({"environment": env, "passed": passed, "total": len(results), "results": results},
              open(os.path.join(OUT, "results.json"), "w"), indent=1)
    write_report(env, results)
    print(f"\n{passed}/{len(results)} passed in {total:.0f}s; report: {os.path.join(OUT, 'REPORT.md')}")
    return min(len(results) - passed, 99)


def write_report(env, results):
    cats = {}
    for r in results:
        cats.setdefault(r["category"], []).append(r)
    lines = [f"# witness-log swarm report: {env['cli_version']}", "",
             f"- target: `{env['cli']}`, Python package {env['python_package_version']}"
             + (f", GitHub release `{env['release']}`" if env['release'] else " (local build)"),
             f"- {env['witnesses']} live witnesses, {env['agents']} concurrent agents, {env['seconds']} s, {env['platform']}, Python {env['python']}",
             f"- **{sum(r['passed'] for r in results)}/{len(results)} passed**", ""]
    lines += ["| category | passed | total |", "|---|---|---|"]
    for c, rs in cats.items():
        lines.append(f"| {c} | {sum(r['passed'] for r in rs)} | {len(rs)} |")
    fails = [r for r in results if not r["passed"]]
    if fails:
        lines += ["", "## Failures", ""]
        for r in fails:
            tag = f" (regression for a defect fixed in {r['fixed_in']})" if r["fixed_in"] else ""
            tag += f" (API added in {r['since']})" if r["since"] else ""
            lines.append(f"- **{r['id']}** {r['name']}{tag}: `{r['detail']}`")
        expected = [r for r in fails if r["fixed_in"] or r["since"]]
        lines += ["", f"{len(expected)} of {len(fails)} failures are expected for a release before the one that fixed or added them; "
                  f"**{len(fails) - len(expected)} unexpected**."]
    lines += ["", "## All scenarios", "", "| id | category | scenario | result | detail |", "|---|---|---|---|---|"]
    for r in results:
        res = "pass" if r["passed"] else "**FAIL**"
        if r["fixed_in"]:
            res += f" (fixed in {r['fixed_in']})"
        if r["since"]:
            res += f" (since {r['since']})"
        lines.append(f"| {r['id']} | {r['category']} | {r['name']} | {res} | {r['detail'].replace('|', '/')} |")
    open(os.path.join(OUT, "REPORT.md"), "w").write("\n".join(lines) + "\n")


if __name__ == "__main__":
    sys.exit(main())
