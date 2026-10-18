"""witness-log-hook + witness-log-hookd: event normalization, a daemon and
client round trip over a temp Unix socket, autostart, and the printed
install snippets. Unix sockets only, so skipped on Windows."""

from __future__ import annotations

import io
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

import pytest
import witness_log as wl
from witness_log import hook, hookd

pytestmark = pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="Unix sockets only")


@pytest.fixture
def daemon(tmp_path):
    sock = str(tmp_path / "s.sock")
    d = hookd.Hookd(str(tmp_path / "hooks.jsonl"), sock)
    d.bind()
    t = threading.Thread(target=d.serve_forever, daemon=True)
    t.start()
    yield d
    d.shutdown()
    t.join(5)


# --- normalization ------------------------------------------------------------


def test_normalize_claude_code_shapes():
    pre = {
        "session_id": "abc",
        "transcript_path": "/home/u/.claude/t.jsonl",
        "cwd": "/repo",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "tool_use_id": "toolu_1",
    }
    leaf, payload = hook.normalize(pre)
    assert leaf == "intent"
    assert payload == {
        "profile": "hook.claude-code v1",
        "event": "PreToolUse",
        "session_id": "abc",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "tool_use_id": "toolu_1",
        "cwd": "/repo",
    }
    post = {**pre, "hook_event_name": "PostToolUse", "tool_response": {"stdout": "a\n"}}
    leaf, payload = hook.normalize(post)
    assert leaf == "result" and payload["tool_response"] == {"stdout": "a\n"} and "transcript_path" not in payload
    leaf, payload = hook.normalize({"hook_event_name": "Stop", "session_id": "abc", "stop_hook_active": False})
    assert leaf == "memory" and payload["stop_hook_active"] is False


def test_normalize_generic_and_unknown_shapes():
    assert hook.normalize({"tool": "search", "args": {"q": 1}}) == (
        "intent",
        {"profile": "hook.generic v1", "tool": "search", "args": {"q": 1}},
    )
    leaf, p = hook.normalize({"tool": "search", "args": {"q": 1}, "result": [1]})
    assert leaf == "result" and p["result"] == [1]
    leaf, p = hook.normalize({"tool_name": "edit", "tool_input": {"f": "a.py"}, "tool_response": "ok"})
    assert leaf == "result" and p["tool"] == "edit" and p["args"] == {"f": "a.py"} and p["result"] == "ok"
    assert hook.normalize({"tool": "x", "kind": "memory"})[0] == "memory"
    assert hook.normalize({"tool": "x"}, "result")[0] == "result"  # --kind wins
    assert hook.normalize({"something": "else"}) == ("memory", {"profile": "hook.generic v1", "event": {"something": "else"}})
    assert hook.normalize("text")[0] == "memory"


# --- daemon + client round trip ----------------------------------------------


def test_round_trip_over_socket(daemon, tmp_path):
    ev = {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": {"command": "ls"}}
    assert hook.main(["--socket", daemon.socket_path], stdin=io.StringIO(json.dumps(ev))) == 0
    ev2 = {**ev, "hook_event_name": "PostToolUse", "tool_response": {"stdout": ""}}
    assert hook.main(["--socket", daemon.socket_path], stdin=io.StringIO(json.dumps(ev2))) == 0
    st = hook.request(daemon.socket_path, {"op": "status"})
    assert st["ok"] and st["leaf_count"] == 2 and st["witnessed"] is False
    ex = hook.request(daemon.socket_path, {"op": "export"})
    assert ex["ok"] and pathlib.Path(ex["path"]).exists() and ex["bytes"] > 0
    dossier = json.loads(pathlib.Path(ex["path"]).read_text())
    assert [l["leaf_type"] for l in dossier["leaves"]] == [1, 2]
    assert json.loads(wl.verify_dossier_json(json.dumps(dossier), 0.66, st["identity"]))["verdict"] == "unanchored"
    # The payload the daemon committed is the normalized event as JCS.
    _, payload = hook.normalize(ev)
    d = daemon.log.disclose(0)
    assert wl.verify_disclosure(dossier["leaves"][0], wl.canonical_json(payload), d["salt"])
    # Bad requests are answered, not fatal.
    assert hook.request(daemon.socket_path, {"op": "append", "leaf": "bogus", "payload": 1})["ok"] is False
    assert hook.request(daemon.socket_path, {"op": "nope"})["ok"] is False
    assert hook.request(daemon.socket_path, {"op": "submit"})["ok"] is False  # no --directory
    if os.name == "posix":
        assert oct(os.stat(daemon.socket_path).st_mode & 0o777) == "0o600"


def test_parallel_hooks_all_land(daemon):
    def one(i):
        ev = {"tool": "t", "args": {"i": i}}
        assert hook.main(["--socket", daemon.socket_path], stdin=io.StringIO(json.dumps(ev))) == 0

    ts = [threading.Thread(target=one, args=(i,)) for i in range(20)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(10)
    assert hook.request(daemon.socket_path, {"op": "status"})["leaf_count"] == 20


def test_missing_daemon_is_not_fatal_unless_strict(tmp_path, capsys):
    sock = str(tmp_path / "none.sock")
    assert hook.main(["--socket", sock], stdin=io.StringIO('{"tool": "x"}')) == 0
    assert "not recorded" in capsys.readouterr().err
    assert hook.main(["--socket", sock, "--strict"], stdin=io.StringIO('{"tool": "x"}')) == 2
    assert hook.main(["--socket", sock], stdin=io.StringIO("not json")) == 0  # malformed stdin: also exit 0


def test_autostart_spawns_the_daemon_and_second_daemon_is_refused(tmp_path):
    sock = str(tmp_path / "auto.sock")
    journal = str(tmp_path / "auto.jsonl")
    try:
        r = subprocess.run(
            [sys.executable, "-m", "witness_log.hook", "--autostart", "--journal", journal, "--socket", sock],
            input='{"tool": "a", "args": 1}',
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert r.returncode == 0 and r.stderr == "", r.stderr
        st = hook.request(sock, {"op": "status"})
        assert st["leaf_count"] == 1 and st["journal"] == journal
        # The same socket again: no second daemon, same journal.
        r = subprocess.run(
            [sys.executable, "-m", "witness_log.hook", "--autostart", "--journal", journal, "--socket", sock],
            input='{"tool": "b", "args": 2, "result": 3}',
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert r.returncode == 0
        assert hook.request(sock, {"op": "status"})["leaf_count"] == 2
        # A daemon asked to bind a live socket refuses.
        with pytest.raises(OSError, match="already listening"):
            hookd.Hookd(str(tmp_path / "other.jsonl"), sock).bind()
    finally:
        try:
            hook.request(sock, {"op": "shutdown"})
        except OSError:
            pass
    for _ in range(100):
        if not os.path.exists(sock):
            break
        time.sleep(0.05)
    assert not os.path.exists(sock)
    # The journal is released: it can be opened again and holds both leaves.
    log = wl.open(journal)
    assert log.tree_size() == 2


def test_stale_socket_file_is_replaced(tmp_path):
    sock = tmp_path / "stale.sock"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(sock))
    s.close()  # a file nobody listens on
    d = hookd.Hookd(str(tmp_path / "j.jsonl"), str(sock))
    d.bind()
    d.close()
    assert not sock.exists()


# --- where the socket lives and who it talks to (security sweep F8) ---------------
#
# Through 0.6.0, without XDG_RUNTIME_DIR the socket was
# <tmp>/witness-log-hookd-<uid>.sock, a name in a shared directory, and the
# hook connected to whatever listened there and sent tool_input and
# tool_response in plaintext: another local user could bind it first.


def _fallback(monkeypatch, tmp_path):
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    return hookd.default_socket_path()


def test_without_xdg_runtime_dir_the_socket_is_in_a_private_directory(tmp_path, monkeypatch):
    path = _fallback(monkeypatch, tmp_path)
    assert path == str(tmp_path / f"witness-log-{os.getuid()}" / "hookd.sock")
    assert not os.path.exists(os.path.dirname(path))  # computing the default creates nothing
    d = hookd.Hookd(str(tmp_path / "j.jsonl"))
    d.bind()
    t = threading.Thread(target=d.serve_forever, daemon=True)
    t.start()
    try:
        st = os.lstat(os.path.dirname(path))
        assert st.st_uid == os.getuid() and oct(st.st_mode & 0o777) == "0o700"
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"
        assert hook.main([], stdin=io.StringIO('{"tool": "x"}')) == 0  # the hook finds it by default
        assert hook.request(path, {"op": "status"})["leaf_count"] == 1
    finally:
        d.shutdown()
        t.join(5)


@pytest.mark.parametrize("planted", ["group/other mode", "symlink", "file"])
def test_the_daemon_refuses_a_fallback_directory_someone_else_could_use(tmp_path, monkeypatch, planted):
    path = _fallback(monkeypatch, tmp_path)
    where = os.path.dirname(path)
    if planted == "group/other mode":
        os.mkdir(where)
        os.chmod(where, 0o755)
    elif planted == "symlink":
        os.mkdir(tmp_path / "elsewhere", 0o700)
        os.symlink(tmp_path / "elsewhere", where)
    else:
        open(where, "w").close()
    d = hookd.Hookd(str(tmp_path / "j.jsonl"))
    try:
        with pytest.raises(OSError, match="must be 0700|not a directory"):
            d.bind()
    finally:
        d.close()
    assert not (tmp_path / "elsewhere" / "hookd.sock").exists()


def test_a_directory_owned_by_another_user_is_refused(tmp_path, monkeypatch):
    where = tmp_path / "witness-log-x"
    os.mkdir(where, 0o700)
    real = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: real + 1)  # the directory is now someone else's
    with pytest.raises(OSError, match="owned by uid"):
        hookd.private_dir(str(where))


def test_the_hook_sends_nothing_to_a_socket_another_user_owns(tmp_path, monkeypatch):
    sock = str(tmp_path / "planted.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock)
    srv.listen(4)
    srv.settimeout(0.5)
    try:
        real = os.getuid()
        monkeypatch.setattr(os, "getuid", lambda: real + 1)  # the socket file is now someone else's
        with pytest.raises(OSError, match="owned by uid"):
            hook.request(sock, {"op": "append", "leaf": "intent", "payload": {"secret": 1}}, timeout=2.0)
        event = json.dumps({"tool": "x", "args": {"secret": 1}})
        assert hook.main(["--socket", sock, "--strict"], stdin=io.StringIO(event)) == 2
        assert hook.main(["--socket", sock], stdin=io.StringIO(event)) == 0  # never fatal without --strict
        monkeypatch.undo()
        with pytest.raises(socket.timeout):  # noqa: UP041
            srv.accept()  # nobody even connected
    finally:
        srv.close()


@pytest.mark.skipif(not hasattr(socket, "SO_PEERCRED"), reason="SO_PEERCRED is Linux")
def test_peer_uid_is_the_daemons(daemon):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(daemon.socket_path)
        assert hook.peer_uid(s) == os.getuid()
    finally:
        s.close()


_CHILD_AS_NOBODY = "import os, socket, sys\ns = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.bind(sys.argv[1])\nos.setgid(65534); os.setuid(65534); s.listen(1)\nprint('ready', flush=True); c, _ = s.accept(); c.settimeout(2)\ntry:\n    data = c.recv(65536)\nexcept OSError:\n    data = b''\nprint(len(data), flush=True)\n"


@pytest.mark.skipif(
    not (hasattr(socket, "SO_PEERCRED") and hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs Linux and root to listen as another uid",
)
def test_the_hook_refuses_a_listener_running_as_another_user(tmp_path):
    """The socket file is ours (bound as root), but the process listening on
    it dropped to uid 65534 before listen(): only SO_PEERCRED can tell, and
    the hook must send nothing."""
    sock = str(tmp_path / "s.sock")
    child = subprocess.Popen([sys.executable, "-c", _CHILD_AS_NOBODY, sock], stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "ready"
        assert os.stat(sock).st_uid == os.getuid()
        with pytest.raises(OSError, match="runs as uid 65534"):
            hook.request(sock, {"op": "append", "leaf": "intent", "payload": {"secret": 1}}, timeout=2.0)
        assert child.stdout.readline().strip() == "0"  # connected, but received nothing
    finally:
        child.kill()
        child.wait(5)


# --- install snippets -----------------------------------------------------------


def test_install_prints_snippets_without_writing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for host in ("claude-code", "cursor", "codex"):
        out = io.StringIO()
        assert hook.main(["install", host, "--journal", "/j.jsonl", "--socket", "/s.sock"], stdout=out) == 0
        text = out.getvalue()
        assert "witness-log-hook --autostart --journal /j.jsonl --socket /s.sock" in text
    assert list(tmp_path.iterdir()) == []  # nothing written
    out = io.StringIO()
    hook.main(["install", "claude-code"], stdout=out)
    body = "\n".join(line for line in out.getvalue().splitlines() if not line.startswith("#"))
    cfg = json.loads(body)
    assert set(cfg["hooks"]) == {"PreToolUse", "PostToolUse"}
    assert cfg["hooks"]["PreToolUse"][0]["hooks"][0]["type"] == "command"
    with pytest.raises(SystemExit):
        hook.main(["install", "emacs"], stdout=io.StringIO())


def test_cli_errors():
    r = subprocess.run([sys.executable, "-m", "witness_log.hook", "--autostart"], input="{}", capture_output=True, text=True)
    assert r.returncode == 2 and "--journal" in r.stderr
    r = subprocess.run([sys.executable, "-m", "witness_log.hookd", "--journal", "j", "--submit-every", "2"], capture_output=True, text=True)
    assert r.returncode == 2 and "--directory" in r.stderr
