"""witness-log-hook: record a coding agent's tool call from a hook.

::

    # as a Claude Code PreToolUse / PostToolUse hook (reads the event on stdin)
    witness-log-hook --autostart --journal ~/.witness-log/claude-code.jsonl

    # print the settings snippet for a host
    witness-log-hook install claude-code
    witness-log-hook install cursor
    witness-log-hook install codex

The hook reads one JSON event from stdin, turns it into a leaf and sends
it to ``witness-log-hookd`` over a Unix socket (``--socket``, default
``witness_log.hookd.default_socket_path()``). With ``--autostart`` and
``--journal`` it starts the daemon when none is listening. It exits 0
whatever happens, so an audit-trail problem never blocks the agent;
``--strict`` exits 2 instead (Claude Code then blocks the tool call and
shows the reason), for environments where an unrecorded action is worse
than a stopped one.

Event shapes, in the order they are tried:

* Claude Code: ``hook_event_name`` is present. ``PreToolUse`` becomes an
  intent leaf, ``PostToolUse`` a result leaf; any other event
  (``UserPromptSubmit``, ``Stop``, ``Notification``, ...) a memory leaf.
  The payload is ``{"profile": "hook.claude-code v1", "event",
  "session_id", "tool_name", "tool_input"}`` plus ``"tool_use_id"`` and
  ``"cwd"`` when present and ``"tool_response"`` for ``PostToolUse``;
  ``transcript_path`` is not recorded.
* Generic: ``{"tool": ..., "args": ..., "result": ...}``. With
  ``"result"`` present it is a result leaf, else an intent leaf; a
  ``"kind"`` field (``"intent"``/``"result"``/``"memory"``) or ``--kind``
  overrides. Payload ``{"profile": "hook.generic v1", "tool", "args"}``
  (+ ``"result"``). Hosts whose events carry ``tool_name``/``tool_input``
  (and ``tool_response``/``output``) without ``hook_event_name`` are read
  the same way.
* Anything else is recorded whole as a memory leaf under
  ``{"profile": "hook.generic v1", "event": <the object>}``, so an
  unexpected shape is still on the record.

Payloads are committed as RFC 8785 canonical JSON and salted per leaf;
``log.disclose(i)`` on the journal reveals one, ``log.forget(i)`` erases
one.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import socket
import struct
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from .hookd import default_socket_path

PROFILE_CLAUDE = "hook.claude-code v1"
PROFILE_GENERIC = "hook.generic v1"


def normalize(event: Any, kind: Optional[str] = None) -> Tuple[str, Dict[str, Any]]:
    """``(leaf_kind, payload)`` for a hook event. See the module docstring
    for the shapes."""
    if isinstance(event, dict) and isinstance(event.get("hook_event_name"), str):
        name = event["hook_event_name"]
        payload: Dict[str, Any] = {"profile": PROFILE_CLAUDE, "event": name}
        for k in ("session_id", "tool_name", "tool_input", "tool_use_id", "cwd"):
            if k in event:
                payload[k] = event[k]
        if name == "PreToolUse":
            leaf = "intent"
        elif name == "PostToolUse":
            leaf = "result"
            if "tool_response" in event:
                payload["tool_response"] = event["tool_response"]
        else:
            leaf = "memory"
            for k, v in event.items():
                if k not in payload and k != "transcript_path":
                    payload[k] = v
        return kind or leaf, payload
    if isinstance(event, dict) and ("tool" in event or "tool_name" in event):
        tool = event.get("tool", event.get("tool_name"))
        args = event.get("args", event.get("arguments", event.get("tool_input")))
        payload = {"profile": PROFILE_GENERIC, "tool": tool, "args": args}
        leaf = "intent"
        for k in ("result", "tool_response", "output"):
            if k in event:
                payload["result"] = event[k]
                leaf = "result"
                break
        if isinstance(event.get("kind"), str) and event["kind"] in ("intent", "result", "memory"):
            leaf = event["kind"]
        return kind or leaf, payload
    return kind or "memory", {"profile": PROFILE_GENERIC, "event": event}


def peer_uid(s: socket.socket) -> Optional[int]:
    """The uid of the process at the other end of a connected Unix
    socket (Linux ``SO_PEERCRED``), or None where it is not available."""
    if not hasattr(socket, "SO_PEERCRED"):
        return None
    _pid, uid, _gid = struct.unpack("3i", s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    return uid


def _check_owner(socket_path: str) -> None:
    """Refuse a socket file another user owns: whoever listens on it would
    receive every tool call's input and output."""
    if not hasattr(os, "getuid"):
        return
    st = os.stat(socket_path)
    if st.st_uid != os.getuid():
        raise OSError(
            f"refusing {socket_path}: the socket is owned by uid {st.st_uid}, not you (uid {os.getuid()}); "
            "another user may be listening for your tool calls"
        )


def request(socket_path: str, req: Dict[str, Any], timeout: float = 10.0) -> Dict[str, Any]:
    """One request/reply on the daemon's socket. Raises ``OSError`` when
    nothing is listening, when the socket or (on Linux) the process
    listening on it belongs to another user (nothing is sent then), and
    ``ValueError`` on a malformed reply."""
    _check_owner(socket_path)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect(socket_path)
        uid = peer_uid(s)
        if uid is not None and uid != os.getuid():
            raise OSError(
                f"refusing {socket_path}: the process listening on it runs as uid {uid}, not you "
                f"(uid {os.getuid()}); nothing was sent"
            )
        s.sendall(json.dumps(req, separators=(",", ":")).encode() + b"\n")
        f = s.makefile("rb")
        line = f.readline()
    finally:
        s.close()
    if not line:
        raise OSError("daemon closed the connection without replying")
    reply = json.loads(line)
    if not isinstance(reply, dict):
        raise ValueError("malformed reply from daemon")
    return reply


def ensure_daemon(socket_path: str, journal: str, *, directory: Optional[str] = None, submit_every: int = 0, wait: float = 5.0) -> None:
    """Start ``witness-log-hookd`` detached if nothing answers on
    ``socket_path``, and wait until it does."""
    try:
        request(socket_path, {"op": "status"}, timeout=1.0)
        return
    except (OSError, ValueError):
        pass
    cmd = [sys.executable, "-m", "witness_log.hookd", "--journal", journal, "--socket", socket_path]
    if directory:
        cmd += ["--directory", directory]
    if submit_every:
        cmd += ["--submit-every", str(submit_every)]
    subprocess.Popen(  # noqa: S603 -- our own module
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        try:
            request(socket_path, {"op": "status"}, timeout=1.0)
            return
        except (OSError, ValueError):
            time.sleep(0.05)
    raise OSError(f"witness-log-hookd did not come up on {socket_path} within {wait:g}s")


# ---------------------------------------------------------------- install


def _snippet(host: str, journal: str, socket_path: Optional[str]) -> str:
    cmd = f"witness-log-hook --autostart --journal {shlex.quote(journal)}"
    if socket_path:
        cmd += f" --socket {shlex.quote(socket_path)}"
    if host == "claude-code":
        settings = {
            "hooks": {
                "PreToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": cmd}]}],
                "PostToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": cmd}]}],
            }
        }
        return (
            "# Claude Code: merge into .claude/settings.json (project) or ~/.claude/settings.json (user).\n"
            "# Every tool call becomes an intent leaf (PreToolUse) and a result leaf (PostToolUse).\n"
            "# Add --strict to the command to block tool calls when the trail cannot be written.\n"
            + json.dumps(settings, indent=2)
            + "\n"
        )
    if host == "cursor":
        hooks = {
            "version": 1,
            "hooks": {
                "beforeShellExecution": [{"command": cmd + " --kind intent"}],
                "beforeMCPExecution": [{"command": cmd + " --kind intent"}],
                "afterFileEdit": [{"command": cmd + " --kind result"}],
            },
        }
        return (
            "# Cursor: hooks.json (project .cursor/hooks.json or ~/.cursor/hooks.json).\n"
            "# Check the event names against the Cursor hooks documentation for your version;\n"
            "# the hook reads whatever JSON the event delivers (tool_name/command fields are\n"
            "# recorded under the generic profile, unknown shapes as a memory leaf).\n"
            + json.dumps(hooks, indent=2)
            + "\n"
        )
    if host == "codex":
        return (
            "# Codex CLI: hook support and its configuration keys depend on the Codex version;\n"
            "# wire any hook that pipes a JSON event to this command:\n"
            f"#   {cmd}\n"
            "# The command accepts Claude Code's hook payload, or the generic shape\n"
            '#   {"tool": "<name>", "args": {...}}            -> intent leaf\n'
            '#   {"tool": "<name>", "args": {...}, "result": ...} -> result leaf\n'
            "# and records anything else whole as a memory leaf. For an MCP-based setup,\n"
            "# witness-log-mcp-proxy wraps the server instead and needs no hook.\n"
        )
    raise ValueError(f"unknown host {host!r}; expected claude-code, cursor or codex")


# ---------------------------------------------------------------------- main


def main(argv: Optional[List[str]] = None, stdin: Any = None, stdout: Any = None) -> int:
    ap = argparse.ArgumentParser(
        prog="witness-log-hook",
        description="Record a tool event from stdin into a witness-log journal via witness-log-hookd.",
    )
    ap.add_argument("--socket", help=f"daemon socket (default {default_socket_path()})")
    ap.add_argument("--journal", help="journal path; required with --autostart")
    ap.add_argument("--autostart", action="store_true", help="start witness-log-hookd if it is not running")
    ap.add_argument("--directory", help="passed to the daemon on autostart: witness directory to submit to")
    ap.add_argument("--submit-every", type=int, default=0, help="passed to the daemon on autostart")
    ap.add_argument("--kind", choices=("intent", "result", "memory"), help="override the leaf kind")
    ap.add_argument("--strict", action="store_true", help="exit 2 when the event could not be recorded")
    sub = ap.add_subparsers(dest="cmd")
    inst = sub.add_parser("install", help="print the hook configuration for a host (does not write it)")
    inst.add_argument("host", choices=("claude-code", "cursor", "codex"))
    inst.add_argument("--journal", default="~/.witness-log/hooks.jsonl", dest="install_journal")
    inst.add_argument("--socket", dest="install_socket")
    a = ap.parse_args(argv)
    out = stdout if stdout is not None else sys.stdout
    if a.cmd == "install":
        out.write(_snippet(a.host, a.install_journal, a.install_socket))
        return 0
    if a.autostart and not a.journal:
        ap.error("--autostart needs --journal")
    socket_path = a.socket or default_socket_path()
    src = stdin if stdin is not None else sys.stdin
    try:
        raw = src.read()
        event = json.loads(raw) if raw.strip() else {}
        leaf, payload = normalize(event, a.kind)
        if a.autostart:
            ensure_daemon(socket_path, a.journal, directory=a.directory, submit_every=a.submit_every)
        reply = request(socket_path, {"op": "append", "leaf": leaf, "payload": payload})
        if not reply.get("ok"):
            raise RuntimeError(str(reply.get("error", "daemon refused the append")))
    except (OSError, ValueError, RuntimeError) as e:
        sys.stderr.write(f"witness-log-hook: not recorded: {e}\n")
        return 2 if a.strict else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
