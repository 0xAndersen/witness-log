"""witness-log-mcp-proxy: an audit trail for any stdio MCP server, no code.

::

    witness-log-mcp-proxy --name git --journal ./git.wlog -- mcp-server-git
    witness-log-mcp-proxy --name fs --journal fs.wlog \\
        --directory trusted.json --submit-every 20 -- npx -y @modelcontextprotocol/server-filesystem .

Put the proxy where the host's configuration had the server: the host
talks JSON-RPC to the proxy over stdio, the proxy talks to the real
server over stdio, and every message passes through unchanged except
the ones below. The host sees the server's tools plus two of the proxy's
own.

What is recorded (profile ``"mcp.tools/call v1"``). For each
``tools/call`` request the proxy appends an *intent* leaf before
forwarding it and a *result* leaf when the response arrives::

    intent  = canonical_json({"profile": "mcp.tools/call v1", "server": <--name>,
                              "tool": <params.name>, "args_sha256": <hex>})
    result  = canonical_json({"profile": "mcp.tools/call v1", "server": <--name>,
                              "tool": <params.name>, "intent_index": <int>,
                              "result_sha256": <hex>, "is_error": <bool>})

where ``canonical_json`` is RFC 8785 (``witness_log.canonical_json``) and

* ``args_sha256`` is SHA-256 over ``canonical_json(params.arguments)``, with
  ``{}`` when the request has no ``arguments``;
* ``result_sha256`` is SHA-256 over ``canonical_json(response.result)`` (the
  whole CallToolResult object) for a success response, or over
  ``canonical_json({"error": response.error})`` for a JSON-RPC error
  response, or over ``canonical_json({"error": {"code": -32000, "message":
  "witness-log-mcp-proxy: timed out after <N>s"}})`` when the proxy gave
  up waiting; ``is_error`` is true for the last two and when
  ``result.isError`` is true.

The leaves carry hashes, not arguments or results, so the journal can be
handed to an auditor without handing over the data; the host keeps its
own transcript and the hashes bind it. Payloads are salted per leaf
(SPEC §8) and ``forget(i)`` erases one.

Supervision: if the server exits, in-flight calls get a JSON-RPC error,
the server is restarted (at most ``--max-restarts`` times) and the host's
``initialize`` request and ``notifications/initialized`` are replayed to
it; the new server's ``initialize`` response is not forwarded (the host
already has one). ``--timeout`` bounds each call. With ``--directory``
the journal is submitted to those witnesses every ``--submit-every``
completed calls and once more when the host closes stdin.

Injected tools, appended to every ``tools/list`` response and answered
by the proxy: ``audit__status`` -> ``{leaf_count, root, identity,
journal, calls, restarts, witnessed, last_verdict}``; ``audit__export``
-> writes ``<journal>.dossier.json`` and returns ``{path, sha256,
bytes, verdict}`` (the verdict is ``unanchored`` unless a directory was
given, since a verifier needs a directory it trusts).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional

from . import canonical_json
from . import open as open_journal

PROFILE = "mcp.tools/call v1"

INJECTED_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "audit__status",
        "description": (
            "Where the witness-log audit trail of this MCP server stands: leaf count, "
            "current root, identity, calls recorded, restarts, whether the head is witnessed."
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "audit__export",
        "description": (
            "Write the audit trail's dossier (every leaf, the signed checkpoint, any witness "
            "receipts) to <journal>.dossier.json and return its path, sha256 and size. Anyone "
            "can verify the file with `witness-log verify`."
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
]


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class _Pending:
    __slots__ = ("deadline", "intent_index", "tool")

    def __init__(self, tool: str, intent_index: int, deadline: float) -> None:
        self.tool = tool
        self.intent_index = intent_index
        self.deadline = deadline


class Proxy:
    """One proxied server. ``run()`` blocks until the host closes stdin or
    the server cannot be restarted."""

    def __init__(
        self,
        command: List[str],
        journal: str,
        name: str,
        *,
        timeout: float = 60.0,
        max_restarts: int = 3,
        directory: Optional[str] = None,
        submit_every: int = 0,
        stdin: Any = None,
        stdout: Any = None,
    ) -> None:
        if not command:
            raise ValueError("no server command given (put it after `--`)")
        self.command = command
        self.name = name
        self.timeout = timeout
        self.max_restarts = max_restarts
        self.directory = directory
        self.submit_every = submit_every
        self.log = open_journal(journal, store_payloads=False)
        self._in = stdin if stdin is not None else sys.stdin.buffer
        self._out = stdout if stdout is not None else sys.stdout.buffer
        self._out_lock = threading.Lock()
        self._child_lock = threading.Lock()
        self._state = threading.Lock()
        self._pending: Dict[str, _Pending] = {}
        self._list_ids: set = set()
        self._local_ids: set = set()  # initialize replays whose response is swallowed
        self._answered: set = set()  # calls the proxy already answered with an error; late replies are dropped
        self._init_request: Optional[bytes] = None
        self._initialized_note: Optional[bytes] = None
        self.child: Optional[subprocess.Popen] = None
        self.restarts = 0
        self.calls = 0
        self._since_submit = 0
        self._submitting = False
        self.last_verdict: Optional[str] = None
        self._closing = False

    # -- I/O ------------------------------------------------------------------

    def _send_client(self, msg: Dict[str, Any]) -> None:
        data = json.dumps(msg, separators=(",", ":")).encode() + b"\n"
        with self._out_lock:
            try:
                self._out.write(data)
                self._out.flush()
            except (BrokenPipeError, ValueError, OSError):
                pass

    def _send_child(self, raw: bytes) -> None:
        with self._child_lock:
            child = self.child
            if child is None or child.stdin is None:
                raise BrokenPipeError("server is not running")
            child.stdin.write(raw if raw.endswith(b"\n") else raw + b"\n")
            child.stdin.flush()

    # -- leaves -----------------------------------------------------------------

    def _record_intent(self, tool: str, arguments: Any) -> int:
        args = arguments if arguments is not None else {}
        return self.log.append_intent(
            canonical_json(
                {"profile": PROFILE, "server": self.name, "tool": tool, "args_sha256": _sha256(canonical_json(args))}
            )
        )

    def _record_result(self, p: _Pending, hashed: Any, is_error: bool) -> int:
        idx = self.log.append_result(
            canonical_json(
                {
                    "profile": PROFILE,
                    "server": self.name,
                    "tool": p.tool,
                    "intent_index": p.intent_index,
                    "result_sha256": _sha256(canonical_json(hashed)),
                    "is_error": bool(is_error),
                }
            )
        )
        with self._state:
            self.calls += 1
            self._since_submit += 1
            due = self.directory is not None and self.submit_every > 0 and self._since_submit >= self.submit_every
        if due:
            self._submit_async()
        return idx

    # -- witnessing ---------------------------------------------------------------

    def _submit_async(self) -> None:
        with self._state:
            if self._submitting:
                return
            self._submitting = True
            self._since_submit = 0
        threading.Thread(target=self._submit, name="witness-log-mcp-proxy-submit", daemon=True).start()

    def _submit(self) -> None:
        try:
            out = self.log.submit(self.directory)
            with self._state:
                self.last_verdict = out.get("verdict")
        except Exception as e:  # noqa: BLE001 -- witnessing must never take the proxy down
            with self._state:
                self.last_verdict = f"error: {type(e).__name__}: {e}"
            sys.stderr.write(f"witness-log-mcp-proxy: submit failed: {e}\n")
        finally:
            with self._state:
                self._submitting = False

    # -- injected tools -----------------------------------------------------------

    def _witnessed_head(self) -> bool:
        try:
            st = json.loads(open(self.log.path() + ".witnesses.json", encoding="utf-8").read())  # noqa: SIM115
            size = int(st.get("cosigned_size") or 0)
            return size == self.log.tree_size() and self.log.root_hex_at(size) == str(st.get("cosigned_root", "")).lower()
        except (OSError, ValueError, TypeError):
            return False

    def _status(self) -> Dict[str, Any]:
        witnessed = self._witnessed_head()
        with self._state:
            return {
                "server": self.name,
                "journal": self.log.path(),
                "leaf_count": self.log.tree_size(),
                "root": self.log.root_hex(),
                "identity": self.log.identity_pubkey_hex(),
                "calls": self.calls,
                "restarts": self.restarts,
                "witnessed": witnessed,
                "last_verdict": self.last_verdict,
            }

    def _export(self) -> Dict[str, Any]:
        from . import _core

        self.log.sync()
        if self.directory is not None:
            # The export is what gets handed on: witness the current head
            # first (synchronously, once, bounded by the round's timeout)
            # instead of exporting whatever the last periodic round covered.
            with self._state:
                pending = self._since_submit > 0 or not self._witnessed_head()
                if pending and not self._submitting:
                    self._submitting = True
                    self._since_submit = 0
                else:
                    pending = False
            if pending:
                self._submit()
        dossier = self.log.to_dossier_json()
        if self.directory is not None:
            witnessed = self.log.witnessed_dossier_json()
            if witnessed and json.loads(witnessed).get("checkpoint", {}).get("tree_size") == self.log.tree_size():
                dossier = witnessed
        data = dossier.encode()
        path = self.log.path() + ".dossier.json"
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:  # noqa: SIM115
            f.write(data)
        os.replace(tmp, path)
        td = None
        if self.directory is not None:
            try:
                with open(self.directory, encoding="utf-8") as f:
                    td = f.read()
            except OSError:
                td = None
        # Gate on a cosignature count, the same gate `submit` used (its
        # default of 2 from two operators), not on a fraction of the whole
        # directory: against a 20-witness directory the fraction gate turned
        # every WITNESSED export into CONSISTENT-UNWITNESSED.
        verdict = json.loads(
            _core.verify_dossier_json(dossier, 0.66, self.log.identity_pubkey_hex(), td, 2 if td else None)
        ).get("verdict")
        return {"path": path, "sha256": _sha256(data), "bytes": len(data), "verdict": verdict}

    def _answer_local(self, msg_id: Any, tool: str) -> None:
        try:
            body = self._status() if tool == "audit__status" else self._export()
            result = {"content": [{"type": "text", "text": json.dumps(body)}], "structuredContent": body, "isError": False}
        except Exception as e:  # noqa: BLE001
            result = {"content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}], "isError": True}
        self._send_client({"jsonrpc": "2.0", "id": msg_id, "result": result})

    # -- message handling --------------------------------------------------------------

    def _handle_client(self, raw: bytes) -> None:
        try:
            msg = json.loads(raw)
        except ValueError:
            self._send_child(raw)  # not ours to judge; the server answers with a parse error
            return
        if not isinstance(msg, dict):
            self._send_child(raw)
            return
        method = msg.get("method")
        msg_id = msg.get("id")
        if method == "initialize":
            self._init_request = raw
        elif method == "notifications/initialized":
            self._initialized_note = raw
        if method == "tools/call" and msg_id is not None:
            params = msg.get("params") or {}
            tool = str(params.get("name", ""))
            if tool in ("audit__status", "audit__export"):
                self._answer_local(msg_id, tool)
                return
            idx = self._record_intent(tool, params.get("arguments"))
            with self._state:
                self._pending[_key(msg_id)] = _Pending(tool, idx, time.monotonic() + self.timeout)
            try:
                self._send_child(raw)
            except (BrokenPipeError, OSError) as e:
                self._fail_call(_key(msg_id), msg_id, f"witness-log-mcp-proxy: server unavailable ({e})")
            return
        if method == "tools/list" and msg_id is not None:
            with self._state:
                self._list_ids.add(_key(msg_id))
        try:
            self._send_child(raw)
        except (BrokenPipeError, OSError) as e:
            if msg_id is not None:
                self._send_client(
                    {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32000, "message": f"witness-log-mcp-proxy: server unavailable ({e})"}}
                )

    def _handle_child(self, raw: bytes) -> None:
        try:
            msg = json.loads(raw)
        except ValueError:
            with self._out_lock:
                self._out.write(raw if raw.endswith(b"\n") else raw + b"\n")
                self._out.flush()
            return
        if not isinstance(msg, dict) or "id" not in msg or "method" in msg:
            # Notifications, server-initiated requests, batches: pass through.
            self._forward_raw(raw)
            return
        key = _key(msg["id"])
        with self._state:
            if key in self._local_ids:
                self._local_ids.discard(key)
                return  # a replayed initialize; the host already has its answer
            if key in self._answered:
                self._answered.discard(key)
                return  # the host already got a timeout/error for this id
            pending = self._pending.pop(key, None)
            is_list = key in self._list_ids
            self._list_ids.discard(key)
        if pending is not None:
            if "error" in msg:
                self._record_result(pending, {"error": msg["error"]}, True)
            else:
                result = msg.get("result")
                self._record_result(pending, result, bool(isinstance(result, dict) and result.get("isError")))
        elif is_list and isinstance(msg.get("result"), dict) and isinstance(msg["result"].get("tools"), list):
            msg["result"]["tools"] = list(msg["result"]["tools"]) + INJECTED_TOOLS
        self._send_client(msg)

    def _forward_raw(self, raw: bytes) -> None:
        with self._out_lock:
            self._out.write(raw if raw.endswith(b"\n") else raw + b"\n")
            self._out.flush()

    def _fail_call(self, key: str, msg_id: Any, message: str, code: int = -32000) -> None:
        with self._state:
            pending = self._pending.pop(key, None)
            if len(self._answered) > 10_000:
                self._answered.clear()
            self._answered.add(key)
        if pending is not None:
            self._record_result(pending, {"error": {"code": code, "message": message}}, True)
        self._send_client({"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}})

    # -- supervision ----------------------------------------------------------------------

    def _spawn(self) -> None:
        self.child = subprocess.Popen(  # noqa: S603 -- the operator's own command line
            self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr, bufsize=0
        )

    def _read_child(self) -> None:
        """Forward the server's stdout until it closes; then supervise."""
        while not self._closing:
            child = self.child
            assert child is not None and child.stdout is not None
            for raw in iter(child.stdout.readline, b""):
                if raw.strip():
                    try:
                        self._handle_child(raw)
                    except Exception as e:  # noqa: BLE001 -- one bad message must not stop the pipe
                        sys.stderr.write(f"witness-log-mcp-proxy: dropped a server message: {e}\n")
            code = child.wait()
            if self._closing:
                return
            with self._state:
                dead = {k: v for k, v in self._pending.items()}
            for key, p in dead.items():
                msg_id = _unkey(key)
                self._fail_call(key, msg_id, f"witness-log-mcp-proxy: server exited with code {code} during {p.tool}")
            if self.restarts >= self.max_restarts:
                sys.stderr.write(
                    f"witness-log-mcp-proxy: server exited with code {code}; restart limit ({self.max_restarts}) reached\n"
                )
                self._closing = True
                self.log.sync()
                try:
                    self._in.close()
                except (OSError, ValueError):
                    pass
                os._exit(code if isinstance(code, int) and code > 0 else 1)
            self.restarts += 1
            sys.stderr.write(f"witness-log-mcp-proxy: server exited with code {code}; restarting ({self.restarts}/{self.max_restarts})\n")
            with self._child_lock:
                self._spawn()
            if self._init_request is not None:
                try:
                    init = json.loads(self._init_request)
                    with self._state:
                        self._local_ids.add(_key(init.get("id")))
                    self._send_child(self._init_request)
                    if self._initialized_note is not None:
                        self._send_child(self._initialized_note)
                except (OSError, ValueError) as e:
                    sys.stderr.write(f"witness-log-mcp-proxy: could not re-initialize the server: {e}\n")

    def _watch_timeouts(self) -> None:
        while not self._closing:
            time.sleep(0.05)
            now = time.monotonic()
            with self._state:
                late = [k for k, p in self._pending.items() if p.deadline <= now]
            for key in late:
                self._fail_call(key, _unkey(key), f"witness-log-mcp-proxy: timed out after {self.timeout:g}s")

    def run(self) -> int:
        with self._child_lock:
            self._spawn()
        threading.Thread(target=self._read_child, name="witness-log-mcp-proxy-child", daemon=True).start()
        threading.Thread(target=self._watch_timeouts, name="witness-log-mcp-proxy-timeouts", daemon=True).start()
        try:
            for raw in iter(self._in.readline, b""):
                if not raw.strip():
                    continue
                try:
                    self._handle_client(raw)
                except Exception as e:  # noqa: BLE001
                    sys.stderr.write(f"witness-log-mcp-proxy: dropped a host message: {e}\n")
        finally:
            self.close()
        return 0

    def close(self) -> None:
        if self._closing:
            return
        self._closing = True
        if self.directory is not None and self._since_submit > 0:
            self._submit()
        try:
            self.log.sync()
        except OSError:
            pass
        child = self.child
        if child is not None:
            try:
                if child.stdin is not None:
                    child.stdin.close()
                child.wait(timeout=2.0)
            except (OSError, subprocess.TimeoutExpired):
                child.kill()
        try:
            self.log.close()
        except OSError:
            pass


def _key(msg_id: Any) -> str:
    return json.dumps(msg_id, separators=(",", ":"), sort_keys=True)


def _unkey(key: str) -> Any:
    return json.loads(key)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="witness-log-mcp-proxy",
        description="Wrap a stdio MCP server; record every tools/call as salted hashes in a witness-log journal.",
        epilog="Put the server command after `--`: witness-log-mcp-proxy --name git --journal git.wlog -- mcp-server-git",
    )
    ap.add_argument("--name", required=True, help="server name recorded in every leaf")
    ap.add_argument("--journal", required=True, help="journal path (created or resumed)")
    ap.add_argument("--timeout", type=float, default=60.0, help="seconds to wait for a tool call (default 60)")
    ap.add_argument("--max-restarts", type=int, default=3, help="restart the server at most this often (default 3)")
    ap.add_argument("--directory", help="witness directory JSON file you trust; enables witnessing")
    ap.add_argument("--submit-every", type=int, default=0, help="submit to witnesses every N completed calls")
    ap.add_argument("command", nargs=argparse.REMAINDER, help="the server command (after --)")
    a = ap.parse_args(argv)
    command = a.command[1:] if a.command and a.command[0] == "--" else a.command
    if a.submit_every and not a.directory:
        ap.error("--submit-every needs --directory")
    try:
        proxy = Proxy(
            command,
            a.journal,
            a.name,
            timeout=a.timeout,
            max_restarts=a.max_restarts,
            directory=a.directory,
            submit_every=a.submit_every,
        )
    except (OSError, ValueError) as e:
        sys.stderr.write(f"witness-log-mcp-proxy: {e}\n")
        return 2
    return proxy.run()


if __name__ == "__main__":
    sys.exit(main())
