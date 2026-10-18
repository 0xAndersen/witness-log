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

Supervision: if the server exits, the calls it had been sent get a
JSON-RPC error, the server is restarted (at most ``--max-restarts``
times; an attempt whose command cannot be started counts too) and the
host's ``initialize`` request and ``notifications/initialized`` are
replayed to it; the new server's ``initialize`` response is not
forwarded (the host already has one). Calls that arrive meanwhile go to
the new server. Once the restarts are used up, every pending call gets an
error and the proxy exits non-zero. ``--timeout`` bounds each call. With ``--directory``
the journal is submitted to those witnesses every ``--submit-every``
completed calls and once more when the host closes stdin.

Injected tools, appended to every ``tools/list`` response and answered
by the proxy: ``audit__status`` -> ``{leaf_count, root, identity,
journal, calls, restarts, witnessed, last_verdict, directory_source}``;
``audit__export`` -> writes ``<journal>.dossier.json`` and returns
``{path, sha256, bytes, verdict, directory_source, split_view_unsafe,
tamper_alerts}`` (the verdict is ``unanchored`` unless a directory was
given, since a verifier needs a directory it trusts; ``split_view_unsafe`` is true for a ``witnessed``
verdict whose cosigners are not a strict majority of the directory; the
head witnesses last cosigned is checked as a known head, so a journal
rewritten after witnessing is ``diverged`` and one truncated below it is
a tamper alert).

The wrapped server is the code being audited, often a third party's
(``npx -y ...``), so it is started without the identity seed: the
proxy's environment minus ``WITNESS_LOG_IDENTITY_SEED_ENV`` and the
variable it names (see :func:`child_environment`). That keeps the seed
out of the child's environment, not out of its reach: a child running as
the same OS user can still read ``/proc/<proxy pid>/environ`` or an
unsealed journal's header. Run the wrapped server as a different OS user
for isolation.

The trust anchor is the operator's: the only directory the proxy uses is
``--directory``, given on its command line, and the injected tools take no
arguments, so nothing the host's model passes can change whom the
verdicts count as witnesses. ``directory_source`` is ``"pinned"`` when a
verdict was scored against that file and ``null`` when there was none
(the same field the MCP server's verdicts carry).
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
from typing import Any, Callable, Dict, List, Optional

from . import IDENTITY_SEED_ENV, canonical_json
from . import open as open_journal

PROFILE = "mcp.tools/call v1"
# How long `audit__export` waits for a witnessing round already in flight.
EXPORT_WAIT_S = 30.0
# How long a host message waits for a crashed server to be replaced.
RESTART_WAIT_S = 10.0

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


def child_environment(environ: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """The environment the wrapped server is started with: the proxy's,
    minus the identity seed. ``WITNESS_LOG_IDENTITY_SEED_ENV`` names the
    variable holding the raw seed (``AGENT_KEY=<64 hex>``); both are
    removed, since the server under audit has no business signing as the
    log it is audited by. (These are the only secret-bearing variables
    witness-log reads; ``WITNESS_LOG_HOME``, ``WITNESS_LOG_CA_FILE`` and
    ``WITNESS_LOG_TRUSTED_DIRECTORY`` are paths and are kept.)"""
    env = dict(os.environ if environ is None else environ)
    name = env.pop(IDENTITY_SEED_ENV, None)
    if name:
        env.pop(name, None)
    return env


class _Pending:
    __slots__ = ("child", "deadline", "intent_index", "tool")

    def __init__(self, tool: str, intent_index: int, deadline: float) -> None:
        self.tool = tool
        self.intent_index = intent_index
        self.deadline = deadline
        # The server process the call was written to; None until it is. A
        # crash fails exactly the calls written to the server that died.
        self.child: Optional[subprocess.Popen] = None


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
        # Signalled when a witnessing round ends, so an export can wait for
        # a periodic round that is covering an older head.
        self._submit_done = threading.Condition(self._state)
        # Clear while the server is being replaced after a crash; host
        # messages wait for it instead of hitting the dead server's pipe.
        self._ready = threading.Event()
        self._ready.set()
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
        self._exit_code = 0

    # -- I/O ------------------------------------------------------------------

    def _send_client(self, msg: Dict[str, Any]) -> None:
        data = json.dumps(msg, separators=(",", ":")).encode() + b"\n"
        with self._out_lock:
            try:
                self._out.write(data)
                self._out.flush()
            except (BrokenPipeError, ValueError, OSError):
                pass

    def _write_child_locked(self, raw: bytes) -> None:
        """Write to the current server; the caller holds ``_child_lock``."""
        child = self.child
        if child is None or child.stdin is None:
            raise BrokenPipeError("server is not running")
        child.stdin.write(raw if raw.endswith(b"\n") else raw + b"\n")
        child.stdin.flush()

    def _send_child(self, raw: bytes) -> None:
        with self._child_lock:
            self._write_child_locked(raw)

    def _send_call(self, key: str, raw: bytes) -> None:
        """Write a pending ``tools/call`` to the server and note which
        server process it went to, in one step under ``_child_lock``. The
        supervisor takes the same lock to decide which calls the dead
        server had, so a call is failed for a crash only if it was written
        to the server that crashed. A call already answered (timed out
        while waiting for a restart) is not sent at all."""
        with self._child_lock:
            with self._state:
                p = self._pending.get(key)
                if p is None:
                    return
                p.child = self.child
            self._write_child_locked(raw)

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
                self._submit_done.notify_all()

    # -- injected tools -----------------------------------------------------------

    def _witnessed_head(self) -> bool:
        try:
            st = json.loads(open(self.log.path() + ".witnesses.json", encoding="utf-8").read())  # noqa: SIM115
            size = int(st.get("cosigned_size") or 0)
            return size == self.log.tree_size() and self.log.root_hex_at(size) == str(st.get("cosigned_root", "")).lower()
        except (OSError, ValueError, TypeError):
            return False

    def _cosigned_head(self) -> Optional[str]:
        """``<size>:<root>`` that witnesses last cosigned for this journal,
        from ``<journal>.witnesses.json``, *not* checked against the
        journal: it is what a rewritten or truncated journal is checked
        against."""
        from .witnessing import load_state

        st = load_state(self.log.path() + ".witnesses.json")
        root = st["cosigned_root"].lower()
        if st["cosigned_size"] > 0 and len(root) == 64 and all(c in "0123456789abcdef" for c in root):
            return f'{st["cosigned_size"]}:{root}'
        return None

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
                "directory_source": "pinned" if self.last_verdict is not None and self.directory is not None else None,
            }

    def _export(self) -> Dict[str, Any]:
        from . import _core

        self.log.sync()
        if self.directory is not None:
            # The export is what gets handed on: witness the current head
            # first (synchronously, once, bounded by the round's timeout)
            # instead of exporting whatever the last periodic round covered.
            #
            # A periodic round may be running for an older head. Before
            # 0.5.0 the export skipped witnessing in that case and handed
            # on an unwitnessed dossier (about 1% of exports in the
            # 100,000-agent swarm); now it waits for that round, then
            # witnesses whatever it did not cover.
            deadline = time.monotonic() + EXPORT_WAIT_S
            with self._state:
                while self._submitting and time.monotonic() < deadline:
                    self._submit_done.wait(max(0.0, deadline - time.monotonic()))
                pending = not self._submitting and (self._since_submit > 0 or not self._witnessed_head())
                if pending:
                    self._submitting = True
                    self._since_submit = 0
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
        #
        # The head witnesses last cosigned is a known head, read without
        # checking it against the journal. `witnessed_dossier_json` is
        # rebuilt from the journal and drops cosignatures it no longer
        # matches, so it cannot reveal a journal rewritten after witnessing;
        # this does (security review 3, F2).
        known = self._cosigned_head()
        report = json.loads(
            _core.verify_dossier_json(
                dossier, 0.66, self.log.identity_pubkey_hex(), td, 2 if td else None, None, [known] if known else None
            )
        )
        alerts = (
            list(report.get("failures", []))
            + [f"contradiction: {c}" for c in report.get("contradictions", [])]
            + [
                f"the journal has {self.log.tree_size()} leaves, fewer than its witnessed head {h}: "
                "it was truncated after witnessing"
                for h in report.get("known_heads_unchecked", [])
            ]
        )
        return {
            "path": path,
            "sha256": _sha256(data),
            "bytes": len(data),
            "verdict": report.get("verdict"),
            "directory_source": "pinned" if td is not None else None,
            # Witnessed, but not by a strict majority of the directory (the
            # CLI's exit 11): the verdict string alone does not say so.
            "split_view_unsafe": bool(report.get("split_view_unsafe")),
            "tamper_alerts": alerts,
        }

    def _answer_local(self, msg_id: Any, tool: str, arguments: Any = None) -> None:
        try:
            if arguments:
                # Refused, not ignored: a model that passed a directory (from
                # a document, a tool result, the counterparty) must not come
                # away believing its directory scored the verdict.
                raise ValueError(
                    f"{tool} takes no arguments (got {sorted(arguments) if isinstance(arguments, dict) else arguments!r}); "
                    "the only witness directory this proxy uses is the operator's --directory"
                )
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
                self._answer_local(msg_id, tool, params.get("arguments"))
                return
            idx = self._record_intent(tool, params.get("arguments"))
            key = _key(msg_id)
            with self._state:
                self._pending[key] = _Pending(tool, idx, time.monotonic() + self.timeout)
            # A call that arrives while a crashed server is being replaced
            # waits here, unsent. In 0.5.0 it was then failed along with the
            # calls the dead server had, although it went on to run on the
            # replacement, whose real answer was dropped (security review 3,
            # F4); only calls written to the dead server are failed now.
            self._ready.wait(RESTART_WAIT_S)
            try:
                self._send_call(key, raw)
            except (BrokenPipeError, OSError) as e:
                self._fail_call(key, msg_id, f"witness-log-mcp-proxy: server unavailable ({e})")
            return
        if method == "tools/list" and msg_id is not None:
            with self._state:
                self._list_ids.add(_key(msg_id))
        self._ready.wait(RESTART_WAIT_S)
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

    def _fail_call(self, key: str, msg_id: Any, message: str, code: int = -32000, *, may_still_reply: bool = False) -> None:
        """Answer a pending call with an error and journal that, unless it
        was answered already (by its reply, a timeout or a crash): each
        call gets exactly one answer and one result leaf. With
        ``may_still_reply`` (a timeout of a call written to a live server,
        which may answer late) its late reply is dropped; otherwise a later
        call that reuses the id (a host retrying after a crash) keeps its
        own reply."""
        with self._state:
            pending = self._pending.pop(key, None)
            if pending is None:
                return
            if may_still_reply and pending.child is not None:
                if len(self._answered) > 10_000:
                    self._answered.clear()
                self._answered.add(key)
        self._record_result(pending, {"error": {"code": code, "message": message}}, True)
        self._send_client({"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}})

    # -- supervision ----------------------------------------------------------------------

    def _spawn(self) -> None:
        self.child = subprocess.Popen(  # noqa: S603 -- the operator's own command line
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            bufsize=0,
            env=child_environment(),
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
            self._ready.clear()
            code = child.wait()
            if self._closing:
                self._ready.set()
                return

            def fail(calls: Dict[str, _Pending]) -> None:
                for key, p in calls.items():
                    why = f"during {p.tool}" if p.child is child else f"and was not replaced; {p.tool} was not sent"
                    self._fail_call(key, _unkey(key), f"witness-log-mcp-proxy: server exited with code {code} {why}")

            with self._child_lock:
                # Under the lock every call is written with: the calls
                # written to the dead server are exactly the ones failed
                # below (it may have run them or not; nobody can tell). A
                # call not yet written stays pending and goes to the
                # replacement, which gets the host's initialize first.
                with self._state:
                    dead = {k: p for k, p in self._pending.items() if p.child is child}
                self.child = None
                restarted, start_error = self._restart_locked(code)
            if not restarted:
                last = f"; the last start failed: {start_error}" if start_error else ""
                sys.stderr.write(
                    f"witness-log-mcp-proxy: server exited with code {code}; restart limit ({self.max_restarts}) reached{last}\n"
                )
                self._give_up(code, fail)
            # Only now tell the host its in-flight calls failed: it usually
            # retries at once, and before 0.5.0 that retry could reach the
            # dead server's pipe ("server unavailable") because the error
            # went out before the replacement was running.
            self._ready.set()
            fail(dead)

    def _restart_locked(self, code: Any) -> "tuple[bool, Optional[BaseException]]":
        """Start a replacement server and replay the host's initialize to
        it; the caller holds ``_child_lock``. Every attempt counts against
        ``--max-restarts``, including one whose command cannot be started
        at all. In 0.5.0 that case raised out of the supervisor thread
        after ``_ready`` was cleared: the crashed calls were answered only
        by the per-call timeout, every later message waited 10 s and failed,
        and the proxy never exited (security review 3, F8). Returns whether
        a server is running, and the last start error."""
        error: Optional[BaseException] = None
        while self.restarts < self.max_restarts:
            self.restarts += 1
            sys.stderr.write(
                f"witness-log-mcp-proxy: server exited with code {code}; restarting ({self.restarts}/{self.max_restarts})\n"
            )
            try:
                self._spawn()
            except Exception as e:  # noqa: BLE001 -- the supervisor thread must survive this
                self.child = None
                error = e
                sys.stderr.write(f"witness-log-mcp-proxy: could not start the server: {type(e).__name__}: {e}\n")
                time.sleep(min(0.2 * self.restarts, 1.0))
                continue
            self._replay_init_locked()
            return True, None
        return False, error

    def _replay_init_locked(self) -> None:
        """Replay the host's ``initialize`` and ``notifications/initialized``
        to a new server; the caller holds ``_child_lock``, so no call can
        reach the server before them."""
        if self._init_request is None:
            return
        try:
            init = json.loads(self._init_request)
            with self._state:
                self._local_ids.add(_key(init.get("id")))
            self._write_child_locked(self._init_request)
            if self._initialized_note is not None:
                self._write_child_locked(self._initialized_note)
        except (OSError, ValueError) as e:
            sys.stderr.write(f"witness-log-mcp-proxy: could not re-initialize the server: {e}\n")

    def _give_up(self, code: Any, fail: Callable[[Dict[str, _Pending]], None]) -> None:
        """No server will run again: fail every pending call and exit."""
        # Decide the exit status and make the journal durable before the
        # host hears about the failed calls: once it does it may close
        # stdin, and the main thread's exit must not report success for a
        # proxy that gave up on its server.
        self._closing = True
        self._exit_code = code if isinstance(code, int) and code > 0 else 1
        try:
            self.log.sync()
        except OSError:
            pass
        self._ready.set()
        with self._state:
            every = dict(self._pending)
        fail(every)
        try:
            self.log.sync()
        except OSError:
            pass
        # Exit now. 0.5.0 closed stdin first, which waits for the main
        # thread's blocked read, i.e. until the host wrote or closed stdin:
        # a proxy that had given up kept running until then.
        os._exit(self._exit_code)

    def _watch_timeouts(self) -> None:
        while not self._closing:
            time.sleep(0.05)
            now = time.monotonic()
            with self._state:
                late = [k for k, p in self._pending.items() if p.deadline <= now]
            for key in late:
                self._fail_call(key, _unkey(key), f"witness-log-mcp-proxy: timed out after {self.timeout:g}s", may_still_reply=True)

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
        return self._exit_code

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
