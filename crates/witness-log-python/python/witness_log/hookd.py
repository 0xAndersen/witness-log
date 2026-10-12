"""witness-log-hookd: holds one journal open behind a Unix socket so
short-lived hook processes (``witness-log-hook``) can append to it.

::

    witness-log-hookd --journal ~/.witness-log/claude-code.jsonl
    witness-log-hookd --journal agent.jsonl --socket /run/user/1000/wl.sock \\
        --directory trusted.json --submit-every 50

A journal admits one writer, and a hook runs as a fresh process per tool
call, so without a daemon two hooks firing at once (parallel tool calls)
fight over the lock and resuming the journal per call mints a session
key each time. The daemon resumes once and serves appends over the
socket; the socket is created 0600 and the journal is sealed when
``WITNESS_LOG_IDENTITY_SEED_ENV`` is set (see ``witness_log.open``).

Protocol (one JSON object per line, one reply per request)::

    {"op": "append", "leaf": "intent"|"result"|"memory", "payload": <JSON>}
        -> {"ok": true, "index": n, "tree_size": n, "root": hex}
    {"op": "status"}  -> {"ok": true, "leaf_count", "root", "identity", "journal",
                          "witnessed", "last_verdict"}
    {"op": "export"}  -> {"ok": true, "path", "sha256", "bytes"}   (<journal>.dossier.json)
    {"op": "submit"}  -> {"ok": true, "verdict", ...}               (needs --directory)
    {"op": "sync"}    -> {"ok": true}
    {"op": "shutdown"} -> {"ok": true}; the daemon exits

Errors: ``{"ok": false, "error": "..."}``. The payload is committed as RFC
8785 canonical JSON (``witness_log.canonical_json``) and fsynced before
the reply, so a hook that got ``ok`` knows the leaf is on disk.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sys
import threading
from typing import Any, Dict, List, Optional

from . import canonical_json
from . import open as open_journal

MAX_REQUEST_BYTES = 4_000_000


def default_socket_path() -> str:
    """``$XDG_RUNTIME_DIR/witness-log-hookd.sock`` when that directory
    exists (per-user, cleaned at logout), else
    ``<tmpdir>/witness-log-hookd-<uid>.sock``."""
    run = os.environ.get("XDG_RUNTIME_DIR")
    if run and os.path.isdir(run):
        return os.path.join(run, "witness-log-hookd.sock")
    import tempfile

    uid = os.getuid() if hasattr(os, "getuid") else 0
    return os.path.join(tempfile.gettempdir(), f"witness-log-hookd-{uid}.sock")


class Hookd:
    """The daemon. ``serve_forever()`` blocks; ``shutdown()`` from another
    thread (or the ``shutdown`` op) stops it."""

    def __init__(
        self,
        journal: str,
        socket_path: Optional[str] = None,
        *,
        directory: Optional[str] = None,
        submit_every: int = 0,
    ) -> None:
        if not hasattr(socket, "AF_UNIX"):
            raise OSError("witness-log-hookd needs Unix domain sockets")
        self.journal = journal
        self.socket_path = socket_path or default_socket_path()
        self.directory = directory
        self.submit_every = submit_every
        self.log = open_journal(journal)
        self._lock = threading.RLock()
        self._since_submit = 0
        self.last_verdict: Optional[str] = None
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None

    # -- requests ---------------------------------------------------------------

    def handle(self, req: Dict[str, Any]) -> Dict[str, Any]:
        op = req.get("op")
        if op == "append":
            leaf = req.get("leaf", "intent")
            if leaf not in ("intent", "result", "memory"):
                return {"ok": False, "error": f'leaf must be "intent", "result" or "memory", got {leaf!r}'}
            payload = canonical_json(req.get("payload"))
            with self._lock:
                idx = getattr(self.log, f"append_{leaf}")(payload)
                self.log.sync()
                out = {"ok": True, "index": idx, "tree_size": self.log.tree_size(), "root": self.log.root_hex()}
                self._since_submit += 1
                due = self.directory is not None and 0 < self.submit_every <= self._since_submit
            if due:
                self._submit()
            return out
        if op == "status":
            with self._lock:
                size = self.log.tree_size()
                return {
                    "ok": True,
                    "leaf_count": size,
                    "root": self.log.root_hex(),
                    "identity": self.log.identity_pubkey_hex(),
                    "journal": self.log.path(),
                    "witnessed": self._witnessed(size),
                    "last_verdict": self.last_verdict,
                }
        if op == "export":
            with self._lock:
                self.log.sync()
                if self.directory is not None and self._since_submit > 0:
                    self._submit()  # the export is what gets handed on; witness the head first
                dossier = self.log.to_dossier_json()
                witnessed = self.log.witnessed_dossier_json()
                if witnessed and json.loads(witnessed).get("checkpoint", {}).get("tree_size") == self.log.tree_size():
                    dossier = witnessed
                data = dossier.encode()
            path = self.log.path() + ".dossier.json"
            tmp = path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, path)
            return {"ok": True, "path": path, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
        if op == "submit":
            if self.directory is None:
                return {"ok": False, "error": "the daemon was started without --directory"}
            r = self._submit()
            if r is None:
                return {"ok": False, "error": self.last_verdict or "submit failed"}
            return {"ok": True, **{k: v for k, v in r.items() if k != "dossier"}}
        if op == "sync":
            with self._lock:
                self.log.sync()
            return {"ok": True}
        if op == "shutdown":
            self._stop.set()
            return {"ok": True}
        return {"ok": False, "error": f"unknown op {op!r}"}

    def _witnessed(self, size: int) -> bool:
        try:
            with open(self.log.path() + ".witnesses.json", encoding="utf-8") as f:
                st = json.load(f)
            n = int(st.get("cosigned_size") or 0)
            return n == size and self.log.root_hex_at(n) == str(st.get("cosigned_root", "")).lower()
        except (OSError, ValueError, TypeError):
            return False

    def _submit(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            self._since_submit = 0
        try:
            out = self.log.submit(self.directory)
            self.last_verdict = out.get("verdict")
            return out
        except Exception as e:  # noqa: BLE001 -- witnessing must not take the daemon down
            self.last_verdict = f"error: {type(e).__name__}: {e}"
            sys.stderr.write(f"witness-log-hookd: submit failed: {e}\n")
            return None

    # -- socket -------------------------------------------------------------------

    def bind(self) -> None:
        if os.path.exists(self.socket_path):
            # A live daemon answers; a stale socket file does not.
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.settimeout(0.5)
                probe.connect(self.socket_path)
            except OSError:
                os.unlink(self.socket_path)
            else:
                probe.close()
                raise OSError(f"another witness-log-hookd is already listening on {self.socket_path}")
            finally:
                probe.close()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # Bind inside a private 0700 directory, set the mode, then move the
        # socket into place: no moment where it is reachable with a wider
        # mode, and no umask change (umask is process-wide; the in-process
        # daemon of a 100,000-agent run made sibling threads' CLI output 0600).
        import tempfile

        private = tempfile.mkdtemp(prefix=".hookd-", dir=os.path.dirname(os.path.abspath(self.socket_path)) or ".")
        staged = os.path.join(private, "s")
        try:
            s.bind(staged)
            os.chmod(staged, 0o600)
            os.rename(staged, self.socket_path)
        except OSError:
            s.close()
            raise
        finally:
            try:
                os.rmdir(private)
            except OSError:
                pass
        s.listen(64)
        s.settimeout(0.5)
        self._sock = s

    def serve_forever(self) -> None:
        if self._sock is None:
            self.bind()
        assert self._sock is not None
        try:
            while not self._stop.is_set():
                try:
                    conn, _ = self._sock.accept()
                except socket.timeout:  # noqa: UP041 -- an alias of TimeoutError only from 3.10
                    continue
                except OSError:
                    break
                threading.Thread(target=self._serve_conn, args=(conn,), daemon=True).start()
        finally:
            self.close()

    def _serve_conn(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(30.0)
            f = conn.makefile("rb")
            try:
                while True:
                    line = f.readline(MAX_REQUEST_BYTES + 1)
                    if not line:
                        return
                    if len(line) > MAX_REQUEST_BYTES:
                        reply = {"ok": False, "error": f"request over {MAX_REQUEST_BYTES} bytes"}
                    else:
                        try:
                            req = json.loads(line)
                            if not isinstance(req, dict):
                                raise ValueError("request must be a JSON object")
                            reply = self.handle(req)
                        except (ValueError, OSError) as e:
                            reply = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                    conn.sendall(json.dumps(reply).encode() + b"\n")
                    if self._stop.is_set():
                        return
            except OSError:
                return

    def shutdown(self) -> None:
        self._stop.set()

    def close(self) -> None:
        """Stop accepting, release the journal, then remove the socket file.
        The order matters: a client that waits for the socket to disappear
        and then opens the journal must not find the lock still held."""
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        try:
            if self.directory is not None and self._since_submit > 0:
                self._submit()
            self.log.sync()
            self.log.close()
        except OSError:
            pass
        try:
            os.unlink(self.socket_path)
        except OSError:
            pass


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="witness-log-hookd",
        description="Hold a witness-log journal open behind a Unix socket for witness-log-hook.",
    )
    ap.add_argument("--journal", required=True, help="journal path (created or resumed)")
    ap.add_argument("--socket", help=f"Unix socket path (default {default_socket_path()})")
    ap.add_argument("--directory", help="witness directory JSON file you trust; enables witnessing")
    ap.add_argument("--submit-every", type=int, default=0, help="submit to witnesses every N appends")
    a = ap.parse_args(argv)
    if a.submit_every and not a.directory:
        ap.error("--submit-every needs --directory")
    try:
        d = Hookd(a.journal, a.socket, directory=a.directory, submit_every=a.submit_every)
        d.bind()
    except (OSError, ValueError) as e:
        sys.stderr.write(f"witness-log-hookd: {e}\n")
        return 2
    sys.stderr.write(f"witness-log-hookd: {d.log.path()} on {d.socket_path} (identity {d.log.identity_pubkey_hex()})\n")
    try:
        d.serve_forever()
    except KeyboardInterrupt:
        d.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
