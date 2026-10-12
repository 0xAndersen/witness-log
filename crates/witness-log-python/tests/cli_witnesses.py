"""Start real witnesses from the built CLI for tests.

The CLI is found at ``$WITNESS_LOG_CLI``, then ``target/release`` and
``target/debug`` of this repository, then ``witness-log`` on PATH. Tests
that need it skip when none exists (``cargo build --release -p
witness-log-cli`` provides it).
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import socket
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

REPO = pathlib.Path(__file__).resolve().parents[3]


def find_cli() -> Optional[str]:
    env = os.environ.get("WITNESS_LOG_CLI")
    if env and os.path.exists(env):
        return env
    exe = "witness-log.exe" if os.name == "nt" else "witness-log"
    for p in (REPO / "target" / "release" / exe, REPO / "target" / "debug" / exe):
        if p.exists():
            return str(p)
    return shutil.which("witness-log")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class CliWitness:
    """``witness-log witness init`` + ``serve --open-enrollment`` in a temp dir."""

    def __init__(self, cli: str, root: pathlib.Path, name: str, org: str):
        self.port = free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.dir = root / name
        out = subprocess.run(
            [cli, "witness", "init", str(self.dir), "--name", f"{name}.test/w", "--org", org, "--url", self.url],
            capture_output=True,
            text=True,
            check=True,
        )
        self.entry: Dict[str, Any] = json.loads(out.stdout)
        self.proc = subprocess.Popen(
            [cli, "witness", "serve", str(self.dir), "--listen", f"127.0.0.1:{self.port}", "--open-enrollment"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                urllib.request.urlopen(self.url + "/health", timeout=1).read()
                return
            except OSError:
                time.sleep(0.05)
        self.stop()
        raise RuntimeError(f"witness {name} did not start")

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


class FlakyProxy:
    """Forwards to ``target`` but answers the first ``n429`` requests with
    ``429 Retry-After: 1``. Counts requests."""

    def __init__(self, target: str, n429: int = 1):
        self.target = target
        self.n429 = n429
        self.hits = 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                pass

            def do_POST(self) -> None:  # noqa: N802
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n)
                outer.hits += 1
                if outer.hits <= outer.n429:
                    self.send_response(429)
                    self.send_header("Retry-After", "1")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                req = urllib.request.Request(outer.target + self.path, data=body, method="POST")
                try:
                    with urllib.request.urlopen(req, timeout=10) as r:
                        st, out = r.status, r.read()
                except urllib.error.HTTPError as e:  # type: ignore[attr-defined]
                    st, out = e.code, e.read()
                self.send_response(st)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        import urllib.error  # noqa: F401 -- used in the handler

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.httpd.shutdown()


def directory(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"witnesses": entries}
