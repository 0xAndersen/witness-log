#!/usr/bin/env python3
"""Run the code blocks the docs mark as runnable, so a quickstart that
stops working fails CI instead of a newcomer.

A block opts in with an HTML comment on the line right before its fence
(invisible on GitHub and in the wiki):

    <!-- doctest -->
    ```sh
    witness-log log init agent.jsonl
    ```

Options, space-separated inside the comment after "doctest:":

    exit=N        the status the block must end with (default 0)
    group=NAME    blocks of one file with the same group share a working
                  directory, in document order (default: one group per file)
    before="..."  a shell command run first and not shown to the reader
                  (e.g. start a local testnet the prose already mentioned)
    after="..."   a shell command run afterwards, even if the block failed
    timeout=S     seconds before the block is killed (default 120)

`sh`/`bash`/`shell` blocks run with `bash -eo pipefail`; the `python` blocks
of a group run in one interpreter (this one), in order, sharing variables
as if pasted into one session. Each group runs in a fresh temporary directory with
the witness-log CLI first on PATH; every process a group starts (a
witness put in the background with `&`, say) is killed when the group
ends. Exit 0 when every marked block behaved, 1 otherwise.

    python3 docs/doctest.py                      # every file listed below
    python3 docs/doctest.py docs/wiki/Quickstart-CLI.md
    WITNESS_LOG_CLI=target/release/witness-log python3 docs/doctest.py
"""

from __future__ import annotations

import os
import queue
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FILES = [
    "README.md",
    "docs/wiki/Quickstart-CLI.md",
    "docs/wiki/Getting-Witnessed.md",
    "docs/wiki/Quickstart-Python.md",
]
MARK = re.compile(r"^<!--\s*doctest(?::(?P<opts>.*?))?\s*-->\s*$")
FENCE = re.compile(r"^```(?P<lang>[A-Za-z0-9_-]*)\s*$")
LANGS = {"sh": "sh", "bash": "sh", "shell": "sh", "console": "sh", "python": "python", "py": "python"}


def blocks(path: Path):
    """(line, lang, code, options) for every marked block, in order."""
    lines = path.read_text(encoding="utf-8").splitlines()
    i = 0
    while i < len(lines):
        m = MARK.match(lines[i].strip())
        if not m:
            i += 1
            continue
        opts = dict(kv.split("=", 1) for kv in shlex.split(m.group("opts") or "") if "=" in kv)
        f = FENCE.match(lines[i + 1].strip()) if i + 1 < len(lines) else None
        if not f or f.group("lang") not in LANGS:
            raise SystemExit(f"{path}:{i + 1}: a doctest marker must sit right above a ```sh or ```python fence")
        j = i + 2
        while j < len(lines) and lines[j].strip() != "```":
            j += 1
        yield i + 2, LANGS[f.group("lang")], "\n".join(lines[i + 2 : j]) + "\n", opts
        i = j + 1


def cli_dir() -> str:
    exe = "witness-log.exe" if os.name == "nt" else "witness-log"
    env = os.environ.get("WITNESS_LOG_CLI")
    candidates = [Path(env)] if env else []
    candidates += [REPO / "target" / "release" / exe, REPO / "target" / "debug" / exe]
    for c in candidates:
        if c.exists():
            return str(c.resolve().parent)
    found = shutil.which("witness-log")
    if found:
        return str(Path(found).parent)
    raise SystemExit("no witness-log CLI: cargo build --release -p witness-log-cli (or set WITNESS_LOG_CLI)")


def run(argv: list, cwd: str, env: dict, timeout: float, sessions: list) -> tuple:
    """Run in a session of its own and remember it, so whatever the block
    leaves running in the background is killed with the group."""
    # Output goes to a file, not a pipe: a witness the block left running
    # in the background keeps a pipe open, and reading it to EOF would wait
    # for that witness instead of for the block.
    with tempfile.TemporaryFile(mode="w+") as log:
        p = subprocess.Popen(argv, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT,
                             text=True, start_new_session=True)
        sessions.append(p.pid)
        try:
            rc = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
            rc = None
        log.seek(0)
        out = log.read()
    return rc, (out if rc is not None else f"timed out after {timeout:.0f} s\n{out[-1500:]}")


# Python blocks of one group run in one interpreter, in order, sharing their
# variables, the way a reader pastes them into one session.
DRIVER = r"""
import sys, traceback
g = {"__name__": "__main__"}
while True:
    header = sys.stdin.readline()
    if not header:
        break
    code = sys.stdin.read(int(header))
    status = 0
    try:
        exec(compile(code, "<doc block>", "exec"), g)
    except SystemExit as e:
        status = e.code if isinstance(e.code, int) else 1
    except BaseException:
        traceback.print_exc()
        status = 1
    sys.stdout.flush(); sys.stderr.flush()
    print("\n@@DOCTEST-DONE %d" % status, flush=True)
"""


class PySession:
    def __init__(self, cwd: str, env: dict, sessions: list):
        self.p = subprocess.Popen([sys.executable, "-u", "-c", DRIVER], cwd=cwd, env=env, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                  start_new_session=True)
        sessions.append(self.p.pid)
        self.lines: "queue.Queue[str | None]" = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for line in self.p.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def run(self, code: str, timeout: float) -> tuple:
        self.p.stdin.write(f"{len(code)}\n{code}")
        self.p.stdin.flush()
        out, deadline = [], time.monotonic() + timeout
        while True:
            try:
                line = self.lines.get(timeout=max(0.01, deadline - time.monotonic()))
            except queue.Empty:
                return None, f"timed out after {timeout:.0f} s\n" + "".join(out)[-1500:]
            if line is None:
                return None, "the interpreter exited\n" + "".join(out)[-1500:]
            if line.startswith("@@DOCTEST-DONE "):
                return int(line.split()[1]), "".join(out)
            out.append(line)


def run_group(path: Path, name: str, items, env: dict) -> list[str]:
    failures = []
    work = tempfile.mkdtemp(prefix="wl-doctest-")
    sessions: list[int] = []
    py = None
    try:
        for line, lang, code, opts in items:
            where = f"{path.relative_to(REPO)}:{line}"
            want = int(opts.get("exit", "0"))
            timeout = float(opts.get("timeout", "120"))
            if lang == "sh":
                script = os.path.join(work, ".block.sh")
                with open(script, "w") as f:
                    f.write("set -eo pipefail\n" + code)
                argv = ["bash", script]
            else:
                argv = None
            setup_ok = True
            if "before" in opts:
                rc, out = run(["bash", "-c", opts["before"]], work, env, timeout, sessions)
                if rc != 0:
                    failures.append(f"{where}: hidden setup {opts['before']!r} exited {rc}\n{out[-1500:]}")
                    setup_ok = False
            if setup_ok:
                t0 = time.monotonic()
                if argv is None:
                    py = py or PySession(work, env, sessions)
                    rc, out = py.run(code, timeout)
                else:
                    rc, out = run(argv, work, env, timeout, sessions)
                status = "ok  " if rc == want else "FAIL"
                print(f"{status} {where} [{name}] ({lang}, exit {rc}, want {want}, {time.monotonic() - t0:.1f} s)")
                if rc != want:
                    failures.append(f"{where}: exited {rc}, the docs promise {want}\n--- output (tail) ---\n{out[-2500:]}")
            if "after" in opts:
                run(["bash", "-c", opts["after"]], work, env, timeout, sessions)
    finally:
        if py is not None:
            py.p.stdin.close()
            try:
                py.p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        for pgid in sessions:
            try:
                os.killpg(pgid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
        time.sleep(0.2)
        shutil.rmtree(work, ignore_errors=True)
    return failures


def main() -> int:
    files = [Path(a).resolve() for a in sys.argv[1:]] or [REPO / f for f in FILES]
    env = dict(os.environ)
    env["PATH"] = cli_dir() + os.pathsep + env.get("PATH", "")
    env.setdefault("PYTHONUNBUFFERED", "1")
    failures: list[str] = []
    total = 0
    for path in files:
        groups: dict[str, list] = {}
        for item in blocks(path):
            groups.setdefault(item[3].get("group", "default"), []).append(item)
            total += 1
        for name, items in groups.items():
            failures += run_group(path, name, items, env)
    print(f"\n{total - len(failures)} of {total} marked blocks behaved as documented.")
    for f in failures:
        print("\n" + f)
    return 1 if failures or total == 0 else 0


if __name__ == "__main__":
    sys.exit(main())
