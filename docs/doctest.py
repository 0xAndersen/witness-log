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
    file=NAME     do not run the block: write it to NAME in the group's
                  directory, for a script the prose tells the reader to
                  save (a later block runs it). Any fence language; NAME is
                  relative and stays inside that directory.

`sh`/`bash`/`shell` blocks run with `bash -eo pipefail`. Shell variables a
block (or a before=/after= command) sets are set in the later shell blocks
of its group, as in one terminal, also when the block sets its own `trap
... EXIT`; changes to inherited variables such as PATH are not carried, nor
is `cd`. The `python` blocks of a group run in one interpreter (this one),
in order, sharing variables as if pasted into one session.

Each group runs in a fresh temporary directory with the witness-log CLI
first on PATH and, when this interpreter is a virtual environment's, that
environment's commands next, so `python`, `pip` and the package's own
commands in a shell block are the ones the python blocks use (`pip install
witness-log` then finds the build under test installed and changes
nothing). A loopback port a page names (`127.0.0.1:7381`, `localhost:7381`)
is replaced by a free one, the same port by the same free port throughout
the group, before= and after= included: a witness the reader may already
run on 7381 is never enrolled into, or sent a tutorial's equivocation.
Every process a group starts (a witness put in the background with `&`,
say) is stopped when the group ends: SIGTERM, then SIGKILL after a few
seconds. Exit 0 when every marked block behaved, 1 otherwise.

    python3 docs/doctest.py                      # every file listed below
    python3 docs/doctest.py docs/wiki/Quickstart-CLI.md
    python3 docs/doctest.py -v docs/wiki/Quickstart-CLI.md   # and print each block's output
    WITNESS_LOG_CLI=target/release/witness-log python3 docs/doctest.py
"""

from __future__ import annotations

import os
import queue
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path, PurePosixPath, PureWindowsPath

REPO = Path(__file__).resolve().parents[1]
FILES = [
    "README.md",
    "docs/wiki/Quickstart-CLI.md",
    "docs/wiki/Getting-Witnessed.md",
    "docs/wiki/Quickstart-Python.md",
    "docs/wiki/Quickstart-TypeScript.md",
    "docs/wiki/Tutorial-Audit-a-Payments-Agent.md",
    "docs/wiki/Tutorial-Multi-Agent-Handoff.md",
    "docs/wiki/Redaction-Explained.md",
    "docs/wiki/Keys-and-Identity.md",
    "docs/wiki/Troubleshooting.md",
    "docs/wiki/Hooks.md",
]
VERBOSE = False  # -v: print every block's output, to refresh a page's sample output
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
        if not f or (f.group("lang") not in LANGS and "file" not in opts):
            raise SystemExit(f"{path}:{i + 1}: a doctest marker must sit right above a ```sh or ```python fence"
                             " (or any fence, with file=)")
        name = opts.get("file")
        if name is not None and (not name or PurePosixPath(name).is_absolute() or PureWindowsPath(name).is_absolute()
                                 or ".." in PurePosixPath(name.replace("\\", "/")).parts):
            raise SystemExit(f"{path}:{i + 1}: file={name!r} must be a relative path inside the group's directory")
        j = i + 2
        while j < len(lines) and lines[j].strip() != "```":
            j += 1
        lang = "file" if "file" in opts else LANGS[f.group("lang")]
        yield i + 2, lang, "\n".join(lines[i + 2 : j]) + "\n", opts
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


# Put before every shell block: the variables earlier blocks of the group
# set come back, and on any exit (a failing command included) the ones this
# block set, everything not inherited from the environment, are written
# for the next. A block's own `trap ... EXIT` runs after the save instead
# of replacing it, and sees the exit status it would have seen. Names with
# __dt_ are this prelude's own.
PRELUDE = r"""set -eo pipefail
__dt_vars=%(vars)s
__dt_base=" $(compgen -v | tr '\n' ' ') "
if [ -f "$__dt_vars" ]; then . "$__dt_vars"; fi
__dt_save() {
  local __dt_rc=${1:-$?} __dt_n
  for __dt_n in $(compgen -v); do
    case "$__dt_base" in *" $__dt_n "*) continue ;; esac
    case "$__dt_n" in __dt_*|BASH_*|FUNCNAME|PIPESTATUS|GROUPS|DIRSTACK) continue ;; esac
    declare -p "$__dt_n"
  done > "$__dt_vars.new" 2>/dev/null || true
  mv -f "$__dt_vars.new" "$__dt_vars" 2>/dev/null || true
  return $__dt_rc
}
trap() {
  local __dt_h __dt_s
  if [ "$1" = -- ]; then shift; fi
  case "$1" in -l|-p|"") builtin trap "$@"; return ;; esac
  if [ $# -lt 2 ]; then set -- - "$1"; fi
  __dt_h=$1; shift
  for __dt_s in "$@"; do
    case "$__dt_s" in
      EXIT|exit|SIGEXIT|0)
        case "$__dt_h" in
          -|'') builtin trap __dt_save EXIT ;;
          *) builtin trap "__dt_x=\$?; set +e; __dt_save \$__dt_x; $__dt_h" EXIT ;;
        esac ;;
      *) builtin trap -- "$__dt_h" "$__dt_s" ;;
    esac
  done
}
builtin trap __dt_save EXIT
"""


# Loopback addresses whose port is replaced by a free one per group.
LOOPBACK = re.compile(r"(?<![\w.])(127\.0\.0\.1|localhost):(\d{1,5})(?!\d)")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def remap_ports(text: str, ports: dict) -> str:
    """`text` with every loopback port replaced by this group's free one."""
    def sub(m):
        if m.group(2) not in ports:
            ports[m.group(2)] = str(free_port())
        return f"{m.group(1)}:{ports[m.group(2)]}"
    return LOOPBACK.sub(sub, text)


def shell_script(work: str, name: str, code: str) -> list:
    """argv running `code` with bash -eo pipefail, sharing the group's variables."""
    script = os.path.join(work, name)
    with open(script, "w") as f:
        f.write(PRELUDE % {"vars": shlex.quote(os.path.join(work, ".doctest-vars"))} + code)
    return ["bash", script]


def shown(path: Path) -> str:
    try:
        return str(path.relative_to(REPO))
    except ValueError:
        return str(path)


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


def stop(sessions: list, grace: float = 3.0) -> None:
    """SIGTERM every process group a group started, SIGKILL what is still
    there after `grace` seconds."""
    def alive(pgid: int) -> bool:
        try:
            os.killpg(pgid, 0)
            return True
        except (ProcessLookupError, PermissionError):
            return False

    left = []
    for pgid in sessions:
        try:
            os.killpg(pgid, signal.SIGTERM)
            left.append(pgid)
        except (ProcessLookupError, PermissionError):
            pass
    deadline = time.monotonic() + grace
    while left and time.monotonic() < deadline:
        time.sleep(0.05)
        left = [g for g in left if alive(g)]
    for pgid in left:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def run_group(path: Path, name: str, items, env: dict) -> list[str]:
    failures = []
    work = tempfile.mkdtemp(prefix="wl-doctest-")
    sessions: list[int] = []
    ports: dict = {}
    py = None
    try:
        for line, lang, code, opts in items:
            where = f"{shown(path)}:{line}"
            want = int(opts.get("exit", "0"))
            timeout = float(opts.get("timeout", "120"))
            code = remap_ports(code, ports)
            setup_ok = True
            if "before" in opts:
                argv = shell_script(work, ".before.sh", remap_ports(opts["before"], ports) + "\n")
                rc, out = run(argv, work, env, timeout, sessions)
                if rc != 0:
                    failures.append(f"{where}: hidden setup {opts['before']!r} exited {rc}\n{out[-1500:]}")
                    setup_ok = False
            if setup_ok and lang == "file":
                target = os.path.join(work, opts["file"])
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "w") as f:
                    f.write(code)
                print(f"ok   {where} [{name}] (written to {opts['file']})")
            elif setup_ok:
                t0 = time.monotonic()
                if lang == "python":
                    py = py or PySession(work, env, sessions)
                    rc, out = py.run(code, timeout)
                else:
                    rc, out = run(shell_script(work, ".block.sh", code), work, env, timeout, sessions)
                status = "ok  " if rc == want else "FAIL"
                print(f"{status} {where} [{name}] ({lang}, exit {rc}, want {want}, {time.monotonic() - t0:.1f} s)")
                if VERBOSE:
                    print("    " + out.rstrip().replace("\n", "\n    "))
                if rc != want:
                    failures.append(f"{where}: exited {rc}, the docs promise {want}\n--- output (tail) ---\n{out[-2500:]}")
            if "after" in opts:
                run(shell_script(work, ".after.sh", remap_ports(opts["after"], ports) + "\n"), work, env, timeout,
                    sessions)
    finally:
        if py is not None:
            py.p.stdin.close()
            try:
                py.p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        stop(sessions)
        shutil.rmtree(work, ignore_errors=True)
    return failures


def main(argv: list | None = None) -> int:
    global VERBOSE
    args = sys.argv[1:] if argv is None else argv
    VERBOSE = "-v" in args
    files = [Path(a).resolve() for a in args if a != "-v"] or [REPO / f for f in FILES]
    env = dict(os.environ)
    first = [cli_dir()]
    if sys.prefix != sys.base_prefix:      # a venv: its python, pip and console scripts
        first.append(os.path.dirname(sys.executable))
    env["PATH"] = os.pathsep.join(first + [env.get("PATH", "")])
    env.setdefault("PYTHONUNBUFFERED", "1")
    env.setdefault("PIP_DISABLE_PIP_VERSION_CHECK", "1")
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
