"""Tests for docs/doctest.py, the runner behind `make docs`: the options
the docs rely on (file=, shell variables shared by a group's blocks,
exit=) and that every page with a marked block is in its default list.
They need no witness-log build: the CLI directory only has to exist."""
import importlib.util
import os
import re
import socket
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "doctest.py"
spec = importlib.util.spec_from_file_location("docs_doctest", SCRIPT)
doctest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(doctest)


@pytest.fixture(autouse=True)
def any_cli(monkeypatch):
    monkeypatch.setenv("WITNESS_LOG_CLI", sys.executable)


def page(tmp_path, text):
    p = tmp_path / "page.md"
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_file_option_writes_the_block_for_a_later_block_to_run(tmp_path, capsys):
    md = page(tmp_path, """
<!-- doctest: group=g file=hello.py -->
```python
import sys
print("hello", sys.argv[1])
```

<!-- doctest: group=g -->
```sh
test "$(python3 hello.py reader)" = "hello reader"
```

<!-- doctest: group=g file=conf/settings.json -->
```json
{"any": "fence language"}
```

<!-- doctest: group=g -->
```sh
grep -q '"any"' conf/settings.json
```
""")
    assert doctest.main([md]) == 0
    out = capsys.readouterr().out
    assert "written to hello.py" in out and "4 of 4 marked blocks" in out


def test_shell_variables_carry_through_a_group_as_in_one_terminal(tmp_path, capsys):
    md = page(tmp_path, """
<!-- doctest: group=g before="FROM_SETUP=hidden" -->
```sh
KEY="two words"
ARR=(a "b c")
export EXPORTED=yes
```

<!-- doctest: group=g exit=40 -->
```sh
LATE=set-before-the-failure
sh -c 'exit 40'
LATER=never
```

<!-- doctest: group=g -->
```sh
test "$KEY" = "two words" && test "${ARR[1]}" = "b c" && test "$FROM_SETUP" = hidden
test "$LATE" = set-before-the-failure && test -z "${LATER-}"
sh -c 'test "$EXPORTED" = yes'
```

<!-- doctest: group=other -->
```sh
test -z "${KEY-}"
```
""")
    assert doctest.main([md]) == 0, capsys.readouterr().out


def test_a_blocks_own_exit_trap_runs_and_keeps_its_variables(tmp_path, capsys):
    """A block's `trap ... EXIT` used to replace the runner's, dropping the
    variables that block set."""
    md = page(tmp_path, """
<!-- doctest: group=g exit=3 -->
```sh
trap 'echo "handler saw $?" > handler.txt' EXIT
KEPT=yes
sh -c 'exit 3'
```

<!-- doctest: group=g -->
```sh
test "$KEPT" = yes
grep -qx 'handler saw 3' handler.txt
trap - EXIT
ALSO=kept
```

<!-- doctest: group=g -->
```sh
test "$ALSO" = kept
```
""")
    assert doctest.main([md]) == 0, capsys.readouterr().out


@pytest.mark.parametrize("name", ["/tmp/evil.py", "../evil.py", "a/../../evil.py", "..\\\\evil.py", ""])
def test_file_option_stays_inside_the_group_directory(tmp_path, name):
    md = page(tmp_path, f"""
<!-- doctest: file="{name}" -->
```python
print("x")
```
""")
    with pytest.raises(SystemExit, match="relative path inside"):
        doctest.main([md])


def test_loopback_ports_are_replaced_by_free_ones_per_group(tmp_path, capsys):
    """A page that names 127.0.0.1:N must not reach whatever already
    listens on N: here, a listener the test holds."""
    with socket.socket() as held:
        held.bind(("127.0.0.1", 0))
        held.listen()
        port = held.getsockname()[1]
        md = page(tmp_path, f"""
<!-- doctest: group=g before="echo http://127.0.0.1:{port}/ > before.txt" -->
```sh
python3 -c "import socket, sys; h, p = sys.argv[1].split(':'); socket.socket().bind((h, int(p))); print(p)" 127.0.0.1:{port} > got.txt
test "$(cat got.txt)" != {port}
grep -q "127.0.0.1:$(cat got.txt)/" before.txt
echo localhost:{port} 127.0.0.10:{port} > other.txt
```

<!-- doctest: group=g -->
```python
got = open("got.txt").read().strip()
assert open("other.txt").read().split() == ["localhost:" + got, "127.0.0.10:{port}"]
```
""")
        assert doctest.main([md]) == 0, capsys.readouterr().out


def gone(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    try:  # killed, and only waiting for init to reap it
        return open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0] == "Z"
    except OSError:
        return False


def test_a_process_that_ignores_sigterm_is_killed(tmp_path, capsys, monkeypatch):
    md = page(tmp_path, """
<!-- doctest -->
```sh
sh -c 'trap "" TERM; echo $$ > stubborn.pid; while :; do sleep 0.1; done' &
until test -s stubborn.pid; do sleep 0.05; done
cp stubborn.pid "$PIDFILE"
```
""")
    pidfile = tmp_path / "pid"
    monkeypatch.setenv("PIDFILE", str(pidfile))
    t0 = time.monotonic()
    assert doctest.main([md]) == 0, capsys.readouterr().out
    assert time.monotonic() - t0 < 30
    pid = int(pidfile.read_text())
    for _ in range(100):
        if gone(pid):
            return
        time.sleep(0.05)
    os.kill(pid, 9)
    pytest.fail(f"process {pid} survived the group")


def test_a_block_that_breaks_its_promise_fails_the_run(tmp_path, capsys):
    md = page(tmp_path, """
<!-- doctest: exit=20 -->
```sh
true
```
""")
    assert doctest.main([md]) == 1
    assert "exited 0, the docs promise 20" in capsys.readouterr().out


def test_every_page_with_a_marked_block_runs_by_default():
    repo = SCRIPT.parent.parent
    pages = [repo / "README.md", *sorted((repo / "docs").rglob("*.md"))]
    marked = {str(p.relative_to(repo)) for p in pages
              if re.search(r"^<!--\s*doctest", p.read_text(encoding="utf-8"), re.M)}
    assert marked, "no marked pages found"
    assert marked <= set(doctest.FILES), sorted(marked - set(doctest.FILES))
