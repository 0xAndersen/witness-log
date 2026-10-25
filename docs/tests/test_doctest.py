"""Tests for docs/doctest.py, the runner behind `make docs`: the options
the docs rely on (file=, shell variables shared by a group's blocks,
exit=) and that every page with a marked block is in its default list.
They need no witness-log build: the CLI directory only has to exist."""
import importlib.util
import re
import sys
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
