"""Tests for registry/build_directory.py: it builds a directory only from
entries that pass registry/validate.py (outside review III, P1). Before,
it concatenated whatever registry/witnesses/*.json held, so an http://
URL, a malformed key, an empty org or a duplicate key went straight into
the trust anchor of every verdict computed against it."""
import importlib.util
import io
import json
import os
import subprocess
import sys

import pytest

from test_validate import KEY, KEY2, entry, served, server, write_registry  # noqa: F401  (server is a fixture)

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "build_directory.py")
spec = importlib.util.spec_from_file_location("build_directory", SCRIPT)
build_directory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_directory)


def build(reg, *flags):
    out = io.StringIO()
    code = build_directory.main(["--registry-dir", reg, *flags], out=out)
    return code, out.getvalue()


def run_script(reg, *flags):
    """The script as CI and the docs run it: `build_directory.py > directory.json`."""
    return subprocess.run([sys.executable, SCRIPT, "--registry-dir", reg, *flags], capture_output=True, text=True)


def test_valid_registry_builds_every_entry_in_file_order(tmp_path):
    a = entry()
    b = entry(name="w2.example.net/witness", operator_org="Example Org B", url="https://w2.example.net", pubkey=KEY2)
    p = entry(name="p.example.com/w", operator_org="Project", url="https://p.example.com", pubkey="cd" * 32,
              is_project_operated=True)
    reg = write_registry(tmp_path, a, b, p)
    code, out = build(reg)
    assert code == 0
    assert json.loads(out) == {"witnesses": [a, b, p]}
    code, out = build(reg, "--exclude-project")
    assert code == 0 and json.loads(out) == {"witnesses": [a, b]}


BAD = {
    "http url": dict(url="http://w1.example.org"),
    "loopback url": dict(url="https://127.0.0.1:7380"),
    "localhost url": dict(url="https://localhost:7380"),
    "not a url": dict(url="ftp://w1.example.org"),
    "uppercase pubkey": dict(pubkey=KEY.upper()),
    "short pubkey": dict(pubkey="ab" * 31),
    "pubkey with whitespace": dict(pubkey=" " + KEY),
    "empty org": dict(operator_org=""),
    "blank org": dict(operator_org="   "),
    "unspecified org": dict(operator_org="unspecified"),
    "org with stray whitespace": dict(operator_org="Example  Org"),
    "name with +": dict(name="w1.example.org+witness"),
    "unknown runtime": dict(runtime="robot"),
    "non-boolean is_project_operated": dict(is_project_operated="false"),
    "unknown field": dict(extra=1),
}


@pytest.mark.parametrize("why", sorted(BAD))
def test_an_entry_validate_py_rejects_fails_the_build(tmp_path, capsys, why):
    good = entry(name="w2.example.net/witness", operator_org="Example Org B", url="https://w2.example.net", pubkey=KEY2)
    reg = write_registry(tmp_path, good, entry(**BAD[why]))
    code, out = build(reg)
    err = capsys.readouterr().err
    assert code == 1 and out == "", why
    assert "e1.json" in err and "refusing to build a directory" in err, err


def test_a_missing_field_fails_the_build(tmp_path, capsys):
    e = entry()
    del e["is_project_operated"]
    code, out = build(write_registry(tmp_path, e))
    assert code == 1 and out == "" and "missing" in capsys.readouterr().err


def test_duplicate_key_or_name_fails_the_build(tmp_path, capsys):
    a = entry()
    same_key = entry(name="w2.example.net/witness", operator_org="Example Org B", url="https://w2.example.net")
    code, out = build(write_registry(tmp_path, a, same_key))
    assert code == 1 and out == "" and "duplicate pubkey" in capsys.readouterr().err
    same_name = entry(operator_org="Example Org B", url="https://w2.example.net", pubkey=KEY2)
    (tmp_path / "n").mkdir()
    code, out = build(write_registry(tmp_path / "n", a, same_name))
    assert code == 1 and out == "" and "duplicate name" in capsys.readouterr().err


def test_a_file_that_is_not_json_fails_the_build(tmp_path, capsys):
    reg = write_registry(tmp_path, entry())
    with open(os.path.join(reg, "zz.json"), "w") as f:
        f.write("{")
    code, out = build(reg)
    assert code == 1 and out == "" and "not JSON" in capsys.readouterr().err


def test_allow_insecure_accepts_http_and_loopback(tmp_path):
    e = entry(url="http://127.0.0.1:7380")
    reg = write_registry(tmp_path, e)
    assert build(reg)[0] == 1
    code, out = build(reg, "--allow-insecure")
    assert code == 0 and json.loads(out) == {"witnesses": [e]}


def test_the_script_refuses_and_prints_nothing(tmp_path):
    """What `build_directory.py > trusted.json` does with a bad entry:
    exit 1 and an empty stdout, so a pipeline cannot use a partial file."""
    reg = write_registry(tmp_path, entry(url="http://w1.example.org"))
    r = run_script(reg)
    assert r.returncode == 1 and r.stdout == "", r
    assert "plain http" in r.stderr


def test_the_live_check_is_off_unless_asked(tmp_path, capsys, server):
    """Offline by default (CI, air-gapped verifiers); --live cross-checks
    the served key and org like validate.py; --require-live makes an
    unreachable URL an error."""
    e = entry(url=server.url)
    server.handler.body = json.dumps(served(e, pubkey_hex=KEY2)).encode()
    reg = write_registry(tmp_path, e)
    code, out = build(reg, "--allow-insecure")
    assert code == 0 and json.loads(out) == {"witnesses": [e]}
    code, out = build(reg, "--allow-insecure", "--live")
    assert code == 1 and out == "" and "serves key" in capsys.readouterr().err
    server.handler.body = json.dumps(served(e)).encode()
    assert build(reg, "--allow-insecure", "--live")[0] == 0
    server.handler.status = 503
    code, _ = build(reg, "--allow-insecure", "--live")
    assert code == 0 and "not reachable" in capsys.readouterr().err
    assert build(reg, "--allow-insecure", "--live", "--require-live")[0] == 1


def test_flags(tmp_path):
    reg = write_registry(tmp_path, entry())
    with pytest.raises(SystemExit) as e:
        build(reg, "--bogus")
    assert e.value.code == 2
    with pytest.raises(SystemExit) as e:
        build(reg, "--require-live")
    assert e.value.code == 2


def test_real_registry_builds():
    """The committed registry (possibly empty) builds, as CI runs it."""
    r = subprocess.run([sys.executable, SCRIPT], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert isinstance(json.loads(r.stdout)["witnesses"], list)
