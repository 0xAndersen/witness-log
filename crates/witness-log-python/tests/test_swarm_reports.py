"""The swarm drivers' reports get committed (examples/swarm/reports/), so
they must not carry the absolute path of the CLI that was tested (it
names the machine and the account) or the kernel release string
platform.platform() returns (security sweep F13). Each driver runs a few
agents that need no network."""

from __future__ import annotations

import json
import os
import pathlib
import platform
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from cli_witnesses import REPO, find_cli  # noqa: E402

CLI = find_cli()
pytestmark = pytest.mark.skipif(CLI is None, reason="witness-log CLI not built (cargo build --release -p witness-log-cli)")
SWARM = REPO / "examples" / "swarm"
TRUSTED = REPO / "examples" / "trusted-directory.json"


def _shown(cli: str) -> str:
    p = os.path.abspath(cli)
    return os.path.relpath(p, REPO) if p.startswith(str(REPO) + os.sep) else os.path.basename(p)


def _check(text: str):
    assert os.path.abspath(CLI) not in text, "the report carries the CLI's absolute path"
    assert f"`{_shown(CLI)}`" in text, text[:400]


@pytest.mark.parametrize("driver", ["outside.py", "outside_0_4.py"])
def test_outside_reports_name_the_cli_relative_to_the_repository(tmp_path, driver):
    out = tmp_path / "out"
    r = subprocess.run(
        [sys.executable, str(SWARM / driver), "--agents", "300", "--only", "verifier_only", "--directory", str(TRUSTED),
         "--out", str(out), "--processes", "1", "--threads", "2", "--cli", CLI],
        capture_output=True, text=True, timeout=600,
    )
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]
    _check((out / "REPORT.md").read_text())


def test_run_py_names_the_cli_relative_to_the_repository_and_omits_the_kernel_release(tmp_path):
    out = tmp_path / "out"
    r = subprocess.run(
        [sys.executable, str(SWARM / "run.py"), "--only", "T001", "--out", str(out), "--cli", CLI],
        capture_output=True, text=True, timeout=600,
    )
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]
    report = (out / "REPORT.md").read_text()
    _check(report)
    env = json.loads((out / "results.json").read_text())["environment"]
    assert env["platform"] == f"{platform.system()} {platform.machine()}"
    assert env["cli"] == _shown(CLI)
    if platform.release():
        assert platform.release() not in report and platform.release() not in json.dumps(env)
