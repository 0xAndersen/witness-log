"""The outside swarm's exit status is a gate (outside review III, M2).

What a persona checks -- a tampered dossier verifies INVALID, a fork is
refused with 422, an oversized body with 413 -- is an expectation: one that
does not hold fails the run. Before, these were notes, which never moved
the exit status, so a verifier that accepted a tampered dossier still
exited 0. These tests run ``examples/swarm/outside.py`` against three real
witnesses: honest (exit 0, and the checks ran) and with each injected fault
(exit non-zero, on the named expectations, with expected and observed
values in the results; no agent crashed and no operation failed, so the
expectations alone moved the exit status).
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from cli_witnesses import REPO, CliWitness, find_cli  # noqa: E402

CLI = find_cli()
pytestmark = pytest.mark.skipif(CLI is None, reason="witness-log CLI not built (cargo build --release -p witness-log-cli)")

OUTSIDE = REPO / "examples" / "swarm" / "outside.py"
# 300 assigned agents filtered to these personas: 11 auditors, 7 adversaries
# and 3 verifiers (the assignment is deterministic).
PERSONAS = "auditor,adversary,verifier_only"
AGENTS = 300

TAMPER = "a tampered dossier verifies INVALID (exit 40)"
DIFF = "`diff` of a dossier and its tampered copy exits 40"
KNOWN_HEAD = "a contradicted --known-head verifies DIVERGED (exit 30)"
UNANCHORED = "without a directory the sample is UNANCHORED, never witnessed"
EDITED = "a checkpoint edited by 1 ms verifies INVALID"
FORK = "no witness cosigns a fork of a head it cosigned"
FORK_422 = "every witness refuses a same-size fork with 422"
JUNK = "a junk add-checkpoint body is refused with 400"
OVERSIZED = "a 70 KiB add-checkpoint body is refused with 413"


@pytest.fixture(scope="module")
def directory(tmp_path_factory):
    root = tmp_path_factory.mktemp("gate-witnesses")
    ws = [CliWitness(CLI, root, f"g{i}", org) for i, org in enumerate(("Gate Org A", "Gate Org B", "Gate Org B"))]
    path = root / "directory.json"
    path.write_text(json.dumps({"witnesses": [w.entry for w in ws]}))
    yield path
    for w in ws:
        w.stop()


def swarm(tmp_path, directory, fault=None):
    out = tmp_path / (fault or "honest")
    cmd = [sys.executable, str(OUTSIDE), "--agents", str(AGENTS), "--only", PERSONAS, "--directory", str(directory),
           "--out", str(out), "--processes", "1", "--threads", "6", "--cli", CLI]
    if fault:
        cmd += ["--inject-fault", fault]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    assert (out / "results.json").exists(), r.stdout[-2000:] + r.stderr[-2000:]
    res = json.loads((out / "results.json").read_text())
    report = (out / "REPORT.md").read_text()
    # A fault run must fail on expectations, not because an agent crashed or
    # an operation broke: that would prove nothing about the gate.
    crashed = [x for x in res["results"] if x["status"] != "ok"]
    failed_ops = [o for x in res["results"] for o in x["ops"] if not o["ok"]]
    assert not crashed and not failed_ops, (crashed[:2], failed_ops[:2], r.stdout[-2000:])
    return r.returncode, res, report


def test_honest_run_passes_and_runs_every_check(tmp_path, directory):
    code, res, report = swarm(tmp_path, directory)
    exp = res["expectations"]
    assert code == 0, report
    assert exp["failed"] == 0, exp["failed_by_check"]
    for check in (TAMPER, DIFF, KNOWN_HEAD, UNANCHORED, EDITED, FORK, FORK_422, JUNK, OVERSIZED):
        assert exp["by_check"].get(check, 0) > 0, f"{check!r} never ran: {exp['by_check']}"
    assert "- expectations checked:" in report and "; failed: 0" in report


def test_a_verifier_that_accepts_anything_fails_the_run(tmp_path, directory):
    code, res, report = swarm(tmp_path, directory, "weak-verifier")
    exp = res["expectations"]
    assert code != 0, report
    assert exp["failed"] > 0
    for check in (TAMPER, DIFF, KNOWN_HEAD, UNANCHORED, EDITED):
        assert exp["failed_by_check"].get(check) == exp["by_check"][check], (check, exp)
    # The witnesses were honest: their checks still held.
    for check in (FORK, FORK_422, JUNK, OVERSIZED):
        assert check not in exp["failed_by_check"], (check, exp["failed_by_check"])
    failed = [f for x in res["results"] for f in x["failed_expectations"] if f["check"] == TAMPER]
    assert failed and all(f["expected"] == "exit 40 INVALID" and f["observed"].startswith("exit 0 (WITNESSED)") for f in failed)
    assert f"{TAMPER}: expected `exit 40 INVALID`, observed `exit 0 (WITNESSED)" in report


def test_witnesses_that_accept_a_fork_fail_the_run(tmp_path, directory):
    code, res, report = swarm(tmp_path, directory, "lax-witness")
    exp = res["expectations"]
    assert code != 0, report
    for check in (FORK, FORK_422, JUNK, OVERSIZED):
        assert exp["failed_by_check"].get(check) == exp["by_check"][check], (check, exp)
    for check in (TAMPER, DIFF, KNOWN_HEAD, UNANCHORED, EDITED):
        assert check not in exp["failed_by_check"], (check, exp["failed_by_check"])
    failed = [f for x in res["results"] for f in x["failed_expectations"] if f["check"] == OVERSIZED]
    assert failed and all(f["expected"] == "413" and f["observed"].startswith("200 from ") for f in failed)
