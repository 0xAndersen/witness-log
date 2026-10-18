"""spec/verify-output.schema.json describes `witness-log verify --json` and
the verifier report every binding returns. This test holds the schema to
real output: the Rust CLI's golden outputs (the ones the Go CLI is compared
against), the Python binding's report across verdicts, and, when the CLI
is built, the CLI itself across its flags. It runs in CI."""
import json
import subprocess
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")
import witness_log  # noqa: E402

from cli_witnesses import find_cli  # noqa: E402

REPO = Path(__file__).resolve().parents[3]
SCHEMA = json.loads((REPO / "spec" / "verify-output.schema.json").read_text())
EXIT = {"WITNESSED": {0, 11}, "CONSISTENT-UNWITNESSED": {10}, "UNANCHORED": {20}, "DIVERGED": {30}, "INVALID": {40}}
LOWER = {
    "WITNESSED": "witnessed",
    "CONSISTENT-UNWITNESSED": "consistent_unwitnessed",
    "UNANCHORED": "unanchored",
    "DIVERGED": "diverged",
    "INVALID": "invalid",
}


def _validator(ref=None):
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    if ref is None:
        return jsonschema.Draft202012Validator(SCHEMA)
    return jsonschema.Draft202012Validator({"$schema": SCHEMA["$schema"], "$defs": SCHEMA["$defs"], "$ref": ref})


def _check_output(doc, where):
    errors = list(_validator().iter_errors(doc))
    assert not errors, f"{where}: {errors[0].json_path}: {errors[0].message}"
    assert doc["exit_code"] in EXIT[doc["verdict"]], where
    assert doc["report"]["verdict"] == LOWER[doc["verdict"]], where
    if not doc["directory_pinned"]:
        assert doc["report"]["quorum"] is None, where
    assert bool(doc["report"]["failures"]) == (doc["verdict"] == "INVALID"), where


def test_golden_cli_outputs_match_the_schema():
    files = sorted((REPO / "clients" / "go" / "testdata" / "expect").glob("*.json"))
    assert len(files) >= 10
    for f in files:
        doc = json.loads(f.read_text())
        _check_output(doc, f.name)
        exit_file = f.with_suffix(".exit")
        if exit_file.exists():
            assert int(exit_file.read_text()) == doc["exit_code"], f.name


def test_binding_reports_match_the_schema():
    v = _validator("#/$defs/report")
    sample = (REPO / "examples" / "sample-dossier.json").read_text()
    directory = (REPO / "examples" / "trusted-directory.json").read_text()
    ident = json.loads(sample)["identity_pubkey"]
    tampered = json.loads(sample)
    tampered["leaves"][0]["payload_hash"] = "00" * 32
    cases = [
        (sample, None, None),
        (sample, ident, directory),
        (sample, "ab" * 32, directory),
        (json.dumps(tampered), ident, directory),
    ]
    seen = set()
    for dossier, identity, d in cases:
        report = json.loads(witness_log.verify_dossier_json(dossier, 0.66, identity, d))
        errors = list(v.iter_errors(report))
        assert not errors, f"{errors[0].json_path}: {errors[0].message}"
        seen.add(report["verdict"])
        report = json.loads(witness_log.verify_dossier_json(dossier, 0.66, identity, d, subject_org="Example Org"))
        assert not list(v.iter_errors(report))
    assert {"unanchored", "invalid"} <= seen


@pytest.mark.skipif(find_cli() is None, reason="witness-log CLI not built")
def test_cli_verify_json_matches_the_schema():
    cli = find_cli()
    sample = REPO / "examples" / "sample-dossier.json"
    directory = REPO / "examples" / "trusted-directory.json"
    ident = json.loads(sample.read_text())["identity_pubkey"]
    runs = [
        [],
        ["--directory", str(directory)],
        ["--directory", str(directory), "--identity", ident, "--subject-org", "Some Org"],
        ["--directory", str(directory), "--min-witnesses", "1", "--allow-sub-majority"],
        ["--directory", str(directory), "--known-head", "1:" + "ab" * 32],
        ["--identity", "cd" * 32],
    ]
    for extra in runs:
        p = subprocess.run([cli, "verify", str(sample), "--json", *extra], capture_output=True, text=True)
        doc = json.loads(p.stdout)
        _check_output(doc, " ".join(extra) or "(no flags)")
        assert p.returncode == doc["exit_code"], extra
    assert doc["verdict"] == "INVALID"


@pytest.mark.skipif(find_cli() is None, reason="witness-log CLI not built")
def test_cli_fleet_anchor_output_matches_the_schema(tmp_path):
    """Corpus 14 (RFC-0001, experimental): the optional fleet fields too."""
    cli = find_cli()
    vec = json.loads((REPO / "corpus" / "14_fleet_anchor.json").read_text())
    directory = tmp_path / "trusted.json"
    directory.write_text(json.dumps(vec["trusted_directory"]))
    seen = set()
    for name, dossier in vec["dossiers"].items():
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(dossier))
        for extra in ([], ["--accept-fleet-anchor"]):
            p = subprocess.run(
                [cli, "verify", str(path), "--json", "--directory", str(directory), "--min-witnesses", "2",
                 "--subject-org", vec["fleet_operator_org"], *extra],
                capture_output=True, text=True,
            )
            doc = json.loads(p.stdout)
            _check_output(doc, f"{name} {extra}")
            assert p.returncode == doc["exit_code"]
            fa = doc["report"].get("fleet_anchor")
            if fa:
                seen.add(fa["status"])
    assert {"ignored", "verified", "failed"} <= seen
