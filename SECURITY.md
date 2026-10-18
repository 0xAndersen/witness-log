# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.** Report it
privately using GitHub's built-in flow: go to the **Security** tab of
this repository → **Report a vulnerability**. This opens a private
advisory visible only to maintainers until a fix is ready.

If that flow is unavailable to you for any reason, email the address
listed in the repository's GitHub profile (or open a public issue asking
for a private contact — do not include vulnerability details in that
issue itself).

## What to include

- What you found and why it's exploitable (a proof-of-concept test, like
  the ones in `crates/witness-log-network/tests/review_regressions.rs`,
  is the fastest way to make a report actionable).
- Which verdict, guarantee, or claim in `THREAT_MODEL.md` or
  `spec/SPEC.md` the finding contradicts, if applicable.
- Your assessment of severity and why.

## Response

This is a pre-1.0, community-maintained project with no dedicated
security team and no SLA. In practice: expect an initial response within
a few days, not hours. A fix's timeline depends on severity and
complexity — a cryptographic soundness issue is a stop-everything
priority; a documentation/implementation mismatch with no exploitability
is not.

## Scope

In scope: anything in `crates/`, the wire format specified in
`spec/SPEC.md`, and the conformance corpus in `corpus/`. Anything that
lets a fabricated or tampered dossier reach a stronger verdict than it
should (see `THREAT_MODEL.md`'s verdict table) is a security issue, not
a bug report, regardless of how it's framed.

Also in scope: the MCP server (`witness_log.mcp_server`) and the Python
`Witnesser`, which take caller-supplied witness directories (0.3.5's MCP
server followed `file://` URLs from them).

Auditors: [`docs/SECURITY-AUDIT-BRIEF.md`](docs/SECURITY-AUDIT-BRIEF.md)
scopes the core and the verifier, lists every prior finding with its fix,
and gives the commands for the test suites, property tests, conformance
corpus and fuzzers.

Out of scope: the `fuzz/` harness itself finding nothing (fuzzing
coverage gaps are a bug report, not a vulnerability), and third-party
dependencies (report those to the dependency's own maintainers; `cargo
deny check` runs in CI against known advisories).

## Verifying a release

From v0.6.1, every asset of a GitHub release (the CLI archives and
`SHA256SUMS`) carries a SLSA build-provenance attestation, signed through
Sigstore by `.github/workflows/release.yml`. `SHA256SUMS` alone only
proves a download matches what is in the release; the attestation proves
the release workflow built it from the tagged commit:

```sh
gh attestation verify SHA256SUMS --repo 0xAndersen/witness-log \
  --signer-workflow 0xAndersen/witness-log/.github/workflows/release.yml \
  --deny-self-hosted-runners
sha256sum --ignore-missing -c SHA256SUMS
```

The GitHub Action and the project's Docker image build run that check
themselves. PyPI wheels carry PEP 740 attestations from Trusted
Publishing; npm packages carry npm provenance.

## Known, disclosed limitations

This is not a vulnerability report queue for things `THREAT_MODEL.md`
already documents as out of scope, or for things `spec/SPEC.md` §9.2's
verdict table already states plainly — read both first. Known
limitations as of this writing include: no protection against a
compromised host prior to signing, no protection against a malicious or
hallucinating agent logging false content, no protection against log
truncation without a witnessed checkpoint to compare against, and no
protection at all when witness diversity is thin or absent (the
`Unanchored` verdict exists specifically to make this visible rather
than hidden). None of these are bugs; all are structural limits stated
up front. A report that one of these categories is exploitable in a way
`THREAT_MODEL.md` or SPEC.md §9.2 doesn't already describe IS in scope
and welcome.
