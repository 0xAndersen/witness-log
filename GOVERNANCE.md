# Governance

## Why this document exists before there's anything to govern

Trust infrastructure that only one party controls the code, the witness
registry, or the spec for is a contradiction — the whole point is to work
even when you don't trust the operator. This document states, in public,
before it's tested by real pressure, how control over this project is
meant to move away from any single maintainer over time. Publishing the
plan early — rather than once people start asking why one person/company
controls agent trust infrastructure — is itself part of the credibility
this project needs to be useful.

## Current state (v0.2, pre-1.0)

Today, this project has a single maintaining entity. That is normal and
expected for a pre-1.0 protocol — someone has to make fast decisions while
the design is still moving. It is not the intended end state, and the
triggers below are meant to be concrete enough that "is it time yet" isn't
a judgment call made unilaterally by that same entity.

## Federation is a design requirement, not a future nicety

A single canonical registry or witness network, even if well-run, recreates
the exact operator-trust problem this project exists to avoid — just one
layer up. The protocol (SPEC.md) is designed so that:

- Multiple independent registries can issue identities and dossiers under
  the same wire format, and verifiers can check a dossier from any of them
  without deferring to one canonical source.
- The witness directory (`witness-log-network::WitnessDirectory`) is a plain,
  swappable data structure, not a hardcoded list — anyone can run and
  publish their own directory, weighted however they choose, and
  `evaluate_quorum` works against whichever directory a verifier trusts.

If you're building a competing or complementary registry against this same
spec: that's not a fork to be discouraged, that's the design working as
intended.

## Witness network recruitment

The single biggest open gap as of this writing (see THREAT_MODEL.md) is witness
diversity. This is being worked on as an ongoing, public effort:

- Target founding witnesses: operators with pre-existing independent
  credibility and no commercial stake in any single WitnessLog-based product —
  university security labs, existing CT-log operators (who already run
  near-identical infrastructure and would need minimal new work), and
  other agent-infrastructure projects, including ones that compete with
  this one.
- **Agent-operated witnesses are explicitly in scope**, not just
  human-operated ones — see THREAT_MODEL.md's "Witness independence"
  section. `witness-log witness serve` (or `witness_log.WitnessService`
  from Python) is the witness an agent runs; `deploy/witness/AGENT_OPERATOR.md`
  is the playbook. An agent witness registering under `runtime: agent`
  should also disclose a `compute_provider` where possible — recruiting
  witness agents deliberately spread across distinct model/inference
  providers (not just distinct organizations) is its own, separate goal,
  since same-provider agent witnesses share a correlated-failure risk that
  organizational diversity alone doesn't capture.
- The witness directory format and how to offer a witness are documented in
  `crates/witness-log-network/README.md`; `deploy/witness/OPERATORS.md` is
  the runbook. Registration is intentionally lightweight — a name, an
  operator org, a URL, and a public key, which `witness init` prints.
- Progress is tracked publicly. A dossier's diversity score is meant to be
  an uncomfortable, honest number for as long as it takes to genuinely fix,
  not something smoothed over in messaging.

### Bootstrap witnesses

A brand-new witness network has no independent operators on day one, and
refusing to launch until some appear is how protocols never launch. So the
project itself runs a small number of witnesses at launch — `witness-log
witness serve` instances registered as project-operated — to prove
the mechanism works and give real third parties something functioning to
connect to. This is explicitly temporary scaffolding, not a substitute for
real independence, and it's bounded by rules enforced in code, not just
stated here:

- Every project-run witness is registered with `is_project_operated: true`
  in the directory. `evaluate_quorum` collapses **all** witnesses sharing
  that flag into a single bucket on **both** diversity axes, regardless of
  what individual `operator_org` or `compute_provider` labels they carry —
  ten project-run witnesses score identically to one. This is tested
  directly against the specific failure mode of dressing up self-run
  witnesses to look independent (see
  `project_operated_witnesses_never_count_as_diverse_regardless_of_labels`
  in `witness-log-network`'s test suite).
- `witness-log verify` surfaces this on every dossier that includes a
  project-operated signature, unconditionally — it cannot be hidden behind
  a healthy-looking aggregate diversity number.
- A daily-report process publishes, for every checkpoint window: which
  witnesses were active, quorum and diversity stats, and — first and most
  prominently — the count of genuinely independent vs. project-operated
  witnesses currently live. This is public accounting, not a body that
  confers legitimacy on witnesses by "managing" them; the framing matters.
- **Sunset commitment**: project-operated witnesses are meant to shrink as
  a share of any healthy quorum as real third parties join, not persist
  indefinitely as a comfortable default. Once 3+ independent operators are
  active (the same threshold as this document's transition trigger below),
  project-operated witnesses should be treated by verifiers as
  supplementary, not load-bearing, for any quorum involving meaningful
  stakes.

## Spec governance

- All changes to `spec/SPEC.md` go through a public RFC process from the first pre-1.0 release
  onward: proposed as a PR, open for comment, requiring at least one
  approval from a maintainer outside the proposing organization once such
  maintainers exist (see transition triggers below).
- The conformance corpus (`/corpus/`) is the actual enforcement mechanism —
  a spec change isn't complete until the corpus is updated and passes
  against a from-scratch reimplementation check (see CONTRIBUTING.md).
- Where this spec and `draft-maintainer-1f916-agent-record` (or its
  eventual RFC) overlap, known divergences are noted inline in SPEC.md at
  the point they occur (see §1) rather than centralized in one
  comparison section — a dedicated divergence list is future work, not
  written yet.

## Transition triggers

Control transitions from single-maintainer to a multi-stakeholder body
(structure TBD — likely a lightweight foundation along the lines of ISRG/
Let's Encrypt, given the scale) when **any** of the following hold:

1. Three or more independent organizations are operating registries or
   witnesses against this spec, or
2. The project is being relied on for a production dispute, audit, or
   regulatory submission by a party other than the original maintainer, or
3. Twelve months from the v1.0 tag, whichever comes first.

Whichever trigger fires first, the maintainer commits to publicly
initiating the transition process within 90 days — not completing it
unilaterally, initiating an open process for others to participate in.

## What stays out of scope for any governing body

Per THREAT_MODEL.md and the project's non-goals: this project does not
aim to become a settlement/payment rail, and governance of the identity/
audit-trail layer should not expand to cover payment-rail decisions. Keep
these separable so the trust layer stays usable regardless of which
settlement rail an agent economy converges on.
