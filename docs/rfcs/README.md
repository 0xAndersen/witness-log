# RFCs

Proposals to change what `spec/SPEC.md` says, how `witness-log verify`
decides, or how the witness network is joined. An RFC is a document, not a
decision: nothing in this directory is implemented or normative until the
steps below have been taken, and the spec is the only normative text.

## Index

| RFC | title | status | what it would change |
|---|---|---|---|
| [RFC-0001](RFC-0001-fleet-checkpoint-log.md) | Fleet checkpoint log: one C2SP log per organisation | Draft; experimental prototype (0.6.0) behind `verify --accept-fleet-anchor` | dossier gains an optional field; no leaf, STH or receipt change; vector 14 pins the prototype and is outside conformance (`conform` compares 01–12 only) |
| [RFC-0002](RFC-0002-verdict-strictness-and-INVALID.md) | Verdict strictness and an INVALID verdict | Implemented (0.5.0) | verdict set and exit codes (strict by default, exit 11; INVALID, exit 40; DIVERGED narrowed); corpus vector 13; no wire change |
| [RFC-0003](RFC-0003-dns-txt-self-registration.md) | DNS TXT self-registration of witnesses | Draft | registry process; no wire change |
| [RFC-0004](RFC-0004-scitt-receipts.md) | SCITT (RFC 9942) receipts for leaves | Draft | a second signing context for the identity key; new optional artefact |
| [RFC-0005](RFC-0005-index-based-revocation.md) | Index-based revocation cut-off witnesses can pin | Implemented, experimental (0.4.3) | v2 revocation message with a presence-byte field; new witness endpoint |

Statuses: **Draft** (open for comment), **Accepted** (vectors agreed, code
may land behind a flag), **Implemented** (spec text merged, flag removed or
defaulted), **Withdrawn** (kept for the record, with the reason).

## The process

1. **RFC.** A pull request adds `docs/rfcs/RFC-NNNN-<slug>.md` with the
   sections below and `Status: Draft`. Discussion happens on the PR and in
   the repository's GitHub Discussions; the RFC links the thread. Anyone may
   open one. `GOVERNANCE.md` describes who approves: at least one maintainer
   outside the proposing organisation once such maintainers exist.
2. **Corpus vectors.** Before any code, the RFC's "Corpus vectors needed"
   section is turned into concrete vectors under `corpus/` (new file,
   numbered after the last) and a from-scratch check that they are what
   the RFC says. If the vectors cannot be written, the design is not
   finished. Vectors for a Draft RFC live on the RFC's branch, not on
   `main`, so `witness-log conform` on `main` keeps describing the
   released format.
3. **Implementation behind a flag.** The reference implementation gains
   the behaviour behind an explicit opt-in (a CLI flag, a `VerifyContext`
   field, a Cargo feature) that defaults to the current behaviour. Tests
   pin both the old and the new path. The flag ships in a minor release so
   that a second implementation can be checked against the vectors with
   real artefacts.
4. **Spec change.** A pull request edits `spec/SPEC.md` (and
   `spec/dossier.schema.json` where relevant), lands the vectors on `main`,
   flips or removes the flag, and records the RFC as Implemented. Only at
   this step does the behaviour become normative. Pre-1.0 this may be a
   minor release; after 1.0, changes to §2–§9 are a new major (`SPEC.md`,
   top).

An RFC that would change the wire format of an existing artefact (leaf
encoding, STH message, receipt message, C2SP mapping) states so under
"Wire changes" and is held to the strictest reading of step 4: every
historically issued artefact must keep verifying with the same result.

## Sections every RFC has

`Status`, `Motivation`, `Design`, `Wire changes` (explicitly "none" when
true), `Corpus vectors needed`, `Backward compatibility`, `Open questions`,
and a one-line "How to comment" pointing at the discussion thread.

## Why this is heavier than a pull request

The verifier's exit code is a contract other people's CI depends on, and
the corpus is the only thing that makes a second implementation checkable.
Changing either by accident is the failure mode this process exists to
prevent; the cost is a few days of writing per change, which is cheap
against an artefact that is supposed to verify in ten years.
