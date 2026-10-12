# witness-log and Tessera

Part of [Comparison](Comparison). Checked against primary sources on
2026-10-12; links at the bottom.

## What Tessera is

[Tessera](https://github.com/transparency-dev/tessera) is a Go library from
the transparency-dev project for building tile-based transparency logs
([`c2sp.org/tlog-tiles`](https://c2sp.org/tlog-tiles)). It is the successor
to Trillian v1 as the way to build and operate logs, with storage drivers for
GCP, AWS and a POSIX filesystem, and it is the storage layer of Sigstore's
Rekor v2. The code you write around it is a "personality" that decides what
an entry is and who may add one. Licensed Apache-2.0.

## What it is good at

- **Running a public log at scale.** Batching, sequencing, integration and
  checkpoint publishing are designed from a decade of operating CT logs.
  The tile API makes the read path static files, so reads scale like a CDN
  and a frozen log can be served with no running process at all.
- **The witness protocol, natively.** A personality configures a witness
  policy ([`c2sp.org/tlog-policy`](https://c2sp.org/tlog-policy)) and
  Tessera contacts witnesses speaking
  [`c2sp.org/tlog-witness`](https://c2sp.org/tlog-witness), collects
  cosignatures, and publishes a checkpoint only once the policy is
  satisfied. witness-log's witnesses speak the same protocol; this is where
  it comes from.
- **Production pedigree.** Rekor v2 depends on Tessera's storage backends;
  the transparency-dev ecosystem runs the witnesses and tooling that the CT
  and Go checksum database communities rely on.
- **Generic entries.** Any bytes can be an entry, including (if you design
  the personality that way) salted commitments.

## Where it differs, by property

| property | Tessera | witness-log |
|---|---|---|
| unit | one log per operator, many submitters | one log per agent, one writer |
| what a verifier gets | public tiles: every entry is readable by anyone | a private dossier per agent: only salted commitments ever leave the machine |
| witnessing | `tlog-witness` cosignatures gathered by the log before publishing, per a `tlog-policy` | the same protocol; the *verifier* scores receipts against its own directory and requires ≥2 distinct `operator_org` |
| verification output | proofs and cosigned checkpoints; verdict policy is up to the client | one offline command, four verdicts, exit code is the verdict |
| entry schema | none (the personality decides) | eight leaf types: intent, result, memory, redaction, revocation, handoff, authorization, external anchor |
| erasure | not a library feature; public entries are permanent | salted payload hashes, `forget(i)` deletes the salt, proofs intact, a `0x03` tombstone records it |
| keys | one log signing key | long-lived identity key + per-run session keys bound to it, custody disclosed |
| operating model | a service with storage (cloud bucket or filesystem) | a library in the agent process plus a journal file; a witness is `witness-log witness serve` |

The honest summary: Tessera is the better *log*. witness-log is a narrower
thing, an agent-shaped record format and verifier that reuses the same
witness protocol. The primitives (RFC 6962 trees, signed notes,
cosignatures) are the same.

## When to choose Tessera instead

- You want **one public, append-only log** that many parties submit to and
  anyone can read: a registry of releases, model cards, attestations,
  certificates, or a public record of agent registrations. Tessera is built
  for that and witness-log is not.
- Throughput or read scale matters more than per-agent privacy.
- The content is non-personal and meant to be public forever.

A sensible combination: agents keep witness-log journals (private, erasable,
per agent) and publish their checkpoints, or their `ExternalAnchor` targets,
into a Tessera-based public log. witness-log's §9.3 checkpoints are
`tlog-checkpoint` signed notes, so the formats already line up.

A team already running Tessera could add an agent schema and salted erasure
on top; the [conformance corpus](Spec-and-Interop) exists so that such an
implementation can prove it computes the same bytes.

## If this is wrong

If anything here misstates Tessera, open a PR against
`docs/wiki/Comparison-Tessera.md` with a link to the source.

## Sources (checked 2026-10-12)

- Tessera README: <https://github.com/transparency-dev/tessera> (status, roadmap, witnessing section, Apache-2.0)
- C2SP specifications: <https://c2sp.org/tlog-tiles>, <https://c2sp.org/tlog-witness>, <https://c2sp.org/tlog-policy>
- Sigstore, "Rekor v2 GA" (2025-10-10): <https://blog.sigstore.dev/rekor-v2-ga/> ("We depend on Tessera's storage backends"; witnessing "will be implemented soon")
