# Design decisions

The specific choices, each with its reason, that make witness-log the right shape for an agent audit trail rather than one more immutable log. Section numbers refer to `spec/SPEC.md`; the longer discussion is in [Architecture](Architecture) and [Comparison](Comparison).

- **Intent/result semantics are in the data model**, not an integration convention. Eight leaf types (§2), including handoff attestations and authorization events for work that crosses agent boundaries, each with cross-log bindings an auditor can match after the fact.
- **Salted erasure that preserves proofs** (§8): `SHA256(bucket_pad(payload) || salt || index)`, salt outside the tree, tombstone on erase. The property privacy law needs and tamper-evident logs usually cannot offer.
- **Two-tier keys with signed bindings and disclosed custody** (§5): a permanent identity, disposable sessions, and a `custody` field (`self_held`, `kms`, `hsm`, `platform_held`, …) surfaced beside every verdict so a verifier knows whose signature they are looking at.
- **Independence is scored, not assumed** (§7): distinct `operator_org` values, deduplicated by key, with compute-provider diversity reported as a separate axis and project-run witnesses collapsed into one bucket so the project cannot vouch for itself. Many systems count signatures; this one counts organisations.
- **Persist-before-cosign and portable equivocation evidence**: a witness that crashes mid-request can never contradict itself; a log that forks leaves a file.
- **Correct consistency verification**: both roots reconstructed, per RFC 9162. The weaker variant accepts forks at non-power-of-two sizes; we had that bug at ≤0.3.0, found it in a live run, fixed it, and pinned it with an exhaustive test and a corpus vector. The spec now makes the strict algorithm normative.
- **Canonical encoding that cannot collide**: every variable-length field length-prefixed, every optional field with a presence byte, domain-separated leaf and node hashes (§3–§4). Two different leaves never share one hash.
- **Write receipts** (§9.4): a signed "I accepted this hash at size N" that, with later witnessed checkpoints, proves censorship-by-omission, something a plain checkpoint cannot.
- **C2SP interoperability** (§9.3): checkpoints as `tlog-checkpoint` notes with `cosignature/v1`, verified against the specs' own published vectors. The witnesses already running for the Go checksum database and Sigstore could cosign a witness-log unchanged. The hardest problem in transparency is social; speaking the existing protocol inherits an installed base.
- **The verifier never touches the network, and the dossier never supplies trust inputs.** Those two missing arrows are the design.
- **Only the transparency layer.** Attestation, identity and authorization belong to other layers (RATS, WIMSE, OAuth/UCAN); witness-log logs *that* a delegation happened without becoming an authorization system, which is why it composes with whatever an integration already has.
- **A conformance corpus** (`corpus/`, 11 deterministic vectors) and `witness-log conform` so a second implementation proves byte-for-byte agreement instead of looking similar.

Read [Threat model](Threat-Model) before trusting any of this with something real: it states what is proven and what is not, and the biggest current gap is that independent witness operators are still being recruited. "Witnessed" is only ever as strong as the witnesses *you* chose.
