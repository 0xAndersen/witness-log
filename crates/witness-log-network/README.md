# witness-log-network

Witness protocol and dossier verification: peer countersigning of
checkpoints, quorum evaluation, operator/compute-provider diversity
scoring, the four-valued verdict system, `WitnessPolicy` (machine-readable
pre-action gating), and `silence_proof` (censorship-by-omission detection).

This crate builds on `witness-log-core`'s Merkle log and identity
primitives; it does not itself persist anything. See `spec/SPEC.md`
(sections 4, 7, and 9) for the normative wire format this crate
implements, and `THREAT_MODEL.md` for what each verdict does and doesn't
prove.

## The witness directory format

A `WitnessDirectory` is a JSON file (or, embedded, a field on a
`Dossier`) listing candidate witnesses:

```json
{
  "witnesses": [
    {
      "name": "example-university-security-lab",
      "operator_org": "example-university",
      "url": "https://witness.example-university.edu",
      "pubkey": "<hex-encoded Ed25519 public key>",
      "runtime": "human",
      "compute_provider": null,
      "is_project_operated": false
    }
  ]
}
```

Fields:

- **`name`** — a display label, not used in any trust decision.
- **`operator_org`** — the organization actually running this witness.
  This is what operator-diversity scoring groups by.
- **`url`** — where this witness can be reached (informational; this
  crate doesn't fetch anything over the network itself).
- **`pubkey`** — hex-encoded Ed25519 public key. This is the field
  receipts are matched against — see `evaluate_quorum`.
- **`runtime`** — `"human"` or `"agent"`. Informational.
- **`compute_provider`** — optional. Omitting this is scored as its own
  low-diversity bucket, never as neutral or excluded — see
  `compute_provider_key`'s doc comment for why non-disclosure must never
  score better than honest disclosure of a shared provider.
- **`is_project_operated`** — **must be set honestly.** Every entry with
  this set `true` collapses into a single bucket on BOTH diversity axes
  regardless of how differently their other fields are labeled — this is
  what stops ten witnesses run by the same project from being dressed up
  as ten independent operators. See `PROJECT_OPERATED_BUCKET`'s doc
  comment and `GOVERNANCE.md`.

## Running a witness

A witness speaks `c2sp.org/tlog-witness`: a log POSTs its signed
checkpoint plus a consistency proof from the size the witness last saw;
the witness checks the proof, persists the new head, and only then returns
a `c2sp.org/tlog-cosignature` v1 cosignature. `tlog_witness::WitnessService`
is that state machine with no I/O of its own; three servers wrap it:

- `witness-log witness serve <dir>` (the CLI, `crates/witness-log-cli`):
  one file per log under `logs/`, fsync before cosigning, lock file,
  request limits, equivocation evidence under `evidence/`. `deploy/witness/`
  has the Dockerfile, systemd unit and `OPERATORS.md`.
- `witness_log.WitnessService` (Python): mount in any web framework.
- `examples/live-network/` runs ten of them against hostile traffic.

With `--open-enrollment` a witness accepts any log whose origin is the
canonical `witness-log/<identity key hex>`: the origin *is* the key, so
there is nothing to exchange out-of-band. Cosignatures become
`WitnessReceipt`s in a dossier (`tlog_witness::cosignature_to_receipt`),
carrying `c2sp_origin`; only receipts under the canonical origin count.

## Registration

There is no central registry. A directory file is something a verifier
assembles or receives out-of-band; GOVERNANCE.md describes who should
curate one and why it is not this project. To offer a witness: run
`witness-log witness init` with your real `--org`, publish the directory
entry it prints (and the vkey) somewhere the log operators you serve do
not control, and keep it reachable. Verifiers who add your entry to their
directory are the only thing that makes your cosignatures count.

## Trust boundary

`Dossier::verify` never trusts `dossier.witness_directory` or
`dossier.identity_pubkey` for anything above the `Unanchored` verdict —
both are attacker-controlled fields on the artifact under test. Pass a
`VerifyContext` with `trusted_directory` (obtained out-of-band) and
`expected_identity_pubkey` (likewise) to reach `Witnessed`. See
`VerifyContext`'s doc comment for the full rationale.
