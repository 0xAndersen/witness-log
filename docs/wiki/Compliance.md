# Compliance: what witness-log gives an auditor

This page maps the mechanism to the questions compliance teams ask. It
is engineering guidance, not legal advice; confirm requirements with
counsel for your jurisdiction.

## GDPR / CCPA: right to erasure without destroying the audit trail

Payloads are committed as `SHA256(bucket_pad(payload) || salt || index)`
with a random per-leaf salt kept outside the tree (`<journal>.salts`).
`forget(index)` erases the salt and appends a 0x03 Redaction marker naming
the index. Afterwards the committed hash cannot be recomputed from the
original data (the salt is 256 bits of entropy), while every other leaf,
proof and signature is unchanged; a verifier sees "entry 17 was erased on
date D" and nothing else. Bucket padding hides payload length; folding the
index in defeats cross-leaf dictionary attacks.

What to document in your records of processing: the salt file is personal-
data-adjacent key material (0600, back up with the journal, encrypted
storage if block-level remnants matter), and erasure is complete when the
rewritten salt file no longer contains the index.

## SOC 2 / ISO 27001: integrity and non-repudiation evidence

- **Integrity (CC7, A.12.4):** `witness-log verify` on an exported dossier
  shows that no leaf was altered, reordered or removed since the signed
  checkpoint. Exit code 40 (INVALID) is the control failing; 30 (DIVERGED)
  means the dossier is valid but contradicts a head you kept
  (`--known-head`) or a witness's equivocation proof (`--evidence`). Before
  0.5.0 both were 30.
- **Non-repudiation:** checkpoints are signed by the agent's identity key;
  independent witnesses cosign; the dossier verifies offline by the
  auditor with software from a public repository, not from you.
- **Retention evidence:** `evidence_window(range)` exports exactly the
  period requested with an inclusion proof per leaf, without disclosing
  the rest of the log.
- **Change management for agents:** key bindings record every session
  (restart) and `AuthorizationEvent` leaves record delegations between
  agents, cross-checkable in both logs.

Suggested control text: "Autonomous-agent actions are recorded in a
Merkle-tree audit log signed by a per-agent key and countersigned by at
least two independent witnesses; integrity is verified offline with
`witness-log verify` and the verdict is retained with the evidence."

## EU AI Act (high-risk systems: record-keeping, Art. 12) and similar regimes

The Act asks for automatic logging over the system's lifetime that enables
traceability and post-market monitoring. A witnessed journal provides a
tamper-evident, time-anchored, exportable record per agent; witness
receipts give timestamps from parties other than the provider. Map your
retention period to journal retention and keep dossiers per reporting period.

## Financial services and payments

Where an agent initiates transfers, the intent leaf (what it was about to
do, with arguments) and the result leaf (what happened) are separately
committed, so "the agent requested $250 and the system returned success"
is reconstructible and the $25,000 edit in storage is detectable
(`examples/verify_demo.py` shows exactly that). `HandoffAttestation`
leaves bind state passed between agents so a chain of custody across
services can be checked without a shared database.

## Incident response

- Suspected tampering: `witness-log verify --json` on every retained
  dossier; INVALID names the failing check (`report.failures`). Pass the
  heads you retained earlier with `--known-head <size>:<root>`: a history
  rewritten and re-signed with the same key is DIVERGED
  (`report.contradictions`).
- Suspected equivocation (two histories shown to two parties):
  `witness-log diff a.json b.json` (30 equivocation, 40 a copy was
  edited); witnesses also record provable equivocation under `evidence/`,
  checkable with `witness verify-evidence` and usable as `verify
  --evidence`.
- Key compromise: issue a `RevocationStatement` (SPEC §5); leaves after
  `as_of_ms` are treated as untrusted by every verifier.

## What it does not do

It does not prove an event *happened in the world*, only that the agent
committed to it when it said it did and nobody changed the record since.
It does not replace access control, secrets management or host security:
a compromised host can sign anything. See [Threat model](Threat-Model).
