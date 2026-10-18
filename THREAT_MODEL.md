# Threat Model

This document exists because a cryptographic audit trail is only as
trustworthy as the honesty of its own claims. Every guarantee below is
stated with its actual scope. If something isn't listed as detected or
prevented, assume it isn't.

## Two separable questions: attestation vs. transparency

Every guarantee in this document reduces to one of two distinct
questions, and it's worth naming them explicitly (using the same
vocabulary as the IETF's draft-kuehlewind-audit-architecture, so this
maps cleanly onto that effort and others building on the same split):

- **Attestation** — *is this record authentic?* Answered by a signature
  check: did the claimed identity key really sign this leaf/checkpoint?
  This is what `SignedTreeHead::verify` and `KeyBindingStatement::verify`
  do. It says nothing about whether the record is complete, or whether
  it's the same record shown to everyone else.
- **Transparency** — *did this record exist as claimed, unaltered, at the
  claimed position, and is it the same record everyone else sees?*
  Answered by Merkle continuity plus (when present) witness quorum. This
  is the harder property, and the one this whole project is really about
  — see "Witness independence" below.

A dossier can be strong on attestation and weak on transparency (validly
signed, but unwitnessed) or, in principle, the reverse. The two are never
collapsed into one number in this project's tooling — see `witness-log verify`'s
output — precisely so a strong result on one can't be mistaken for a
strong result on both.

## Actors and what WitnessLog does and doesn't protect against

| Actor / scenario | Capability | WitnessLog's guarantee |
|---|---|---|
| **Operator, post-hoc tampering** | Rewrites or deletes leaves already committed to a *local* log file, after the fact. | **Detected**, if a checkpoint (STH) was signed before the tampering and a verifier compares recomputed root against that STH. Detection requires the verifier to have obtained the STH from somewhere the operator couldn't also rewrite (ideally, a witness — see below). A dossier edited under its old checkpoint is INVALID (exit 40); one re-signed by the same key after the rewrite is internally valid and is DIVERGED (exit 30) only when the verifier supplies the earlier head (`verify --known-head <size>:<root>`) or a witness's equivocation proof (`--evidence`). |
| **Operator, equivocation** | Shows verifier A one version of history and verifier B a different one, both internally consistent. | **Detected only if witness diversity is real.** A witnessed checkpoint that a genuinely independent third party has countersigned and published is very hard to quietly replace across all verifiers. A single-node log with no independent witnesses, or witnesses that are not actually independent of the operator, provides **no protection** against this. This is the single most important caveat in this document — see "Witness independence" below. |
| **Compromised host, pre-signature** | Attacker gains code execution on the machine before a leaf is signed/committed. | **Not prevented.** WitnessLog proves what was recorded and that it wasn't altered *after* recording. It cannot prove the recorded content reflects what the agent actually reasoned or that the logging call happened at the time claimed, if the host itself was already compromised. |
| **Malicious or hallucinating agent** | Logs a false `0x01 ActiveIntent` (e.g. claims it intended X when it didn't) or a false `0x02 ActiveResult`. | **Not prevented.** WitnessLog proves authorship (which session/identity signed it) and ordering (its position in the tree), not truthfulness of the content. |
| **Log truncation / selective omission** | Operator drops leaves from what's shown to a specific verifier, without altering the ones shown. | **Detected only via consistency proofs against a witnessed STH.** A dossier that isn't checked against an independently-witnessed checkpoint cannot distinguish "complete history" from "history with inconvenient leaves quietly missing." |
| **Traffic analysis** | An observer who cannot read payloads still sees leaf types, timestamps, and tree positions. | **Not protected against.** Redaction (§8, SPEC.md) hides payload content, not the existence, timing, or type of an event. |
| **Low-entropy payload correlation** | Adversary has a small dictionary of likely payloads (e.g. common email formats) and tries to match them against a `payload_hash`. | **Partially hardened** via bucket-padding and folding `leaf_index` into the hash (see SPEC.md §8), which prevents length-correlation and cross-leaf reuse of a dictionary attack. **This has not had an external cryptographic review.** Treat the unlinkability property as unproven until one is completed — do not make compliance claims resting on it without independent audit. |
| **Key compromise, identity key** | Attacker obtains an agent's persistent identity private key. By default the seed lives in the journal header (mode 0600); `JournaledLog::create_sealed` / Python `open(..., seal=True)` keeps it out of the file entirely, so the journal holds only the public key and the seed stays in a KMS, secrets manager or environment. | Detected/contained only if a `RevocationStatement` (SPEC.md §5) is issued and propagated before the attacker uses it further. Leaves signed before compromise remain valid; leaves and checkpoints at or after revocation `as_of_ms` are rejected by verifiers who see the revocation, and a verifier can supply revocations it knows about (`verify --revocations`) so a dossier that omits one is judged the same way. The cut-off is on timestamps the key holder sets, so against a holder who backdates, what is reliable is a witnessed checkpoint from before the revocation (RFC-0005 proposes an index cut-off witnesses pin). Leaves signed *between* actual compromise and revocation being issued/observed are **not** distinguishable from legitimate ones. |
| **Post-quantum cryptanalysis** | A future adversary with a cryptographically-relevant quantum computer breaks Ed25519. | **Not currently mitigated**, but the wire format's `sig_alg` field (SPEC.md §6) is designed so a PQ-safe signature scheme can be introduced without invalidating the format or breaking historical checkpoints signed under Ed25519. Migration itself is not yet designed. |
| **Silent handoff tampering** | A transport or intermediary between two agents alters context/state in transit during a handoff. | **Detected**, if and only if both agents independently log a HandoffAttestation (SPEC.md §3.1) and someone later runs `verify_handoff_binding`. A mismatch in `handoff_state_hash` is directly visible. **Not detected** if only one side logs, if the tampering happens before either side computes its hash (e.g. a compromised sender that never saw the real content to begin with), or if the comparison is simply never run. |
| **Misattributed or falsely-widened authorization claims** | A grantee later claims a broader scope than was actually granted, or a delegation is misattributed to the wrong party. | **Detected**, if and only if both the granter and grantee independently log an AuthorizationEvent (SPEC.md §3.2) and someone runs `verify_authorization_binding` — a scope-hash or counterparty mismatch fails the check. **Not detected or enforced in any other sense**: WitnessLog never evaluates whether a claimed scope is reasonable, never checks it against a real authorization system's state, and provides no protection at all if only one side logs the event. |
| **Backdated or forward-dated checkpoint** | Operator sets `checkpoint.timestamp_ms` to any value — it's self-signed by the party being verified, not independently attested. | **Not prevented by the checkpoint field alone.** `WitnessPolicy::evaluate`'s staleness check prefers `newest_trusted_witness_ms` — the newest timestamp from a receipt scored against the caller's trusted directory — over `checkpoint.timestamp_ms` whenever a witness-corroborated value exists, since a dishonest operator cannot backdate a timestamp an independent third party countersigned. **No protection at all** when no trusted directory or witness receipts are supplied (the `Unanchored` case) — the fallback is the self-asserted checkpoint timestamp, and the resulting policy error message says so explicitly. |

## Witness independence — the load-bearing assumption

Equivocation-resistance, log-completeness, and tamper-detection-against-the-operator
all reduce to one question: **are the witnesses actually independent of the
thing they're witnessing?**

A "2-of-3 signatures verified" result is not evidence of anything if all
three keys are held by the same operator. This is why `witness-log-network`'s
`evaluate_quorum` always returns an operator-diversity score alongside the
raw count, and why `witness-log verify` prints both — a caller who only checks
`meets_count_threshold` and ignores diversity is making the exact mistake
this project exists to prevent people from making silently.

**Current state of the witness network is thin.** At the time of writing,
witness recruitment is an open, ongoing effort (see GOVERNANCE.md). A
dossier witnessed by few or non-independent operators should be treated as
having tamper-evidence (detects post-checkpoint local tampering) but weak
or no equivocation-resistance (does not reliably detect the operator
showing different histories to different parties).

**Agent-operated witnesses are supported and are not a lesser form of
witnessing** — see SPEC.md §7.1. An autonomous agent can witness
continuously and cheaply, which is a genuine advantage over relying solely
on humans running periodic manual checks. But an agent witness introduces
its own independence question: a set of agent witnesses run by the same
operator, or all built on the same underlying model/inference provider,
fail identically for the same reasons three same-operator human witnesses
do — correlated compromise, correlated outage, correlated blind spots
(e.g. a shared vulnerability to a particular manipulation of witnessed
content, if a witness implementation ever does more than the narrow
cryptographic check it should). This is why `WitnessEntry` and
`evaluate_quorum` track **two separate diversity axes** — operator and
compute-provider — rather than one, and why a caller should look at both,
not just whichever one happens to look better.

**A log's own operator is not independent of it, and only the verifier
can say who that is.** An organisation that runs an agent and also runs
a witness listed in the verifier's directory can cosign its own agent's
log. Its receipt is valid; it says nothing a second party saw. The
verifier excludes such a witness from the independent-operator count
when it can tell: when the directory lists the log's own key (the same
operator), or when the caller names the log's operator with
`--subject-org` (`subject_org`, `subjectOrg`, `SubjectOrg` in the
libraries). Nothing in a dossier can say who operates its log in a way
the verifier should believe, so without `--subject-org` an organisation's
own witness counts as independent of its own agent, and two
organisations each running an agent and a witness reach WITNESSED for
each other's logs with one genuinely independent cosigner each. Pass
`--subject-org`; the CLI prints a reminder when it is absent. A
three-organisation pilot is the smallest set in which every log is
cosigned by two operators other than its own
(`examples/pilot-triangle/run.py`). Found while designing that pilot,
before any outside operator was registered; fixed in 0.6.0.

**Split views: what a gate below a majority cannot catch.** A witness
refuses a second history only for a log it has already seen. A log that
sends history A to one subset of the directory and history B to a
disjoint subset never meets a witness that has seen both, so each history
collects honest cosignatures and, if the gate is satisfied by either
subset alone, each dossier reaches WITNESSED. The condition that rules
this out among honest witnesses is a strict majority: when counted
receipts exceed half the directory, any two gate-satisfying sets overlap
in at least one witness, and that witness refused the second history.
The default `--threshold 0.66` is a majority; `--threshold 0.5`, or
`--min-witnesses N` with `N <= directory/2`, is not. The verifier reports
`split_view_resistant` and `split_view_unsafe` for the dossier in hand and
warns when the gate itself permits a split; since 0.5.0 `witness-log
verify` exits 11 (not 0) for a WITNESSED dossier whose cosigners are not a
strict majority of the directory, unless the caller passes
`--allow-sub-majority` (RFC-0002). It cannot see the other dossier. Two
copies in hand are compared with `witness-log diff`, and a split view is
still equivocation under one key: the two dossiers together are the
evidence (`diff` exits 30), and a head from one passed to `verify` of the
other with `--known-head` does the same with one copy.
(Found by an outside evaluation of 0.3.3; the live test
`split_view_below_a_majority_is_reported_not_hidden` reproduces it.)

The specific mechanism that makes an agent witness meaningful rather than
theatrical is the **consistency-proof check it must run before signing
anything** (SPEC.md §7.1): without it, an agent witness has no algorithmic
way to refuse a checkpoint that quietly doesn't extend the last one it
saw. `WitnessService::handle_add_checkpoint` (the witness every
`witness-log witness serve` and Python `WitnessService` runs) performs this
check before every cosignature and refuses with 422 when it fails; the
`tlog_witness_protocol` tests cover the refusal case.

## Running a witness: what the server defends against

`witness-log witness serve` is internet-facing by design. What it
guarantees, and what it doesn't:

- **It never cosigns a fork.** Every advance is checked with a
  consistency proof (RFC 9162 §2.1.4.2, both roots rebuilt) against the
  last head it cosigned for that origin; failures get 422.
- **It only accuses when it can prove it.** A failed proof alone is not
  evidence — anyone can relay an honest log's public checkpoint with a
  junk proof attached, and recording that would let anyone smear any log
  (and fill the evidence store so real evidence is lost). Only provable
  equivocation is recorded: the log signed two different roots for the
  same size. The witness keeps the last log-signed checkpoint it cosigned
  precisely so it can hold both signatures; `evidence/` gets one
  self-contained `EquivocationProof` file per log (first proof wins, so
  storage is bounded by the log cap and no log can crowd out another;
  checkpoint bodies over 1 KiB are refused, so proofs stay small) that anyone can check with
  the log's key alone. An *older* genuine checkpoint arriving late gets
  400 and is never treated as evidence. A *growing* fork is refused but is
  not provable by one witness; it is caught when someone compares two
  dossiers (`witness-log diff`) or two witnesses' records.
- **Honest agents can still equivocate by accident** — e.g. a journal
  restored from an old backup and appended to re-signs a witnessed size
  with a different root. By the protocol that *is* equivocation, and it
  is recorded permanently. `witness submit` guards against it: it
  remembers the largest head witnesses cosigned and refuses to publish
  any history that does not extend it. Agents using the library directly
  must keep that invariant themselves: never re-sign a size you have had
  cosigned unless the root is identical.
- **It never forgets what it cosigned.** The new record is written,
  fsynced and atomically renamed into place (then the directory fsynced)
  *before* the cosignature is released; if that fails, no cosignature
  leaves the process and the file on disk stays the authority (the
  decision ran on a copy; the in-memory cache changes only after the
  write succeeds). A lock file stops
  two processes serving one state directory, and the server re-checks it
  holds the lock before every cosignature (exiting if another process
  took over). Stale locks from crashed processes are detected on Unix; on
  Windows the operator removes them. Startup refuses a missing `logs/` or any
  file there that is not a record, rather than silently starting from
  empty. Since 0.6.0 records are read on demand, not all at startup (a
  witness with 100,000 logs starts in about half a second and 3 MiB), so a
  record that cannot be read fails its own log closed, HTTP 500 when that
  log next submits, and is never treated as a new log; other logs keep
  being served. Deleting a damaged record to clear the error would turn it
  into exactly that new log: restore it from backup instead. Re-adding a known log never resets it.
  **The one thing no code can catch is a key restored without its
  memory**: `witness.key` with an empty `logs/` is a witness that will
  cosign whatever size-N root it is shown next, contradicting what the
  same key cosigned before. `witness.json` records the key it was
  initialised with and `serve` refuses a mismatch, but an empty `logs/`
  is indistinguishable from a new witness. Back up `witness.key`,
  `witness.json` and `logs/` as one unit, always (see
  `deploy/witness/OPERATORS.md`). The same holds for a consistent but
  *stale* snapshot: a witness restored to a point before its last
  cosignature has forgotten those heads and could cosign a fork between
  the remembered size and the forgotten one. Restore only a snapshot
  newer than the last cosignature; otherwise retire the key.
- **Open enrollment cannot be abused to impersonate.** Only canonical
  origins (`witness-log/<identity key>`) are enrolled, and only when the
  checkpoint verifies under the key the origin names.
- **Bounded resource use.** Request head 8 KiB, body 64 KiB, at most 63
  proof lines, 10 s to deliver a request, at most 256 concurrent
  connections and 16 per client address, 600 new enrollments per address
  (an IPv6 client is keyed by its /64) per minute, 100,000 logs total,
  64 MiB of evidence. With open enrollment, an attacker with many
  addresses and free key pairs can still fill `--max-logs`; new logs then
  get 503 (never a wrong cosignature). Witnesses that expect that should
  enroll explicitly (`witness add-log`) instead. Chunked
  request bodies are refused (request-smuggling surface). Excess load gets
  503/429 with `Retry-After`. All limits are flags.

What it does **not** defend against: a compromised witness host (the key
is a plaintext file, mode 0600 — use full-disk encryption, or front the
witness with an HSM-backed signer if your threat model needs it); a
network-level DDoS (put it behind your usual edge); and an operator who
runs many witnesses under different names — that is the Sybil problem,
answered by the verifier's own trusted directory and diversity scoring,
not by any one witness. The protocol's integrity rests on signatures, not
TLS, so an on-path attacker can only delay or drop; use a TLS-terminating
proxy for privacy. The built-in client speaks `http://` and, since 0.6.0,
`https://` (rustls, Mozilla roots compiled in, or exactly the CAs in
`WITNESS_LOG_CA_FILE`); before that it refused `https://`, so the CLI
could not submit to witnesses registered in the public registry, which
requires `https://` URLs.
Throughput is bounded by one fsync per cosignature (decisions are
serialized so the size check and the persist are atomic): hundreds per
second on ordinary disks, which is far above what witnessing needs.

## Local servers: `journal serve` and `fleet serve`

Both bind loopback by default and have no authentication: anything that
can open a TCP connection to the port can append to the journal (or
submit to the fleet log). On a multi-user host that is every local user;
run them on a single-user machine, or behind your own authenticating
proxy with `--allow-remote`.

A web page the operator visits can also reach loopback, by a cross-site
`fetch` (CSRF) or by pointing its own hostname at 127.0.0.1 (DNS
rebinding). Since 0.6.1 both servers refuse, with 403, any request that
carries an `Origin` header or whose `Host` is not `localhost` or a
loopback address on the server's own port. Browsers always send `Host`
and send `Origin` on cross-site requests; local programs (curl, the
Python and Node clients) send neither or a loopback `Host`, so they are
unaffected. With `--allow-remote` the check is off, because the operator
has chosen to expose the server and its own proxy decides who may reach it.

## Accusations are held to a higher bar than verdicts

Several outputs of this project are accusations — "this log equivocated",
"this log censored an event", "this log rolled back". A false accusation
is worse than a missed one, because it will be acted on. Every such
output therefore requires that everything it rests on is signed by the
accused log and self-consistent: `diff` and `compare_checkpoints` verify
both checkpoints' signatures and that each copy's leaves reproduce its own
root before calling a difference equivocation; a witness records
equivocation only when it holds two log-signed roots for one size; a
silence proof requires a log-signed `WriteReceipt` naming the exact event,
checkpoints cosigned by two independent operators, and leaves that
reproduce those checkpoints' roots (since 0.6.1; before, an accuser could
drop the event from the leaf list it supplied — review III, H1).
Anything less — an unverified checkpoint, an edited copy, a junk proof, a
plain checkpoint standing in for a receipt — is reported as a bad input,
not as misbehaviour. The final pre-publish review found three paths that
did not meet this bar; all are closed in 0.3.1. Since 0.5.0 the verdicts
keep the same line: a file that fails a check is INVALID (exit 40), and
DIVERGED (exit 30) is reserved for a dossier that passes every check and
contradicts a head the verifier supplied or an equivocation proof that
verifies under the verifier key built from the identity's canonical
origin: its name is the origin, its key is the identity, and its key ID
is computed from the two. Nothing is taken from the proof file's own
`log_vkey`, which must equal that key field for field (key ID included)
or the proof does not count; through 0.5.0 the reference read the key ID
from the file, so signature lines carrying an ID the file chose counted
as the log's.

## What "verified" means when you run `witness-log verify`

The CLI is deliberately worded to avoid a bare pass/fail collapsing these
distinctions. A successful run tells you, precisely:

1. The checkpoint's signature is valid, and was made by the claimed
   identity key.
2. The leaves in the dossier, hashed and assembled, produce exactly the
   root the checkpoint attests to — i.e., **nothing in this dossier's
   leaf set has been altered, reordered, or removed since this checkpoint
   was signed.**
3. (If witness receipts are present) how many witnesses signed, and how
   diverse those witnesses are — explicitly, not folded into a single
   score that could be mistaken for "verified against equivocation."

It does **not** tell you that the events described actually happened as
described, that the log is complete, or that history hasn't been shown
differently to someone else — unless the witness diversity is genuinely
strong.

Two inputs you control decide how much a run can conclude. `--directory`
(a witness directory you trust) is what lifts the ceiling above
UNANCHORED: receipts are scored only against it. `--identity` (the key you
expected, from somewhere the dossier's author does not control) ties the
verdict to a party: without it, WITNESSED means independent operators
cosigned *a* log, not *whose*, and the CLI says so. A gate passes both.
Timestamps in leaves and checkpoints are self-asserted; a verifier that
cares about time uses the witnesses' `witnessed_at_ms` (`WitnessPolicy`
does), and a leaf whose timestamp was edited after signing fails
structural validation and reads as INVALID like any other alteration.

## Reporting an issue with this model

If you find a gap between what this document claims and what the code
actually does, that's a higher-priority issue than almost anything else in
this repository. If the gap is a security vulnerability — something an
adversary could exploit, not just a documentation inaccuracy — follow
SECURITY.md's private disclosure process rather than opening a public
issue. For anything else (a claim that's simply wrong or unclear, with no
exploitability), a public issue is the right venue.
