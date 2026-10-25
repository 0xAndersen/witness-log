# Threat model (summary)

The full document is [`THREAT_MODEL.md`](https://github.com/0xAndersen/witness-log/blob/main/THREAT_MODEL.md).
This is the short version an integrator needs.

## Protected against

| threat | mechanism |
|---|---|
| record edited after the fact (operator, insider, attacker with storage access, bug) | leaves rebuild the signed root or they don't: INVALID; re-signed after the edit, it contradicts a head you kept (`--known-head`): DIVERGED |
| record truncated or reordered | same |
| log shows different histories to different parties | witnesses demand a consistency proof and refuse forks (422); two cosigned heads for one size are self-contained evidence (`verify --evidence`); `diff` catches it offline; a WITNESSED dossier cosigned by less than a majority of your directory exits 11 |
| operator rewinds to an old backup and continues | `submit` refuses to publish a history that contradicts what witnesses cosigned |
| log accepts an event, then leaves it out of the history it gets witnessed | a signed write receipt plus the log's witnessed dossiers prove the omission (`log receipt`, `prove-silence`); see [Proving an omission](#proving-an-omission) |
| fabricated dossier with fabricated "witnesses" | the dossier's own directory is never scored; verdict capped at UNANCHORED |
| one operator running many witnesses under many names | independence is by `operator_org` in the *verifier's* directory; project-run witnesses collapse to one bucket |
| replayed / stale checkpoints | 400 at the witness, never evidence |
| hostile HTTP against a witness | bounded everything; see [Running a witness](Running-a-Witness) |
| session key leak | sessions are ephemeral and bound; revoke the identity if that leaks |
| PII in a committed payload | per-leaf salt erasure |

## Not protected against

- **A compromised agent host before signing.** Whatever signs the
  checkpoint can sign a lie. witness-log proves the record was not changed
  afterwards; it does not vouch for the moment of writing. Pair with host
  security; disclose key custody (`custody` field) so verifiers weigh it.
- **Content that is false but honestly logged.**
- **Collusion of every witness in a verifier's directory.** The verdict is
  only as strong as the directory; choose witnesses from organisations
  that would not collude.
- **Timing.** Leaf and checkpoint timestamps are self-asserted; use
  witness receipt times for anything time-sensitive.
- **Metadata leakage.** Leaf types, counts and timing are visible even
  after redaction.
- **A witness restored from backup without its memory** (key without
  `logs/`): it will contradict itself. Operational rule, not code.

## Proving an omission

Witnesses stop a log from rewriting what they cosigned. They cannot stop
it from never recording an event in the first place: a log that takes a
request, says "accepted", and leaves it out of every checkpoint it
submits has a perfectly consistent, perfectly witnessed history. The
write receipt closes that gap (SPEC §9.4).

- **Who issues it.** The log operator, when it accepts the event:
  `witness-log log receipt <journal> <index>` (Python:
  `JournaledLog.write_receipt_json(index)`). The receipt is signed by the
  log's identity key and binds that key to the event's `payload_hash` at
  tree size `<index>`: the event is due in every later checkpoint. The
  operator hands it to the party that submitted the event, then and there.
- **Who checks it.** That party, later, or anyone they hand the bundle
  to: `witness-log prove-silence receipt.json --dossier ... --directory
  <trusted.json> --identity <the log's key>` (Python:
  `witness_log.prove_silence`), against the log's dossiers published since.
  It needs the directory *the checker* trusts and the log's key obtained
  out of band, as `verify` does.
- **What CENSORED (exit 30) proves.** The log's key signed a promise to
  include this exact event, at least `--min-checkpoints` (default 2) later
  checkpoints of that key were each cosigned by two or more independent
  operators from the checker's directory, the leaves supplied reproduce
  the root of every one of them (so they are the log's leaves, not a copy
  someone edited), and the event is not among them. Each piece is signed
  by the log or a witness, so anyone given the same files reaches the
  same result. PRESENT (exit 0) is the converse: the event is in leaves
  that reproduce a checkpoint after it that two independent operators
  cosigned.
- **What it does not prove.** Why the event is missing: a deliberate
  omission, a lost disk, a journal restored from a backup taken before the
  event was appended all look the same, and all are the log's
  responsibility, since it signed the receipt. It says nothing about
  checkpoints the checker was not given: the event may appear later, in a
  history no witness in the directory has cosigned yet. It is only as
  strong as the directory (witnesses that collude with the log can cosign
  anything), and without `--identity` it is about whatever key signed the
  receipt, which anyone can generate. Two witnessed roots for one size are
  equivocation, a different finding (`diff`, `verify --evidence`), and are
  reported as INCONCLUSIVE here. Anything less than the full bundle is
  INCONCLUSIVE (exit 20), never an accusation; a receipt that does not
  verify is a bad input (exit 2), not evidence against anyone.

## Reporting

Security issues: see `SECURITY.md` (private reporting). A gap between
this model and the code is the highest-priority bug the project has.
