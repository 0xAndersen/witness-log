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

## Reporting

Security issues: see `SECURITY.md` (private reporting). A gap between
this model and the code is the highest-priority bug the project has.
