# RFC-0001: Fleet checkpoint log (one C2SP log per organisation)

Status: Draft — experimental prototype in 0.6.0 (`witness-log fleet`, `verify --accept-fleet-anchor`); not part of the spec until the open questions are answered
Target: spec text in a later minor, once the open questions below are answered
Related: SPEC §9.3 (C2SP), §9 (dossier), THREAT_MODEL "Witness independence"; prototype: `docs/wiki/Fleet-Log.md`, `corpus/14_fleet_anchor.json`

## Motivation

A witness-log identity is one C2SP origin (`witness-log/<identity hex>`).
Existing transparency-log witnesses are configured one origin at a time:
the shared configuration service at <https://witness-network.org> admits
each log after a maintainer reviews an application naming the origin, an
Ed25519 vkey, the expected checkpoint rate and a contact (state checked
2026-10-12: `testing` and `staging` lists exist, `production` is "not
available yet"). An organisation running a thousand agents would be a
thousand applications, each for a log that may live for an afternoon.
Nobody will admit that, and nobody should.

The only witnesses that cosign witness-log checkpoints today are
`witness-log witness serve` instances with open enrollment, which means
the operators the project has to recruit itself. The transparency-log
community already runs witnesses with years of uptime; the shape of the
problem is that we are asking them to enroll the wrong unit.

This RFC proposes the unit they can enroll: **one append-only log per
organisation whose entries are the signed checkpoints of that
organisation's agent logs.** It speaks `c2sp.org/tlog-checkpoint` and
`c2sp.org/tlog-tiles`, so any existing witness can cosign it and any
Tessera-style tooling can read it, and it is one origin with a stable
operator and a predictable checkpoint rate, which is exactly what an
admission form asks for.

## Design

### The fleet log

An organisation runs `witness-log fleet serve <dir>` (proposed). It is a
tiled transparency log (`c2sp.org/tlog-tiles`) with:

- origin `<org-domain>/witness-log/fleet` (the organisation's own DNS
  name; one organisation MAY run several, e.g. per region);
- its own Ed25519 log key, published as a C2SP vkey;
- entries that are **agent checkpoints**: the exact bytes of a
  `c2sp.org/tlog-checkpoint` signed note for one agent log (origin
  `witness-log/<identity hex>`, size, root, the agent identity's note
  signature). Nothing else is accepted; an entry that is not a well-formed
  note signed by the key its origin names is refused at submission.

Agents submit their checkpoint note to the fleet log instead of (or as
well as) to witnesses directly. The fleet log appends it, issues its own
checkpoint, and the fleet log's checkpoint is what gets witnessed, by any
`c2sp.org/tlog-witness` witness, through the normal `add-checkpoint` call
with a consistency proof. The fleet log checkpoints at a rate its
operator chooses (every N seconds or every M entries), which is the
number the admission form wants.

### What the dossier carries

The dossier gains one **optional** field:

```json
"fleet_anchor": {
  "origin": "example.com/witness-log/fleet",
  "entry_index": 48213,
  "entry_bytes_b64": "<the agent checkpoint note exactly as appended>",
  "inclusion_proof": ["<hex>", "..."],
  "fleet_checkpoint_note": "<the fleet log's signed note, with cosignature lines>"
}
```

`entry_bytes_b64` MUST parse as a checkpoint note for the dossier's own
identity with the same `tree_size` and `root_hash` as `checkpoint`.
`inclusion_proof` is an RFC 6962 inclusion proof of
`SHA256(0x00 || entry_bytes)` at `entry_index` under the root in
`fleet_checkpoint_note`. The cosignature lines on
`fleet_checkpoint_note` are ordinary `cosignature/v1` lines by witnesses
in the verifier's directory.

### How a verifier scores it

The verifier, when the caller opts in (`VerifyContext.fleet_anchors:
Accept`), does, in order:

1. verify the dossier exactly as today (§9.1–§9.2): nothing here relaxes
   a check;
2. check `entry_bytes` is a note for this identity over this checkpoint's
   size and root, signed by this identity (the note signature is a second
   signature by the identity key over the C2SP body, already defined in
   §9.3);
3. verify the inclusion proof against the fleet checkpoint's root;
4. verify each cosignature line on the fleet checkpoint under a key in the
   trusted directory, with the fleet origin, in the way §9.3 already
   verifies cosignatures;
5. count the operators of the cosigners that verified, with the **same**
   dedup-by-key and distinct-`operator_org` rules as direct receipts, and
   with one extra rule: a cosigner whose `operator_org` equals the fleet
   log operator's organisation counts as the subject's own operator
   (none).

The verdict rules are unchanged: WITNESSED still needs two distinct
independent operators in the verifier's directory; they may now have
cosigned the fleet checkpoint rather than the agent's directly.

### What this proves, and what it proves less well

A direct witness **refuses** a fork at submission time: it holds the last
head for this agent and returns 422 with evidence. A fleet log does not
look inside its entries beyond checking the signature; two checkpoints of
one agent at the same size with different roots are both valid entries
and would both be appended. The fleet log therefore turns equivocation
from something *prevented* into something *recorded and findable*: the
fleet log is append-only and cosigned, so both checkpoints are permanently
in it and anyone scanning the tiles for that origin finds the pair, which
is the same evidence object a direct witness would have produced (two
log-signed roots, one size). The report MUST say which kind of evidence
it has: `witnessed_via: direct | fleet | both`.

Two mitigations the fleet log SHOULD implement, and the RFC asks whether
they should be MUST:

- the fleet log refuses an entry for an origin whose previous entry it
  holds at a size `>=` the new one with a different root (it keeps the
  same per-origin memory a witness keeps), returning 422 and writing the
  same `EquivocationProof`;
- the fleet log publishes a per-origin index (latest entry per agent
  origin) so an auditor need not scan every tile.

With the first in place the fleet log behaves, for its own organisation's
agents, exactly like a witness run by that organisation: one more
operator-controlled check, with the independent cosigners on top.

### Who runs what

| party | runs | needs admission to |
|---|---|---|
| organisation | `fleet serve`, one origin | public witnesses, once |
| agent | `witness submit --fleet https://fleet.example.com` | nothing |
| public witness | unchanged software (`transparency-dev/witness`, Sigsum witnesses, `witness-log witness serve`) | configured with the fleet origin and vkey |
| verifier | unchanged binary with the opt-in | its own directory, as today |

## Wire changes

- Leaf encoding (§3), STH (§6), native receipts (§7), redaction (§8):
  **none**.
- C2SP mapping (§9.3): **none**; the agent checkpoint note and the
  cosignature format are the existing ones.
- Dossier (§9): one new **optional** field, `fleet_anchor`, absent by
  default; `spec/dossier.schema.json` gains it as optional. A dossier
  without it serialises byte-identically to today.
- New artefact: the fleet log itself, which is `c2sp.org/tlog-tiles`
  and defined elsewhere.

## Corpus vectors needed

The 0.6.0 prototype implements these as one verification vector,
`corpus/14_fleet_anchor.json` (`12` is the revocation vector): a four-entry
fleet log with its leaf hashes, root, the inclusion proof for entry 2 and
the fleet checkpoint note, and fourteen cases run by every verifier,
including the three negative cases below. It is not part of the
conformance set.

- `12_fleet_entry.json`: an agent checkpoint note as a fleet entry; its
  leaf hash; a 4-entry fleet tree with roots; an inclusion proof for
  entry 2; the fleet checkpoint note; one cosignature line; expected
  verification result.
- A negative vector: `entry_bytes` for the right identity but a different
  root than `checkpoint.root_hash` (MUST fail step 2).
- A negative vector: cosigner `operator_org` equal to the fleet operator
  (MUST count as zero independent operators).
- A dossier vector with both direct receipts and a fleet anchor, with the
  expected `distinct_independent_operators` after dedup across the two
  paths (a witness that cosigned both counts once).

## Backward compatibility

- Old verifiers ignore unknown dossier fields today (serde default
  behaviour on the `Dossier` struct must be confirmed: if it is
  `deny_unknown_fields`, the schema bump needs to precede the field), so
  a dossier with `fleet_anchor` verifies on 0.3.x as if the field were
  absent: the same or a lower verdict, never a higher one.
  *Confirmed for the prototype:* `Dossier` has never had
  `deny_unknown_fields` (the Go and TypeScript verifiers ignore unknown
  keys too); a test deserialises every anchored corpus dossier into the
  0.5.0 struct. `spec/dossier.schema.json`, which does set
  `additionalProperties: false`, gains `fleet_anchor` as an optional
  property in the same release.
- New verifiers without the opt-in behave as old ones.
- No existing artefact changes meaning.

## Decisions in the 0.6.0 prototype

These are the prototype's answers where the text above left a choice.
They are what the code and `corpus/14_fleet_anchor.json` do, not settled
specification.

1. **The opt-in** is `VerifyContext::accept_fleet_anchor: bool` (default
   false), and `--accept-fleet-anchor` in the CLI; every other verifier
   takes the same boolean. Without it the field is not read beyond its
   origin and index: verdict and report are what they are without the
   field, plus `report.fleet_anchor.status: "ignored"`. A malformed
   field still parses (it is kept as raw JSON), so it cannot make a
   dossier unreadable to a verifier that ignores it.
2. **A failed anchor is reported and ignored, never INVALID.** With the
   opt-in, an anchor that fails any of steps 2–4 sets
   `report.fleet_anchor.status: "failed"` with `failures`, and adds no
   cosigner. INVALID would gain nothing: anyone holding the dossier can
   strip the field and get the verdict without it, so a broken anchor can
   at most be made to disappear, and a rule that lowered the verdict for it
   would let a third party who corrupts the optional part of a file
   suppress valid direct evidence. It also matches how a direct receipt
   that does not verify is treated: not counted, never INVALID. An anchor
   can therefore only add independent operators, and only when it fully
   verifies. One case is reported in plain words: an entry validly signed
   by the identity for the same size with a different root means the
   identity signed two roots for one size. The prototype reports that as
   the step-2 failure and does not make the verdict DIVERGED, because
   RFC-0002 keeps DIVERGED for evidence the verifier brings, and the
   native checkpoint and the C2SP note are different signed formats with
   no existing evidence object for the pair.
3. **The fleet log's key is not a trust input.** The verifier does not
   check the fleet log's own signature on `fleet_checkpoint_note`, and no
   fleet vkey is supplied. A `cosignature/v1` line signs the exact
   checkpoint body (origin, size, root), and a conforming witness cosigns
   a body only after verifying it under the key it was configured with for
   that origin and only if it extends what it cosigned before; a vkey
   taken from the dossier would verify nothing, and a verifier-supplied
   one would identify the operator, which the verdict does not depend on.
   What a holder of the fleet key can do: sign any fleet head (witnesses
   still cosign only consistent ones); not forge an agent's entry (step 2
   checks the agent's own signature); append both of an agent's
   conflicting checkpoints, leave an agent out, or run several fleet
   origins and put conflicting checkpoints of one agent in different ones,
   each of which then needs its own enrollment with each witness. The last
   is the residual risk against direct witnessing, where one identity has
   one origin. A verifier-side list of accepted fleet origins per subject
   would narrow it; the prototype does not have one.
4. **The fleet operator's organisation is `subject_org`.** A fleet log is
   run by the organisation whose agents it records, so the caller's
   `subject_org` names it, and step 5's extra rule is the existing
   `subject_org` rule applied to fleet cosigners. Without `subject_org`
   the anchor is not used (`failed`, "no subject_org"), and the CLI
   refuses `--accept-fleet-anchor` without `--subject-org`: otherwise the
   organisation's own witnesses would count as independent of it.
5. **Fleet cosigners never count toward split-view resistance.**
   `split_view_resistant` is computed from keys with a direct receipt
   only. The majority argument behind it (any two passing sets overlap in
   a witness that refuses the second history) does not hold for a witness
   that committed to the fleet log's head: it would not refuse a
   conflicting checkpoint of the agent. A WITNESSED verdict reached through
   the fleet alone is therefore always `split_view_unsafe`, exit 11, and
   `--allow-sub-majority` accepts it.
6. **Dedup and `witnessed_via`.** Direct receipts and fleet cosigners are
   scored together, each witness key once (its direct receipt, when it has
   one, sets its time). `witnessed_via` is `null` unless the verdict is
   WITNESSED; then `"direct"` when no counted key is fleet-only, `"fleet"`
   when no counted key has a direct receipt, and `"both"` otherwise.
   `witness_paths` gives the witness keys and independent operators per
   path and the keys on both. Both fields appear only with the opt-in, so
   a report without it is unchanged.
7. **Entries.** A fleet entry is the agent's note with no extension lines
   and only its own signature, exactly as the fleet log stored it; the
   fleet origin must not start with `witness-log/` (that names one agent's
   log, whose cosignatures are direct receipts). Bounds: entry 4 KiB,
   checkpoint bodies 1 KiB (as a witness), fleet note 64 KiB and 64
   signature lines, inclusion proofs 64 hashes.
8. **Not implemented:** `c2sp.org/tlog-tiles` (entries are read with
   `GET /proof/<index>`), batching and retention, a per-subject list of
   accepted fleet origins, the vkey in DNS.

## Open questions

1. Should the fleet log's per-origin fork refusal be MUST? It makes the
   fleet log a witness for its own agents, which is good, and makes it
   stateful per agent, which is what we wanted to avoid for the public
   witnesses but is fine for the organisation's own service.
   *Prototype: MUST.* `fleet serve` keeps the last checkpoint it appended
   per agent origin and runs the `tlog-witness` state machine against it
   (`KnownLog`, the code `witness serve` runs): `POST /add-entry` takes an
   add-checkpoint body (old size, consistency proof, note), answers 409
   with the held size, and refuses a checkpoint that does not extend the
   held one with 422; two signed roots for one size are written under
   `evidence/` as the `EquivocationProof` a witness writes. The memory is
   rebuilt from the entries file at start. The verifier does not rely on
   it (decision 5): it is a check by the agent's own organisation.
2. Entry rate limits and retention: tiles are forever; an agent that
   checkpoints every second writes 86,400 entries a day. Batching
   (one entry per agent per minute, latest wins) is probably right and
   needs words.
   *Prototype: not decided.* Each checkpoint that advances an agent is one
   entry; re-sending the held checkpoint appends nothing; `--max-origins`
   caps the number of agents; the server listens on loopback unless
   `--allow-remote`. There is no batching, rate limit per agent, or
   retention.
3. Does an existing operator community accept a log whose entries are
   other logs' checkpoints? It is structurally what Rekor and sumdb are
   (entries that are someone else's signed statements), but the question
   should be asked before the code is written. The draft application text
   is in the discussion thread.
   *Prototype: still open; code cannot answer it.* What the prototype
   shows is that an unmodified `witness-log witness serve`, with the fleet
   origin enrolled by `witness add-log`, cosigns the fleet log through the
   ordinary `add-checkpoint` call (the CLI's end-to-end test does this with
   two witnesses of two organisations). Whether other operators will admit
   such a log has not been asked of them.
4. Dedup across paths: a witness that cosigned the agent directly and the
   fleet checkpoint is one key and counts once; a witness that cosigned
   only the fleet is counted with `witnessed_via: fleet`. Should a verdict
   be able to *require* direct witnessing (`--require-direct`)? Probably
   yes, for high-stakes gates; this RFC proposes it as a flag.
   *Prototype:* dedup as described (decision 6). No `--require-direct`:
   the opt-in is the switch. Without `--accept-fleet-anchor` the anchor is
   ignored entirely, which is requiring direct witnessing; and with it,
   fleet cosigners never make a dossier split-view resistant, so a gate on
   exit 0 without `--allow-sub-majority` still needs a direct majority.
5. Origin naming: `<org-domain>/witness-log/fleet` puts the organisation's
   DNS name in the origin, which is what CT does. RFC-0003 (DNS TXT
   self-registration) could carry the fleet vkey in the same record.
   *Prototype:* any C2SP origin that does not start with `witness-log/`;
   the documentation uses `<org-domain>/witness-log/fleet`. Nothing checks
   that the domain belongs to the organisation, and the vkey is not
   published in DNS.

## How to comment

Open a thread in GitHub Discussions titled `RFC-0001` (or comment on the
pull request that added this file); corrections to the description of
witness-network.org admission are especially welcome from its maintainers.
