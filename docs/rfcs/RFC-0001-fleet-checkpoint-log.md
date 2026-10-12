# RFC-0001: Fleet checkpoint log (one C2SP log per organisation)

Status: Draft
Target: 0.5.0 behind `witness-log fleet serve` and a `VerifyContext` opt-in; spec text in a later minor
Related: SPEC §9.3 (C2SP), §9 (dossier), THREAT_MODEL "Witness independence"

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
- New verifiers without the opt-in behave as old ones.
- No existing artefact changes meaning.

## Open questions

1. Should the fleet log's per-origin fork refusal be MUST? It makes the
   fleet log a witness for its own agents, which is good, and makes it
   stateful per agent, which is what we wanted to avoid for the public
   witnesses but is fine for the organisation's own service.
2. Entry rate limits and retention: tiles are forever; an agent that
   checkpoints every second writes 86,400 entries a day. Batching
   (one entry per agent per minute, latest wins) is probably right and
   needs words.
3. Does an existing operator community accept a log whose entries are
   other logs' checkpoints? It is structurally what Rekor and sumdb are
   (entries that are someone else's signed statements), but the question
   should be asked before the code is written. The draft application text
   is in the discussion thread.
4. Dedup across paths: a witness that cosigned the agent directly and the
   fleet checkpoint is one key and counts once; a witness that cosigned
   only the fleet is counted with `witnessed_via: fleet`. Should a verdict
   be able to *require* direct witnessing (`--require-direct`)? Probably
   yes, for high-stakes gates; this RFC proposes it as a flag.
5. Origin naming: `<org-domain>/witness-log/fleet` puts the organisation's
   DNS name in the origin, which is what CT does. RFC-0003 (DNS TXT
   self-registration) could carry the fleet vkey in the same record.

## How to comment

Open a thread in GitHub Discussions titled `RFC-0001` (or comment on the
pull request that added this file); corrections to the description of
witness-network.org admission are especially welcome from its maintainers.
