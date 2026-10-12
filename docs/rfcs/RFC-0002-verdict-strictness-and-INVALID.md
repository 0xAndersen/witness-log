# RFC-0002: Verdict strictness and an INVALID verdict

Status: Draft
Target: `verify --strict` (exit 11) as an opt-in in 0.4.0; strict as the default and the INVALID split in 0.5.0, with spec text
Related: SPEC §9.2 (the verdict), THREAT_MODEL "Witness independence" and "Accusations", `witness-log explain`

## Motivation

Two findings from the field reports on 0.3.5, both about the verifier
saying WITNESSED with exit 0 when a careful reader would not:

1. **Sub-majority gates pass silently to scripts.** With `--min-witnesses 2`
   against a six-witness directory, a dossier cosigned by two witnesses is
   WITNESSED, exit 0. A conflicting dossier for the same identity, cosigned
   by two of the other four, would also be WITNESSED, exit 0, and no witness
   would have seen both. The CLI prints a warning
   (`⚠ Split view possible`), and `QuorumResult.split_view_resistant` is
   false, but the exit code, which is what CI reads, is 0. A gate that can
   be passed by two disjoint histories is not the gate people think they
   set.
2. **DIVERGED conflates two different situations.** Today `Diverged` means
   "some cryptographic, structural or binding check failed". That covers
   (a) a file that is not a valid dossier about this identity (a bad
   signature, a mutated leaf, the wrong `--identity`, a schema violation
   after signing) and (b) the thing the name suggests: a second, validly
   signed history for the same identity (equivocation, which `diff` and the
   witnesses' evidence files show). An incident responder needs to know
   which. (a) is "this file is garbage or not what you were told"; (b) is
   "this identity has provably told two stories". The same exit code for
   both means the distinction is made by reading prose.

## Design

### Strict mode

`witness-log verify --strict` (0.4.0, opt-in):

- WITNESSED additionally requires `split_view_resistant` (the valid
  receipts from distinct trusted witnesses are a strict majority of the
  trusted directory: `2 × valid_receipts > total_directory_witnesses`),
  unless `--allow-sub-majority` is also given.
- When every other condition for WITNESSED holds but the majority does
  not, the verdict is still WITNESSED in the report (nothing about the
  cryptography changed) but the **exit code is 11**, and the report's
  `strict.split_view_unsafe` is `true`. 11 is chosen because it sits with
  10 (CONSISTENT-UNWITNESSED): the right reading is "witnessed, but not by
  enough of your directory to rule out a split view".
- `--min-witnesses N` with `2N <= total_directory_witnesses` prints the
  existing warning and, under `--strict`, is an error (exit 2) unless
  `--allow-sub-majority`: a gate the caller set that cannot be split-view
  resistant is a configuration mistake, not a verdict.

In 0.5.0 strict becomes the default and `--no-strict` restores the 0.4
behaviour for one release.

Why not change the verdict word: WITNESSED is a statement about receipts
that verified under keys in the caller's directory, and that statement is
true. What is false is the inference that it rules out a conflicting
history, and the inference depends on a number the caller chose. Keeping
the verdict and changing the exit code keeps `verify --json` consumers
that read `verdict` working, while fixing the only thing automation reads.

### INVALID, split from DIVERGED

0.5.0 introduces a fifth verdict:

| verdict | exit | meaning |
|---|---|---|
| WITNESSED | 0 | as today (strict by default) |
| CONSISTENT-UNWITNESSED | 10 | as today |
| (WITNESSED, split-view unsafe) | 11 | strict-mode exit for a sub-majority WITNESSED |
| UNANCHORED | 20 | as today |
| DIVERGED | 30 | **narrowed**: the dossier is internally valid *and* contradicts other evidence the verifier was given about the same identity: a second dossier (`diff`), a trusted earlier checkpoint (`--known-head size:root`), or a witness evidence file |
| INVALID | 40 | any failed signature, identity-binding, structural, key-binding or Merkle-continuity check; the file does not establish anything about the identity |

The rule "the worst verdict wins" still holds, now over five values:
INVALID > DIVERGED > the rest. `verify` with a single dossier and no
other evidence can therefore never return DIVERGED, because divergence is
a relation between two histories; the current behaviour of returning
DIVERGED for a bad signature is exactly the conflation this removes. The
new inputs that make DIVERGED reachable from `verify` are:

- `--known-head <size>:<root hex>`: a checkpoint the caller trusts from
  earlier (a receipt they kept, a cosignature they saw). The dossier's
  leaves must reproduce that root at that size (a consistency check
  against the dossier's own tree); if they do not, DIVERGED.
- `--evidence <file>`: a witness `EquivocationProof` for this identity;
  if it verifies, DIVERGED regardless of the dossier.

`witness-log diff a.json b.json` already distinguishes honest growth,
equivocation and tampering, but today exits 30 for every failing case
(and 2 for unreadable input). Under this RFC it exits 30 for equivocation
(two valid signed histories) and 40 when one copy is not a valid dossier,
so `diff` and `verify` use the same two numbers for the same two facts.

### `explain`

`witness-log explain invalid` and `explain diverged` get the new text;
`explain witnessed` gains the strict-mode paragraph. The four-verdict
pages in `docs/wiki/` are updated in the same change.

## Wire changes

None. Leaves, STHs, receipts, key bindings, the C2SP mapping and the
dossier JSON are untouched. What changes is the verdict enumeration in
`DossierReport` (one new variant, two new report fields:
`strict.split_view_unsafe`, `strict.enabled`), the CLI exit codes, and
§9.2's table. `verify --json` consumers that match on the four strings
need one new arm.

## Corpus vectors needed

The corpus today pins encodings, not verdicts. This RFC adds a verdict
vector file, `13_verdicts.json`, with complete dossiers and directories
and the expected result of each run:

- a WITNESSED dossier with 3 of 4 directory witnesses (strict: exit 0);
- the same dossier with a 6-witness directory, `--min-witnesses 2`
  (0.4 default: exit 0 + warning; `--strict`: exit 11; `--strict
  --allow-sub-majority`: exit 0);
- a dossier whose checkpoint signature is wrong (0.4: DIVERGED/30;
  0.5: INVALID/40);
- a dossier whose `--identity` does not match (0.5: INVALID/40);
- two dossiers for one identity, same size, different roots, each
  individually valid (`diff`: 30; `verify a.json --known-head <b's
  size:root>`: 30);
- a dossier with a verifying `--evidence` file (30).

Each case states the expected `verdict`, exit code and the boolean report
fields, so a second implementation is checked on decisions, not only on
bytes.

## Backward compatibility

- 0.4.0: no default behaviour changes. `--strict` is opt-in; exit 11 is
  only reachable with it.
- 0.5.0: scripts that treat "exit 0" as WITNESSED keep working and get
  safer (fewer exit 0s). Scripts that treat `exit != 0` as failure start
  failing on sub-majority gates, which is the intended effect; the
  release notes name the flag that restores the old reading
  (`--allow-sub-majority`), and `--no-strict` exists for one release.
- 0.5.0: anything matching exit 30 for "the file is bad" must learn 40.
  The CHANGELOG lists it under breaking changes; the `exit` constants in
  the CLI, the Python `Verdict` enum and the TypeScript client's typed
  verdicts change in the same release.
- Historically issued dossiers verify with the same cryptographic result;
  only the name of a failure changes.

## Open questions

1. Is 11 the right code for "WITNESSED but split-view unsafe", or should
   strict mode downgrade the verdict word to CONSISTENT-UNWITNESSED? The
   argument for keeping the word is above; the argument against is that a
   fifth-and-a-half state is confusing. Comments wanted from people whose
   CI reads these codes.
2. Should `--known-head` accept a C2SP note (with cosignatures) rather
   than `size:root`, so the verifier can also say whose cosignatures the
   earlier head carried?
3. Does INVALID need sub-reasons in the exit code (41 signature, 42
   continuity, …) or is `--json` enough? The proposal says `--json` is
   enough and exit codes stay coarse.
4. The majority rule is over `total_directory_witnesses`, the directory
   as passed. A verifier with a 200-entry registry directory would need
   101 cosignatures for strict WITNESSED, which no agent will collect.
   Options: strict counts a majority of the witnesses the agent was
   *supposed* to submit to (not knowable to the verifier), or the
   documentation says to verify against a curated subset (the current
   advice), or the gate is "majority of distinct operators" rather than of
   witnesses. The third is probably right and needs a vector.

## How to comment

Open a thread in GitHub Discussions titled `RFC-0002` (or comment on the
pull request that added this file). Exit-code consumers (CI maintainers,
the TypeScript and Go verifiers) are the people whose objections matter
most here.
