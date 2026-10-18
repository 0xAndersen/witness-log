# Quickstart: CLI

The `witness-log` binary is the whole system in one static file: it
verifies dossiers, runs witnesses, submits journals to them, speaks the
C2SP checkpoint format, and checks other implementations against the
conformance corpus. It is also the fastest way to *understand* witness-log,
because `witness-log demo` walks the entire lifecycle in a few seconds and
narrates each step.

This page is for three readers: someone who wants to see what the tool does
before writing code, an operator who needs a deployment gate, and a
developer in a language without bindings who will shell out to it.

Linux x86_64/aarch64, macOS Intel/Apple Silicon, Windows. No runtime.

---

## 0. Install and run the demo

```sh
cargo install witness-log-cli            # from crates.io (Rust 1.75+)
# or prebuilt: the archive for your platform from
# https://github.com/0xAndersen/witness-log/releases/latest, then `sha256sum -c SHA256SUMS`
witness-log --version
witness-log demo
```

`demo` writes nothing to disk and talks to no network. With throwaway keys
it creates an identity, logs three events, erases one under
right-to-be-forgotten, signs a checkpoint, has four simulated witnesses
cosign it, and then verifies the same bytes **twice**:

- with nothing supplied from outside the file → `UNANCHORED`;
- with an expected identity and a directory *you* trust → `WITNESSED`.

That contrast is the one idea to take from this page: **a dossier can only
prove what the verifier brings to it.** Everything in the file can be checked
for internal consistency; whether it describes the agent you think it does,
and whether anyone independent saw it, are facts that come from outside.

Then run the attack:

<!-- doctest: group=demo exit=40 -->
```sh
witness-log demo --tamper
```

An attacker builds a forgery with flawless cryptography: a fresh identity, a
re-signed checkpoint, three "independent auditors" of their own invention.
It fails `✗ Identity bound` (the key that signed is not the key the file
claims) and, even if that were fixed, tops out at `UNANCHORED` because
receipts are scored only against the verifier's directory, never the
dossier's own. Verdict `INVALID`, exit code 40. Read the two paragraphs it
prints at the end; they are the threat model in miniature.

---

## 1. The commands

| command | what it does | when you use it |
|---|---|---|
| `testnet up / status / down` | three local witnesses as child processes, plus the directory file listing them | trying the whole path on one machine |
| `log init / append / forget / export / disclose / info` | an agent's journal from the shell: create, record, erase, export, disclose one payload | agents without bindings, scripts, CI |
| `submit <journal> --directory <dir.json> --out <dossier.json>` | get a journal cosigned by witnesses in your directory (fail-closed: majority or exit 20) | the step that reaches WITNESSED |
| `verify <dossier.json> [--identity <hex>] [--directory <dir.json>] [--subject-org ORG] [--min-witnesses N] [--allow-sub-majority] [--known-head <size>:<root>] [--evidence <file>] [--json] [--explain]` | offline verification; the exit code **is** the verdict | CI gates, incident review, regulators |
| `journal serve <journal> --listen 127.0.0.1:7390` | HTTP front for one journal: append, forget, submit, dossier | agents in any language, over loopback |
| `directory build / add` | build `trusted.json` from `registry/witnesses/*.json`, or add one witness by its vkey | curating the directory you trust |
| `explain [verdict]` | what each verdict proves and does not, in words | before you gate anything on a verdict |
| `doctor [<journal>] [--directory <dir.json>] [--subject-org ORG] [--witness <dir>]` | checks a setup and prints the fix for each problem: unwitnessed leaves, a journal that contradicts its cosigned head, a directory that cannot reach WITNESSED, witnesses down or serving another key | when something does not work, before you ask |
| `diff <a.json> <b.json>` | compare two dossiers of one log: honest growth, equivocation, or tampering | "these two copies disagree" |
| `bind <a.json> <b.json> [--json]` | two different agents' dossiers: prove their handoff / authorization leaves commit to the same bytes and scope | multi-agent audits |
| `witness init / serve / info / add-log / verify-evidence` | run a witness, inspect one, check an equivocation file | operators |
| `c2sp show / export / verify` | C2SP checkpoint bodies and signed notes, with the dossier's cosignatures attached | interop with other transparency tooling |
| `conform <dir>` | check another implementation against the corpus | implementers |
| `demo [--tamper]` | the walkthrough above | first five minutes |

Every subcommand has `--help`. `verify --explain` prints one line under
each check saying what it does and does not prove. Every flag and exit
code is in the [CLI reference](CLI-Reference).

**From install to WITNESSED, no code.** Three local witnesses under three
operator names are enough to see every verdict on one machine:

<!-- doctest: group=testnet -->
```sh
witness-log testnet up --out trusted.json          # starts 3 witnesses; writes the directory
witness-log log init agent.jsonl                   # prints {"identity": "<hex>", ...}
witness-log log append agent.jsonl --intent '{"tool":"transfer_funds","amount_usd":250}'
witness-log log append agent.jsonl --result '{"status":"ok","tx_id":"tx_7ac31"}' --outcome ok
witness-log submit agent.jsonl --directory trusted.json --out dossier.json
witness-log verify dossier.json --directory trusted.json \
  --identity "$(witness-log log info agent.jsonl | jq -r .identity)"       # exit 0
witness-log testnet down
```

The testnet proves the tooling, not independence: all three witnesses are
yours. Replace `trusted.json` with a directory of other organisations'
witnesses ([Getting witnessed](Getting-Witnessed)) and the same commands
produce a verdict that means something to someone else.

---

## 2. The verdicts and exit codes

```
0   WITNESSED               cryptography sound AND ≥2 independent operators from YOUR directory cosigned,
                            and they are a strict majority of it (or --allow-sub-majority was given)
11  WITNESSED               as for 0, but the cosigners are not a strict majority of your directory:
                            a conflicting history could have been cosigned by the rest (split view)
10  CONSISTENT-UNWITNESSED  cryptography sound; a directory was supplied but coverage fell short of the gate
20  UNANCHORED              internally consistent; no trusted directory supplied, so nothing external was checked
                            (submit: a witness refused with 422, or fewer than --min cosigned)
30  DIVERGED                valid, but contradicts a head you passed with --known-head or a witness
                            equivocation proof you passed with --evidence (diff: two valid, conflicting copies)
40  INVALID                 a check failed: altered, fabricated, or signed by an identity you did not pin
2   usage error / unreadable input
```

**Why exit codes.** Verification is meant to sit in a pipeline, and a
pipeline branches on an integer. The codes are spaced so a shell can test
`-ge 20` for "do not trust this" without parsing text, and `2` is kept
for usage so a typo cannot be mistaken for a verdict. Before 0.5.0 a
failed check exited 30 and 11 needed `--strict`; since 0.5.0 a failed
check is 40 and 11 is the default (`--allow-sub-majority` accepts 11 as
0; `--no-strict`, kept for 0.5.x, is gone).

**What each verdict proves, in one sentence each:**

- `WITNESSED`: the history is unaltered since the moment at least two organisations you trust saw it, and it belongs to the identity you expected.
- `CONSISTENT-UNWITNESSED`: nothing is wrong with the file, but not enough of the witnesses *you* trust have seen it; it may be new, or your directory may be too small, or the agent only reached one operator.
- `UNANCHORED`: the file does not contradict itself. That is all. An attacker can produce this verdict at will.
- `DIVERGED`: the file is valid, and the identity has also signed a history that contradicts it; the report says which head or proof.
- `INVALID`: something concrete failed; the report says which check.

The reasoning behind each is in [Verification and verdicts](Verification-and-Verdicts).

**The deployment gate is one line:**

```sh
witness-log verify dossier.json --identity "$AGENT_KEY" --directory trusted.json --min-witnesses 3 || exit 1
```

`$AGENT_KEY` is the identity you *expect* (from your configuration, not
from the dossier). `trusted.json` is the directory you curated. Both are
inputs from outside the file; that is what makes the gate mean something.
`--min-witnesses` is an absolute floor on receipt count, added because a
fraction of a 60-entry directory is not a useful threshold. Omit it and
the CLI will warn you when the directory is large. A floor of 3 against a
directory of more than five witnesses lets a sub-majority pass the gate:
a dossier cosigned by half the directory or fewer is WITNESSED but exits
11, which this gate rejects. Either verify against a directory of the
witnesses you actually submit to, so that the cosigners are a majority of
it, or accept the split-view risk explicitly with `--allow-sub-majority`.

---

## 3. Get a journal witnessed

```sh
witness-log submit agent.jsonl --directory trusted.json --out dossier.json
witness-log verify dossier.json --identity $(jq -r .identity_pubkey dossier.json) --directory trusted.json
```

(`submit` and `witness submit` are the same command.)

**What `submit` does, step by step.**

1. Opens the journal read-only and signs a checkpoint over its current head.
2. Contacts every witness in `trusted.json`, in parallel. (The `journal serve` front's `POST /submit` takes `want` to contact a diversity-aware subset instead.) (The Python `Witnesser` and the MCP server instead pick at most 8 with `select_witnesses`: one per `operator_org` first, then round-robin, spread per identity. For a registry-sized directory, give `submit` a directory trimmed to the witnesses you want to use.)
3. POSTs the checkpoint to each witness's `/add-checkpoint`. A `409` means "I remember an older head of yours"; `submit` resends with a consistency proof from that size. A `429`/`503` with `Retry-After` is honoured up to 60 s.
4. Collects cosignatures into receipts and writes the dossier.
5. Records, in `agent.jsonl.witnesses.json`, the last size each witness cosigned.
6. Exits fail-closed: `--min` defaults to a strict majority of the directory (never below 2), any `422` refusal is exit 20, and `--allow-partial` exits by the verdict instead.

**Why step 5 matters.** If you ever restore a journal from an old backup
and run `submit`, the cache will show that a witness has already cosigned a
*larger* size than the journal now has. `submit` refuses to publish that
history, because the witness would (correctly) record your identity as
equivocating, and an equivocation is permanent evidence. Protecting you
from your own backups is cheaper than explaining to an auditor why your
agent has two histories.

Where `trusted.json` comes from: [Getting witnessed](Getting-Witnessed) and
`registry/build_directory.py`. To try it on one machine, run two witnesses
under two organisation names and list their entries (`witness init`
prints the entry as JSON on stdout; the prose goes to stderr):

<!-- doctest: group=manual before="witness-log log init agent.jsonl && witness-log log append agent.jsonl --memory hello" -->
```sh
witness-log witness init w1 --name w1.local/w --org "Org One" --url http://127.0.0.1:7381 > w1.json
witness-log witness init w2 --name w2.local/w --org "Org Two" --url http://127.0.0.1:7382 > w2.json
witness-log witness serve w1 --listen 127.0.0.1:7381 --open-enrollment &
witness-log witness serve w2 --listen 127.0.0.1:7382 --open-enrollment &
sleep 1                                                  # give them a moment to start listening
jq -s '{witnesses: .}' w1.json w2.json > trusted.json     # or a bare array: jq -s . w1.json w2.json
witness-log witness submit agent.jsonl --directory trusted.json --out dossier.json
witness-log verify dossier.json --identity "$(jq -r .identity_pubkey dossier.json)" --directory trusted.json   # exit 0
```

Both witnesses are yours, so this proves the mechanics, not independence:
`WITNESSED` is only as strong as the organisations in the directory.

---

## 4. Read a `verify` report

```
✓ Checkpoint signature valid
✓ Identity bound to --identity f7809c16...0506b3be
✓ Leaf structure valid
✓ Key bindings valid (2 bindings, 0 revocations)
✓ Merkle continuity verified (6 leaves)
✓ 3/4 witness signatures valid (gate: at least 3 witnesses)
✓ Independent operators: 2 cosigned (example-infra-co, example-university); 3 of 4 known operators represented (75%)
✓ Compute-provider diversity: 3 of 4 known providers represented (75%)

Verdict: WITNESSED — proofs verify and at least 2 independent operators from your trusted directory cosigned this checkpoint
```

Line by line, what was actually checked:

| line | what it means |
|---|---|
| Checkpoint signature valid | the `(size, root, time)` statement was signed by the key it names, using strict Ed25519 |
| Identity bound to `--identity` | that key is the one *you* said to expect; without `--identity` this line reads "self-consistent (not pinned)", meaning the file agrees with itself but you have not said whose log it should be |
| Leaf structure valid | every leaf parses, types are known, indices are dense |
| Key bindings valid | every session key that wrote a leaf has a binding signed by the identity; revocations are honoured |
| Merkle continuity verified | the tree rebuilt from the leaves has exactly the root the checkpoint signed |
| N/M witness signatures valid | receipts verified against the public keys in *your* directory; the gate in brackets is the one that applied |
| Independent operators | how many distinct `operator_org` values cosigned; this is what WITNESSED requires ≥2 of |
| Compute-provider diversity | a second axis: the same operator on two clouds scores higher than on one |

`--json` gives the same as a structured object (`verdict`, `exit_code`,
`identity_pinned`, `internally_consistent`, `bindings_asserted`,
`quorum.independent_operators_represented`, `quorum.count_gate`,
`split_view_unsafe`, `failures`, `contradictions`, …).

---

## 5. Two copies disagree: `diff`

```sh
witness-log diff monday.json friday.json
```

Three outcomes, and they mean different things:

- **Friday extends Monday.** A consistency proof exists from Monday's size to Friday's; nothing was rewritten. Normal.
- **Same identity, same size, different roots.** The identity signed two histories. That is *equivocation*: the agent (or whoever holds its key) presented different pasts to different people. Witnesses exist precisely to make this detectable. Exit 30 (DIVERGED).
- **Leaves differ but the checkpoint is the same.** Someone edited a dossier after it was signed. That is *tampering*, and the Merkle root catches it. Exit 40 (INVALID): an edited copy proves nothing, so it is never read as equivocation.

With one copy and a head you kept from earlier (a receipt, a cosigned
checkpoint), `verify friday.json --known-head <size>:<root>` makes the
same check: exit 30 if Friday's first `<size>` leaves no longer produce
that root.

---

## 6. From any language

The CLI is the integration for languages without bindings. Write the
dossier JSON (schema: `spec/dossier.schema.json`), shell out to `verify`,
branch on the exit code. Go, TypeScript and shell examples are in
[Other languages](Other-Languages). Because the binary is static and the
verdict is an exit code, this works unchanged inside a container, a CI
runner, or an air-gapped audit workstation.

---

## 7. Where to go next

- Run your own witness in ten minutes: [Running a witness](Running-a-Witness).
- What the protocol on the wire looks like, including the 409 and 422 paths: [Witness protocol walkthrough](Witness-Protocol-Walkthrough).
- The language bindings: [Quickstart: Python](Quickstart-Python), [Quickstart: Rust](Quickstart-Rust).
