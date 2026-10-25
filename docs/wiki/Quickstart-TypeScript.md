# Quickstart: TypeScript / Node.js

From `npm install` to a verified, erasable, witnessed audit trail, with no
Rust toolchain, no Python and no CLI on the machine. The same model as the
[Python quickstart](Quickstart-Python); read [Concepts](Concepts) first if
you want the vocabulary.

**What you will build:** an agent loop whose every tool call is recorded
before it runs and after it returns; a one-file proof you can hand to
anyone; an erasure that removes one entry's content without touching the
proof of anything else; and a `WITNESSED` verdict from independent
operators.

Three packages, all ESM with types, Node 20+:

| package | what it is | needs |
|---|---|---|
| [`@witness-log/node`](https://github.com/0xAndersen/witness-log/tree/main/clients/node) | the log: `openLog`, append, `forget`, `disclose`, `exportDossier`, `submit`, both verifiers. The Rust core as a prebuilt native addon (Linux x64/arm64, macOS x64/arm64, Windows x64). | nothing else |
| [`@witness-log/ai-sdk`](https://github.com/0xAndersen/witness-log/tree/main/clients/ai-sdk) | Vercel AI SDK v5: `witnessTools`, `witnessMiddleware`, `witnessTelemetry` | `ai ^5` |
| [`@witness-log/client`](https://github.com/0xAndersen/witness-log/tree/main/clients/typescript) | the pure-TypeScript verifier (`verifyDossier`), plus typed wrappers for the CLI and the MCP server | nothing, for verifying |

Fastest start: `npm create witness-log my-agent` (or `-- --template ai-sdk`)
generates a project with all of the below wired up and tested.

---

## 0. Install

```sh
npm install @witness-log/node
node -e 'import("@witness-log/node").then(m => console.log(m.nativeVersion()))'
```

`npm install` picks the platform package for your OS and CPU from
`optionalDependencies`; nothing is compiled. Why Rust underneath? The
hashing, Merkle construction and Ed25519 code is the part that must be
identical across every language and every verifier, forever; one
implementation with a conformance corpus ([Spec and interop](Spec-and-Interop))
is how that is kept true. The TypeScript layer adds conveniences (string
and JSON payloads, `step`, `submit` over `fetch`) and one deliberate
duplicate: a verifier that shares no code with the writer (§3).

---

## 1. Open a journal

```ts
import { openLog } from "@witness-log/node";

const log = openLog("agent.jsonl", { storePayloads: true });
console.log(log.identityPubkey);     // 64 hex: the agent's identity, for the rest of its life
```

Files next to your script, all `0600`:

| file | what it holds | why it matters |
|---|---|---|
| `agent.jsonl` | a header with the agent's **identity private key**, then one JSON line per event (index, type, time, session key, payload *hash*) | this *is* the agent; whoever has it can sign as the agent |
| `agent.jsonl.salts` | one 32-byte random salt per event | deleting one salt is how one entry is erased (§4) |
| `agent.jsonl.payloads` | the plaintext payloads, only with `storePayloads: true` | lets `disclose(i)` prove what an entry said; witness-log itself never needs it |
| `agent.jsonl.lock` | the PID that owns the journal | one writer at a time; a second `openLog` throws |

Running the same program again resumes the same identity (`openLog` resumes
when the file exists). To hold the key yourself pass `identitySeed` (32
bytes); add `seal: true` and the seed is never written to disk: the header
holds only the public key, and every open needs the seed from wherever you
keep secrets (a KMS, an environment variable). `log.identityBytes()` gives
the seed of an unsealed journal if you want to move to that mode later.

---

## 2. Record what the agent does

```ts
const tools = {
  search: async (q: string) => [{ title: "Oslo weather", snippet: "21C" }],
  pay: async (amountUsd: number) => ({ tx: "t-1", amountUsd }),
};

const hits = await log.step("search", () => tools.search("weather in Oslo"), { args: { q: "weather in Oslo" } });
const receipt = await log.step("pay", () => tools.pay(25), { args: { amountUsd: 25 } });
```

`step` appends an **intent** leaf (`0x01`: tool name, arguments, time)
before the function runs and a **result** leaf (`0x02`: outcome `ok` with
the return value, or `error` with the message, rethrown) after. The order is
the point: the intent is committed before the side effect happens, so a
record that says "I was about to pay 25" cannot be written after paying 500.

The lower-level calls are there when you want them:

```ts
const i = log.appendIntent({ tool: "search", args: { q: "weather" } });         // any JSON value, string or Uint8Array
log.appendResult({ hits: 3 }, { tool: "search", intentIndex: i, outcome: "ok" });
log.appendMemory("the user prefers metric units");                              // 0x00: context, not an action
```

JSON values are committed as canonical JSON (sorted keys, no whitespace,
`canonicalJson()` is exported and gives the same bytes as the Python package's `canonical_json` for strings, integers, booleans, null, arrays and objects). Nothing you
pass is stored in the tree: each leaf commits
`SHA256(bucket_pad(payload) || salt || index)` ([Redaction explained](Redaction-Explained)).

With the Vercel AI SDK the same two leaves per tool call are one line:

```ts
import { witnessTools } from "@witness-log/ai-sdk";
const result = await generateText({ model, tools: witnessTools(tools, log), prompt });
```

`witnessMiddleware(log)` (via `wrapLanguageModel`) records at the model
boundary instead, including provider-executed tools, and
`witnessTelemetry(log)` is an OpenTelemetry span exporter for
`experimental_telemetry`. The package README has all three.

---

## 3. Export a dossier and verify it, twice

```ts
import { writeFileSync } from "node:fs";
import { verifyDossier, verifyDossierNative } from "@witness-log/node";

const dossier = log.exportDossier();                       // SPEC §9: leaves, signed checkpoint, key bindings
writeFileSync("dossier.json", JSON.stringify(dossier));

const ts = verifyDossier(dossier, { identity: log.identityPubkey });
const rs = verifyDossierNative(dossier, { identity: log.identityPubkey });
console.log(ts.verdict, rs.verdict);                        // UNANCHORED UNANCHORED
```

`verifyDossier` is pure TypeScript (`node:crypto`): leaf encoding, Merkle
root, checkpoint signature, key bindings and revocations, receipts, quorum
and diversity, written from the spec and checked against `/corpus`.
`verifyDossierNative` is the Rust reference verifier, the same code
`witness-log verify` runs. Two independent implementations agreeing on
your dossier is worth more than one; a disagreement is a bug, report it.
Both return `verdict`, `exitCode` (0/11/10/20/30/40, the CLI's contract),
`ok` (WITNESSED with exit 0), `splitViewUnsafe`, `failures` (why INVALID),
`contradictions` (why DIVERGED) and `report` (what `witness-log verify
--json` prints). Both take `knownHeads` (`"<size>:<root hex>"` heads you
kept earlier), `evidence` (witness equivocation proofs) and
`allowSubMajority` besides `identity`, `directory` and the gates, and
`subjectOrg`: the organisation that operates the log, whose own witnesses
then never count as independent of it.

`UNANCHORED` means: internally consistent (every leaf reproduces the signed
root, the signature verifies under the identity, each session key traces to
a binding the identity signed) but nothing you trust has been consulted.
That is the ceiling for a dossier on its own; §5 raises it. Try it:

```ts
const t = structuredClone(dossier);
t.leaves[1].payload_hash = "00".repeat(32);
console.log(verifyDossier(t).verdict, verifyDossier(t).failures);   // INVALID [ 'the leaves do not reproduce the signed root' ]
```

---

## 4. Erase one entry without breaking anything

```ts
const d = log.disclose(1);        // { payloadHash, salt, payload, verified: true }: prove what leaf 1 said
log.forget(1);                    // salt erased from agent.jsonl.salts, payload from .payloads; a 0x03 leaf is appended
log.disclose(1);                  // { payloadHash, salt: null, payload: null, verified: false }
verifyDossier(log.exportDossier()).verdict;   // still UNANCHORED, not INVALID
```

The leaf's `payload_hash` is unchanged, so every proof and every checkpoint
any witness ever cosigned stays true; without the 32-byte salt the content
behind the hash is unrecoverable. The root changes because a leaf was
*added*, never because one was changed. `verifyDisclosure(leaf, payload,
salt)` is how a third party checks a disclosure you hand them, offline.

---

## 5. Get witnessed

A witness is a small HTTP service, ideally run by an organisation that is
not you, speaking `c2sp.org/tlog-witness`. It remembers the last head it
cosigned for your log and refuses (`422`) a history that does not extend it.
Two witnesses from two different `operator_org` values are the floor for
`WITNESSED`; a hundred under one organisation are one voice.

You need a directory of witnesses *you* trust, `{"witnesses": [...]}`. The
public registry is at `registry/` in the repository. For development run
local witnesses with the CLI (`cargo install witness-log-cli`, or a
release binary, or the Docker image `ghcr.io/0xandersen/witness-log`):

<!-- doctest: group=testnet after="witness-log testnet down" -->
```sh
witness-log testnet up --out trusted.json    # CLI 0.4.0+: three local witnesses (three organisations) and the directory file
```

or on an earlier CLI, by hand (each `witness init` prints a directory entry):

<!-- doctest: group=by-hand -->
```sh
witness-log witness init ./w1 --name w1.local/witness --org "Org One" --url http://127.0.0.1:7381 > w1.json
witness-log witness init ./w2 --name w2.local/witness --org "Org Two" --url http://127.0.0.1:7382 > w2.json
witness-log witness serve ./w1 --listen 127.0.0.1:7381 --open-enrollment &
witness-log witness serve ./w2 --listen 127.0.0.1:7382 --open-enrollment &
jq -s '{witnesses: .}' w1.json w2.json > trusted.json
```

Then:

```ts
const r = await log.submit("trusted.json", { want: 8, min: 2 });
console.log(r.ok, r.cosignatures, r.outcomes);              // per witness: 200, or 409/422/429/0 with a reason
if (r.ok) writeFileSync("dossier.json", JSON.stringify(r.dossier));

const v = verifyDossier(r.dossier!, { directory: "trusted.json", identity: log.identityPubkey, minWitnesses: 2 });
console.log(v.verdict, v.report.quorum?.independent_operators_represented);   // WITNESSED [ 'org one', 'org two' ]
```

`submit` is the same procedure as `witness-log witness submit` and the
Python `Witnesser`: it pins the head, picks witnesses diversity-first,
follows the `409` resync (the witness answers with the size it last
cosigned; you resend a consistency proof from there), honours `Retry-After`
on `429`/`503`, counts only cosignatures that verify under the directory's
key over this exact head, and writes `agent.jsonl.witnesses.json`, the
CLI's state file. It refuses (`r.refused`) to submit a journal that does not
extend a head witnesses already cosigned for this identity: a journal
restored from an old backup must not get your identity recorded as
equivocating. Network failures are per-witness `outcomes`, never
exceptions; `r.ok` is false below `min`.

The directory is yours, never the dossier's. The dossier carries a copy of
the witness list for display, but both verifiers score receipts only
against the directory you pass; otherwise a dossier could ship three
"independent auditors" of its own invention. Without a directory the
verdict is `UNANCHORED` no matter what the dossier claims.

---

## 6. Where to go next

- Cross-agent evidence: `log.appendHandoff("sent" | "received", counterparty, state)` and
  `appendAuthorizationEvent(kind, counterparty, scope)`; `verifyHandoffBinding` /
  `verifyAuthorizationBinding` match the pair across two dossiers ([Multi-agent handoff](Tutorial-Multi-Agent-Handoff)).
- External time: `appendExternalAnchor(url, proof)` for a Rekor entry or RFC 3161 token.
- What each verdict proves and does not: [Verification and verdicts](Verification-and-Verdicts).
- The same journal from the CLI: `witness-log verify dossier.json --identity ... --directory trusted.json`,
  `witness-log witness submit agent.jsonl --directory trusted.json`; state and format are shared.
- Running a witness of your own, for others: [Running a witness](Running-a-Witness).
