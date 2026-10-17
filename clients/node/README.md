# @witness-log/node

[witness-log](https://github.com/0xAndersen/witness-log) for Node.js: an
append-only Merkle audit log for AI agents, signed by the agent's identity
key, erasable per entry, cosignable by independent witnesses, verifiable
offline by anyone. The Rust core ships as a prebuilt native addon
(napi-rs), so `npm install` is the whole setup: no Rust toolchain, no
Python, no CLI.

```sh
npm install @witness-log/node
```

Prebuilt for Linux x64/arm64 (glibc), macOS x64/arm64 and Windows x64, as
`optionalDependencies` (`@witness-log/node-linux-x64-gnu` and so on). Node
20+, ESM with types.

## Record, export, verify

```ts
import { openLog, verifyDossier, verifyDossierNative } from "@witness-log/node";

const log = openLog("agent.jsonl", { storePayloads: true });   // creates, or resumes the same identity

const i = log.appendIntent({ tool: "search", args: { q: "weather in Oslo" } });
log.appendResult({ hits: 3 }, { tool: "search", intentIndex: i, outcome: "ok" });

// or, both leaves around a function (errors are recorded, then rethrown):
const tx = await log.step("pay", () => pay(250), { args: { amountUsd: 250 } });

const dossier = log.exportDossier();            // SPEC §9, hand it to anyone
const v = verifyDossier(dossier, { identity: log.identityPubkey });
console.log(v.verdict);                         // UNANCHORED: consistent, not yet witnessed
log.close();
```

Two verifiers ship: `verifyDossier` is pure TypeScript (`node:crypto`,
from `@witness-log/client`, shares no code with the writer) and
`verifyDossierNative` is the Rust reference verifier, the same code
`witness-log verify` runs. They take the same options (`identity`,
`directory`, `threshold` or `minWitnesses`, `revocations`, and
`knownHeads`, `evidence`, `allowSubMajority`, `subjectOrg`, the organisation
that operates the log, whose own witnesses then never count as
independent) and return the same shape:
`verdict` (`WITNESSED | CONSISTENT-UNWITNESSED | UNANCHORED | DIVERGED |
INVALID`), `exitCode` (0/11/10/20/30/40), `ok` (WITNESSED with exit 0),
`splitViewUnsafe`, `failures` (why INVALID), `contradictions` (why
DIVERGED), and `report` (the same object `witness-log verify --json`
prints). INVALID (40) is a failed check; DIVERGED (30) is a valid dossier
that contradicts a head in `knownHeads` (`"<size>:<root hex>"`) or an
equivocation proof in `evidence` that verifies for this identity. Exit 11
is a WITNESSED dossier whose cosigners are not a strict majority of the
directory, unless `allowSubMajority`. Before 0.5.0 failed checks were
DIVERGED (30). Both verifiers run every case of corpus vector
`13_verdicts.json` in the test suite. For a decision that matters, run
both; a disagreement is a bug to report.

## What a payload is

`appendIntent`, `appendResult` and `appendMemory` take a `Uint8Array`
(committed as is), a `string` (UTF-8) or any JSON value (canonical JSON:
sorted keys, no whitespace, `canonicalJson()` is exported). With options
(`{ tool, intentIndex, outcome }`) the leaf's payload is the canonical JSON
of `{ tool, intent_index, outcome, value }`. The log never stores payloads:
the tree holds `SHA256(bucket_pad(payload) || salt || index)` only. With
`storePayloads: true` the plaintext is kept in `<journal>.payloads` (0600)
so `disclose(i)` can return it with the salt:

```ts
const d = log.disclose(i);     // { index, payloadHash, salt, payload, verified: true }
verifyDisclosure(dossier.leaves[i], d.payload, d.salt);   // anyone can check this, offline
log.forget(i);                 // erases salt and payload; every proof stays valid; a 0x03 leaf is appended
```

## Identity and sealing

`openLog(path)` stores a fresh identity seed in the journal header (0600).
`openLog(path, { identitySeed })` uses a 32-byte seed you hold (the same
seed gives the same identity anywhere). `openLog(path, { identitySeed,
seal: true })` keeps the seed out of the file; every later open then needs
it, and opening a sealed journal without it fails with `code: "sealed"`.
`log.identityBytes()` returns the seed; treat it as a private key.

Cross-agent leaves: `appendHandoff("sent" | "received", counterparty,
state)` (SPEC §3.1), `appendAuthorizationEvent(kind, counterparty, scope)`
(§3.2, `kind` is `granted_by_me` … `scope_changed_to_me`),
`appendExternalAnchor(url, proof)` (§3.3). `verifyHandoffBinding` and
`verifyAuthorizationBinding` match a pair across two agents' dossiers.

## Get witnessed

```ts
const r = await log.submit("trusted.json", { want: 8, min: 2 });
// r.ok, r.cosignatures, r.outcomes (per witness: status 200 / 409 / 422 / 429 / 0 + error), r.dossier
if (r.ok) writeFileSync("dossier.json", JSON.stringify(r.dossier));
verifyDossier(r.dossier, { directory: "trusted.json", identity: log.identityPubkey, minWitnesses: 2 }).verdict;
// WITNESSED once two witnesses from two different operator_org values cosigned
```

`submit` is the same procedure as `witness-log witness submit` and the
Python `submit_round`, over Node's `fetch`: diversity-first witness
selection, the `409` resync (the witness tells you the size it last
cosigned, you resend a consistency proof from there), `Retry-After` on
`429`/`503` (up to 60 s), and only cosignatures that verify under the
directory's key over this exact head are counted. State goes to
`<journal>.witnesses.json`, the CLI's file, so the two can take turns. It
refuses (`r.refused`) to submit a journal that does not extend a head
witnesses already cosigned for this identity: witnesses would keep both
heads as proof the identity equivocated. Network failures are per-witness
`outcomes`, never exceptions.

The directory is yours, never the dossier's: `{"witnesses": [...]}`, a bare
array, or a path. The public registry is at `registry/`; for development
run two local witnesses with the CLI (`witness-log witness init` / `serve
--open-enrollment`, or `witness-log testnet up` on CLI 0.4.0+) or the
Docker image. Two witnesses under one organisation are one voice.

## Lower level

`log.native` is the napi-rs object (`addCheckpointBodyAt`,
`dossierFromResponsesAt`, `inclusionProof`, `rootHexAt`, `leavesJson`, ...),
and `import * as native from "@witness-log/node/native"` is the whole
binding. `forceUnlock(path)` removes a stale lock after a crash.
`loadWitnessState`/`saveWitnessState` read and write the CLI's state file.

## Errors

Everything thrown on purpose is a `WitnessLogError` with `code` one of
`closed`, `io`, `invalid`, `sealed`, `refused`, `native`. A second process
opening the same journal gets a lock error (`native`); `forceUnlock` is
for a lock left by a dead process only.

## Building from source

```sh
cd clients && npm ci && npm run build -w typescript
cd node && npm run build            # cargo + napi build (release) + tsc
npm test                            # node:test; a mocked tlog-witness server covers submit
```

Rust 1.80+ for the addon crate (`clients/node/Cargo.toml`, its own
workspace). `.github/workflows/npm-node.yml` builds the five platforms
and publishes on `node-v*` tags.

## License

Apache-2.0.
