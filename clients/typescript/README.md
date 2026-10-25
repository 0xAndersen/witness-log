# @witness-log/client

TypeScript client for [witness-log](https://github.com/0xAndersen/witness-log),
a per-agent RFC 6962 Merkle audit log with independent witnesses and
offline verification.

Three things, each usable on its own:

- `verifyDossier(dossier, opts)`: an offline verifier in pure TypeScript
  (`node:crypto` for SHA-256 and Ed25519; nothing native, no binary). An
  independent second implementation of SPEC §3–§9 that returns the same
  five verdicts and exit codes as the Rust reference verifier, checked
  against the conformance corpus. Writing a log needs `@witness-log/node`; checking one
  needs only this.
- `WitnessLogCLI` spawns the `witness-log` binary for `verify`, `diff`,
  `bind` and `witness submit`, and returns typed results parsed from
  `--json` and the exit code (the exit code *is* the verdict).
- `WitnessLogMCP` starts the witness-log MCP server over stdio with the
  official `@modelcontextprotocol/sdk` and exposes `step(name, fn)`,
  `forget(i)`, `exportDossier()`, `verify()` and `submit()`.

ESM, typed, Node 20+.

## Install

```sh
npm install @witness-log/client
cargo install witness-log-cli            # only for WitnessLogCLI (or a release download)
pip install "witness-log[mcp]"           # only for WitnessLogMCP (Python 3.10+)
```

## Verify a dossier in TypeScript

```ts
import { verifyDossier } from "@witness-log/client";

const r = verifyDossier(JSON.parse(readFileSync("dossier.json", "utf8")), {
  identity: AGENT_KEY,                   // obtained out of band, never from the dossier
  directory: trusted,                    // {witnesses: [...]} YOU trust; without it the ceiling is UNANCHORED
  minWitnesses: 2,                       // or threshold: 0.66 (the default)
  subjectOrg: "Alpha Payments",          // who operates this log: its own witnesses never count as independent
  knownHeads: ["4:0f1e…9a2b"],           // optional: heads you kept earlier for this identity
  evidence: [proof],                     // optional: witness equivocation proofs (the file's "proof" object)
  allowSubMajority: false,               // the default: a sub-majority WITNESSED is exit 11
});
r.verdict;         // "WITNESSED" | "CONSISTENT-UNWITNESSED" | "UNANCHORED" | "DIVERGED" | "INVALID"
r.exitCode;        // 0 / 11 / 10 / 20 / 30 / 40, the CLI's contract
r.ok;              // true only for WITNESSED with exit 0
r.splitViewUnsafe; // WITNESSED, but not by a strict majority of the directory
r.failures;        // why it is INVALID, in words (empty otherwise)
r.contradictions;  // why it is DIVERGED (empty otherwise)
r.report;          // the same object `witness-log verify --json` prints under `report`
```

INVALID (40) means a check failed: signature, identity, leaf structure,
key bindings or revocations, Merkle continuity. DIVERGED (30) means the
dossier is valid but contradicts a known head (its first `tree_size`
leaves give a different root) or an equivocation proof that verifies for
this identity; without `knownHeads` or `evidence` it cannot occur. Before
0.5.0 failed checks were DIVERGED and `failures` was filled for DIVERGED;
both are INVALID now.

Synchronous, never throws on a hostile dossier (that is INVALID), throws
only on bad options. The pieces are exported too: `leafCanonicalBytes`,
`leafHash`, `merkleRoot`, `verifyInclusion`, `payloadHash` and
`verifyDisclosure` (SPEC §8, for a disclosed salt), `verifyCheckpoint`,
`verifyReceipt` (native and C2SP cosignature receipts), `verifyKeyBinding`,
`evaluateQuorum`, `canonicalOrigin`, `verifyEquivocationProof` (the key
comes from the canonical origin, and the proof's own `log_vkey` must be
that key), `parseKnownHead` (`"<size>:<root hex>"`), `EXIT_CODES` (one per
verdict, `INVALID: 40` included) and `EXIT_SPLIT_VIEW_UNSAFE` (11).

Signatures are checked as strictly as the reference verifier
(ed25519-dalek's `verify_strict`, SPEC §6): a small-order key or `R` in
any encoding, `s ≥ L`, or a key that is not a curve point is refused.
Before 0.5.0 this verifier used `node:crypto` alone, which accepts
small-order points; corpus 16 (`corpus/16_ed25519_strict.json`) pins the
cases, and the TypeScript, Go and Rust verifiers agree on every one.

Pass the dossier as JSON text where you can. It is then read exactly as
the reference reads it (corpus 17): integers above 2^53 stay exact
(`u64` fields are `number | bigint`), and duplicate keys, `3.0` for an
integer, a struct written as an array, a value of the wrong type, or
nesting deeper than 1000 arrays and objects make the dossier INVALID
("not a dossier: …"). Reading hostile text is bounded: it stops at the
1001st level, and the values of keys a dossier does not have are checked
as JSON but never built. An already-parsed object holding a plain number
above 2^53 − 1 is INVALID too, since `JSON.parse` has already rounded it,
and so is one nested deeper than 1000. The options are inputs like the
dossier: a `directory`, `revocations` (one statement or an array) or
evidence item nested deeper than 1000 throws a TypeError, as a malformed
one does.

## Verify with the CLI

```ts
import { WitnessLogCLI } from "@witness-log/client";

const cli = new WitnessLogCLI();                     // $WITNESS_LOG_BIN or `witness-log` on PATH
const r = await cli.verify("dossier.json", {
  identity: AGENT_KEY,                               // obtained out of band, never from the dossier
  directory: "trusted.json",                         // witnesses YOU trust
  minWitnesses: 2,
});
if (!r.ok) throw new Error(`audit trail is ${r.verdict}`);   // WITNESSED with exit 0 is the only ok
```

`r.verdict` is `"WITNESSED" | "CONSISTENT-UNWITNESSED" | "UNANCHORED" |
"DIVERGED" | "INVALID"` with `r.exitCode` 0 / 11 / 10 / 20 / 30 / 40,
`r.splitViewUnsafe`, and `r.report` the verifier's full report.
`cli.verify` also takes `allowSubMajority`, `subjectOrg`, `knownHeads` (strings
`"<size>:<root hex>"`), `evidence` (paths or parsed evidence files) and
`revocations`, passed to the CLI as `--allow-sub-majority`, `--subject-org`,
`--known-head`, `--evidence` and `--revocations`. Usage errors (unreadable file, bad flag; exit 2)
reject with `WitnessLogCLIError`. Dossiers and directories may be paths or
objects (objects are written to a private temp file).

`cli.diff(a, b)` compares two copies of one log (`consistent` is false on
equivocation, `exitCode` 30, or tampering, `exitCode` 40), `cli.bind(a, b)` matches two agents' handoff
and authorization leaves, `cli.submit(journal, {directory})` gets a
journal's head cosigned and returns the dossier.

## Record an agent's steps over MCP

```ts
import { WitnessLogMCP } from "@witness-log/client";

const wl = await WitnessLogMCP.start({ sessionId: "agent-1" });   // python -m witness_log.mcp_server

const tx = await wl.step("transfer", async () => pay(250), { args: { amount_usd: 250 } });
// intent leaf before pay() runs, result leaf after (or an "error" result, and the error rethrown)

await wl.forget(3);                         // GDPR erasure of one entry; every proof stays valid
const report = await wl.verify();           // { verdict: "unanchored", tamperAlerts: [] , ... }
const dossier = await wl.exportDossier();   // hand to anyone; check with cli.verify(...)
await wl.close();
```

Options: `serverPath` runs a specific `witness_mcp_server.py`;
`python` (or `$WITNESS_LOG_PYTHON`) picks the interpreter; `command`
overrides everything (for example `{command: "uvx", args: ["--from",
"witness-log[mcp]", "witness-log-mcp"]}`); `home` sets
`WITNESS_LOG_HOME`. `wl.tool(name, args)` calls any server tool
(`record_handoff`, `record_authorization`, `get_inclusion_proof`, ...);
rejected calls throw `WitnessLogMCPError` with the server's reason.

Get witnessed with `await wl.submit(directory)`; afterwards `wl.verify({
trustedDirectory: directory })` reports `witnessed` until the next step.

## Tests

`npm test` runs the TypeScript verifier against `/corpus` (leaf encoding,
Merkle roots, inclusion proofs, checkpoint and cosignature signatures,
payload hashes, revocations, and every case of the verification vector
`13_verdicts.json`) and the sample dossier, then `node:test` end to end against a locally built
CLI (`$WITNESS_LOG_BIN`, default `../../target/release/witness-log`) and
the repository's MCP server with `$WITNESS_LOG_PYTHON` (needs
`witness_log` and `mcp>=2`); two witnesses are started from the CLI on
free ports.

## License

Apache-2.0.
