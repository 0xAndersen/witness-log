# @witness-log/client

TypeScript client for [witness-log](https://github.com/0xAndersen/witness-log),
a per-agent RFC 6962 Merkle audit log with independent witnesses and
offline verification.

Three things, each usable on its own:

- `verifyDossier(dossier, opts)`: an offline verifier in pure TypeScript
  (`node:crypto` for SHA-256 and Ed25519; nothing native, no binary). An
  independent second implementation of SPEC §3–§9 that returns the same
  four verdicts as the Rust reference verifier, checked against the
  conformance corpus. Writing a log needs `@witness-log/node`; checking one
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
});
r.verdict;         // "WITNESSED" | "CONSISTENT-UNWITNESSED" | "UNANCHORED" | "DIVERGED"
r.exitCode;        // 0 / 10 / 20 / 30, the CLI's contract
r.failures;        // why it is DIVERGED, in words
r.report;          // the same object `witness-log verify --json` prints under `report`
```

Synchronous, never throws on a hostile dossier (that is DIVERGED), throws
only on bad options. The pieces are exported too: `leafCanonicalBytes`,
`leafHash`, `merkleRoot`, `verifyInclusion`, `payloadHash` and
`verifyDisclosure` (SPEC §8, for a disclosed salt), `verifyCheckpoint`,
`verifyReceipt` (native and C2SP cosignature receipts), `verifyKeyBinding`,
`evaluateQuorum`, `canonicalOrigin`.

One stated difference from the reference verifier: SPEC §6 asks for
strict Ed25519 (reject small-order components). `node:crypto` rejects
non-canonical scalars but not small-order points, so a deliberately
degenerate signature the Rust verifier refuses could pass here. Honest
signatures are identical under both; for a load-bearing decision run the
Rust verifier as well (`WitnessLogCLI.verify`, or `verifyDossierNative`
from `@witness-log/node`).

## Verify with the CLI

```ts
import { WitnessLogCLI } from "@witness-log/client";

const cli = new WitnessLogCLI();                     // $WITNESS_LOG_BIN or `witness-log` on PATH
const r = await cli.verify("dossier.json", {
  identity: AGENT_KEY,                               // obtained out of band, never from the dossier
  directory: "trusted.json",                         // witnesses YOU trust
  minWitnesses: 2,
});
if (!r.ok) throw new Error(`audit trail is ${r.verdict}`);   // WITNESSED is the only ok
```

`r.verdict` is `"WITNESSED" | "CONSISTENT-UNWITNESSED" | "UNANCHORED" |
"DIVERGED"` with `r.exitCode` 0 / 10 / 20 / 30 and `r.report` the
verifier's full report. Usage errors (unreadable file, bad flag; exit 2)
reject with `WitnessLogCLIError`. Dossiers and directories may be paths or
objects (objects are written to a private temp file).

`cli.diff(a, b)` compares two copies of one log (`consistent` is false on
equivocation or tampering), `cli.bind(a, b)` matches two agents' handoff
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
payload hashes) and the sample dossier, then `node:test` end to end against a locally built
CLI (`$WITNESS_LOG_BIN`, default `../../target/release/witness-log`) and
the repository's MCP server with `$WITNESS_LOG_PYTHON` (needs
`witness_log` and `mcp>=2`); two witnesses are started from the CLI on
free ports.

## License

Apache-2.0.
