# Other languages: TypeScript, Go, Java, anything

Native bindings exist for Rust and Python, and a TypeScript client wraps
the CLI and the MCP server. Everyone else has two routes today, both
complete, and a third on the [Roadmap](Roadmap).

## TypeScript: `@witness-log/client`

`clients/typescript` (npm `@witness-log/client`, ESM with types, Node 20+).
It reimplements no cryptography: `WitnessLogCLI` spawns the `witness-log`
binary and returns typed verdicts, `WitnessLogMCP` drives the MCP server.

```ts
import { WitnessLogCLI, WitnessLogMCP } from "@witness-log/client";

const wl = await WitnessLogMCP.start({ sessionId: "orders-bot" });   // needs pip install "witness-log[mcp]"
const refund = await wl.step("stripe.refund", () => stripe.refund(1042), { args: { order: 1042 } });
const dossier = await wl.exportDossier();
await wl.close();

const v = await new WitnessLogCLI().verify(dossier, { identity: KEY, directory: "trusted.json" });
if (v.verdict !== "WITNESSED") throw new Error(v.verdict);   // v.exitCode is 0/10/20/30
```

See the package README for `diff`, `bind`, `submit`, `forget` and the
server options.

## Route 1: MCP (any language with an MCP client)

Any MCP client library can drive the server (`witness-log-mcp`, or
`python -m witness_log.mcp_server`, from `pip install "witness-log[mcp]"`)
over stdio. Its eleven tools cover logging, proofs, redaction, export,
witnessing and verification; your code never touches the format.

**TypeScript with the SDK directly (Vercel AI SDK / LangChain.js / Mastra / custom):**

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({
  command: "uvx",
  args: ["--from", "witness-log[mcp]", "witness-log-mcp"],
  env: { ...process.env, WITNESS_LOG_HOME: "/var/lib/witness-log" },
});
const wl = new Client({ name: "my-agent", version: "1.0.0" });
await wl.connect(transport);
await wl.callTool({ name: "initialize_witness_chain", arguments: { session_id: "orders-bot" } });

// before the tool call: the intent
const i = await wl.callTool({ name: "append_audit_step", arguments: {
  session_id: "orders-bot", intent: "refund order 1042", tool_name: "stripe.refund",
  payload: { order: 1042, amount: 250 } } });
// after it: the result, bound to the intent's index
await wl.callTool({ name: "record_result", arguments: {
  session_id: "orders-bot", intent_index: i.structuredContent.result.intent_index,
  tool_name: "stripe.refund", value: { refunded: true } } });
```

Vercel AI SDK users can also expose the server's tools directly to the
model with `experimental_createMCPClient` and instruct it to record steps.

## Route 2: the CLI (any language, no Python)

Write the dossier yourself and verify with the binary. The dossier is
plain JSON (`spec/dossier.schema.json`); the leaf encoding and hashes are
specified in `spec/SPEC.md` with test vectors in `corpus/`. For
*verification only* you need nothing but the binary:

```go
cmd := exec.Command("witness-log", "verify", "dossier.json",
    "--identity", key, "--directory", "trusted.json", "--min-witnesses", "2", "--json")
out, _ := cmd.Output()   // err is non-nil for any non-zero exit; the exit code is the verdict
switch cmd.ProcessState.ExitCode() { case 0: /* WITNESSED */ case 10, 20: /* not enough */ case 30: /* refuse */ default: /* 2: usage */ }
```

Producing dossiers from another language means implementing §2–§6 of the
spec (SHA-256, Ed25519, length-prefixed fields). `witness-log conform
<your-corpus-dir> --reference <checkout>/corpus` tells you the moment you
match byte for byte (`--reference` defaults to `./corpus`, so it can be
omitted when run from a checkout). The reference generator is
`crates/witness-log-core/examples/generate_corpus.rs`.

## Route 3 (roadmap): native packages

`@witness-log/core` (napi-rs, same Rust core) and a Go module are the
next bindings; the C ABI they share is tracked in the roadmap. If you need
one, say so in Discussions: demand decides order.
