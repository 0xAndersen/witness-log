# Other languages: TypeScript, Go, Java, anything

Native bindings exist for Rust and Python. Everyone else has two routes
today, both complete, and a third on the [Roadmap](Roadmap).

## Route 1: MCP (recommended for agent frameworks)

Any MCP client library can drive `integrations/mcp/witness_mcp_server.py`
over stdio. The seven tools cover logging, proofs, redaction, export,
witnessing and verification; your code never touches the format.

**TypeScript (Vercel AI SDK / LangChain.js / Mastra / custom):**

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({
  command: "uv",
  args: ["run", "--with", "mcp>=2", "--with", "witness-log", "/path/witness_mcp_server.py"],
  env: { ...process.env, WITNESS_LOG_HOME: "/var/lib/witness-log" },
});
const wl = new Client({ name: "my-agent", version: "1.0.0" });
await wl.connect(transport);
await wl.callTool({ name: "initialize_witness_chain", arguments: { session_id: "orders-bot" } });

// around every tool call:
const r = await wl.callTool({ name: "append_audit_step", arguments: {
  session_id: "orders-bot", intent: "refund order 1042", tool_name: "stripe.refund",
  payload: { order: 1042, amount: 250 }, state_transition: { refunded: true } } });
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
    "--identity", key, "--directory", "trusted.json", "--min-witnesses", "3", "--json")
out, err := cmd.Output()
switch cmd.ProcessState.ExitCode() { case 0: /* WITNESSED */ case 10, 20: /* not enough */ case 30: /* refuse */ }
```

Producing dossiers from another language means implementing §2–§6 of the
spec (SHA-256, Ed25519, length-prefixed fields). `witness-log conform
<your-corpus-dir>` tells you the moment you match byte for byte. The
reference generator is `crates/witness-log-core/examples/generate_corpus.rs`.

## Route 3 (roadmap): native packages

`@witness-log/core` (napi-rs, same Rust core) and a Go module are the
next bindings; the C ABI they share is tracked in the roadmap. If you need
one, say so in Discussions: demand decides order.
