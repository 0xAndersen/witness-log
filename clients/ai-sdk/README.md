# @witness-log/ai-sdk

[witness-log](https://github.com/0xAndersen/witness-log) for the
[Vercel AI SDK](https://ai-sdk.dev) v5: record what an agent intended and
what happened, in an append-only Merkle log that independent witnesses can
cosign and anyone can verify offline.

```sh
npm install @witness-log/ai-sdk ai
```

Depends on `@witness-log/node` (prebuilt native addon, no Rust toolchain).
Peer dependencies: `ai ^5`, `@ai-sdk/provider ^2`; `@opentelemetry/api`
only if you use the telemetry exporter. Node 20+, ESM with types.

## Three places to hook in

Pick the one that matches where you want the record made. All three write
JSON payloads with a `profile` field (`ai-sdk.tool-call/1`,
`ai-sdk.tool-result/1`, ...), so a reader knows what each leaf is.

### `witnessTools(tools, log)`: around each tool's `execute`

An intent leaf before the tool runs (name, tool call id, input), a result
leaf after (output, or the error). Fail-closed: if the intent cannot be
committed the tool does not run. Streaming tools (`AsyncIterable` outputs)
get their result leaf on completion. Tools without `execute` pass through.

```ts
import { generateText, tool } from "ai";
import { openLog, witnessTools } from "@witness-log/ai-sdk";

const log = openLog("agent.jsonl", { storePayloads: true });

const tools = witnessTools(
  {
    weather: tool({
      inputSchema: z.object({ city: z.string() }),
      execute: async ({ city }) => fetchWeather(city),
    }),
  },
  log,
  { redactInput: (name, input) => input, recordOutputs: true },
);

const result = await generateText({ model, tools, prompt: "Weather in Oslo?" });
const dossier = log.exportDossier();
```

### `witnessMiddleware(log)`: at the model boundary

A `LanguageModelV2Middleware` for `wrapLanguageModel`. Every tool call the
model emits becomes an intent leaf (including provider-executed tools and
tools you did not write), the tool results that come back in the next
call's prompt become result leaves, and each generation adds a memory leaf
(model, finish reason, usage; `recordText: true` adds the text). Covers
`generateText` and `streamText`.

```ts
import { wrapLanguageModel } from "ai";
import { witnessMiddleware } from "@witness-log/ai-sdk";

const model = wrapLanguageModel({ model: openai("gpt-4o"), middleware: witnessMiddleware(log) });
```

### `witnessTelemetry(log)`: an OpenTelemetry span exporter

The AI SDK's `experimental_telemetry` emits spans; this exporter turns
`ai.toolCall` spans into an intent and a result leaf and
`ai.generateText` / `ai.streamText` / `ai.generateObject` /
`ai.streamObject` spans into a memory leaf (operation, function id, model,
finish reason, token usage, trace and span ids). Use it when telemetry is
already wired and you want the log to follow it.

```ts
import { BasicTracerProvider, SimpleSpanProcessor } from "@opentelemetry/sdk-trace-base";
import { witnessTelemetry } from "@witness-log/ai-sdk";

const provider = new BasicTracerProvider({ spanProcessors: [new SimpleSpanProcessor(witnessTelemetry(log))] });
await generateText({
  model,
  tools,
  prompt,
  experimental_telemetry: { isEnabled: true, tracer: provider.getTracer("my-agent"), functionId: "orders" },
});
await provider.forceFlush();
```

Other instrumentations sharing the provider are recorded too, when they
follow the OpenTelemetry GenAI semantic conventions (`gen_ai.*`) or
OpenInference (Mastra, LangChain.js and the OpenInference instrumentors):
an `execute_tool` / `TOOL` span becomes an intent and a result leaf, a
`chat`, `generate_content`, `text_completion`, `invoke_agent` or
`invoke_workflow` / `LLM`, `AGENT` span one memory leaf (model, provider,
agent, token usage, outcome; prompts and completions only with
`recordPrompt` / `recordText`). The payloads have the shape the Python
`witness_log.integrations.otel.WitnessLogSpanProcessor` writes, and the AI
SDK's own `ai.*` spans are never recorded twice.

## Then

`log.exportDossier()` is the verifiable record; `verifyDossier(dossier)`
(pure TypeScript) and `verifyDossierNative(dossier)` (the Rust reference
verifier) are re-exported from `@witness-log/node`. `await
log.submit("trusted.json", { min: 2 })` gets the head cosigned by witnesses
you trust, which is what turns `UNANCHORED` into `WITNESSED`. See the
[`@witness-log/node` README](../node/README.md) and the
[TypeScript quickstart](../../docs/wiki/Quickstart-TypeScript.md).

## Tests

`npm test` runs against the real `ai` package with `MockLanguageModelV2`
from `ai/test` (two-step tool call, errors, redaction, streaming tools,
middleware over `generateText` and `streamText`, the telemetry exporter
through a `BasicTracerProvider`), and checks every resulting dossier with
both verifiers.

## License

Apache-2.0.
