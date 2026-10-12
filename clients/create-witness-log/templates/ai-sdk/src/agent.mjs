// A Vercel AI SDK agent with a witness-log audit trail.
//
// `witnessTools` wraps each tool so every call is an intent leaf before it
// runs and a result leaf after. This example runs against a mock model so
// it works with no API key; swap `model` for a real provider when ready.
import { writeFileSync } from "node:fs";
import { generateText, tool, stepCountIs } from "ai";
import { MockLanguageModelV2 } from "ai/test";
import { z } from "zod";
import { openLog, verifyDossier, verifyDossierNative, witnessTools } from "@witness-log/ai-sdk";

const JOURNAL = process.env.WITNESS_LOG_JOURNAL ?? "agent.jsonl";
const log = openLog(JOURNAL, { storePayloads: true });
console.log(`log ${log.identityPubkey} at ${log.path}, ${log.treeSize} leaves so far`);

// Replace with e.g. `openai("gpt-4o")` from @ai-sdk/openai. The mock calls
// `weather` once, then answers.
const usage = { inputTokens: 10, outputTokens: 5, totalTokens: 15 };
const model = new MockLanguageModelV2({
  modelId: "mock-model",
  doGenerate: [
    {
      content: [{ type: "tool-call", toolCallId: "call-1", toolName: "weather", input: JSON.stringify({ city: "Oslo" }) }],
      finishReason: "tool-calls",
      usage,
      warnings: [],
    },
    { content: [{ type: "text", text: "It is 21C and clear in Oslo." }], finishReason: "stop", usage, warnings: [] },
  ],
});

const tools = witnessTools(
  {
    weather: tool({
      description: "Current weather for a city",
      inputSchema: z.object({ city: z.string() }),
      execute: async ({ city }) => ({ city, tempC: 21, sky: "clear" }),
    }),
  },
  log,
);

const result = await generateText({ model, tools, prompt: "What is the weather in Oslo?", stopWhen: stepCountIs(3) });
console.log("model ->", result.text);

const dossier = log.exportDossier();
writeFileSync("dossier.json", JSON.stringify(dossier, null, 2));
console.log(`wrote dossier.json: ${dossier.leaves.length} leaves (intent + result per tool call)`);

const ts = verifyDossier(dossier, { identity: log.identityPubkey });
const rs = verifyDossierNative(dossier, { identity: log.identityPubkey });
console.log(`verdict: ${ts.verdict} (TypeScript) / ${rs.verdict} (Rust)`);
console.log("UNANCHORED means internally consistent but not yet cosigned by witnesses you trust. See README.md.");

log.close();
