import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateText, tool, stepCountIs } from "ai";
import { MockLanguageModelV2 } from "ai/test";
import { z } from "zod";
import { openLog, verifyDossier, verifyDossierNative, witnessTools } from "@witness-log/ai-sdk";

test("tool calls become intent/result leaves and the dossier verifies", async () => {
  const log = openLog(join(mkdtempSync(join(tmpdir(), "wl-")), "agent.jsonl"), { storePayloads: true });
  const usage = { inputTokens: 1, outputTokens: 1, totalTokens: 2 };
  const model = new MockLanguageModelV2({
    doGenerate: [
      {
        content: [{ type: "tool-call", toolCallId: "c1", toolName: "weather", input: '{"city":"Oslo"}' }],
        finishReason: "tool-calls",
        usage,
        warnings: [],
      },
      { content: [{ type: "text", text: "21C" }], finishReason: "stop", usage, warnings: [] },
    ],
  });
  const tools = witnessTools(
    { weather: tool({ inputSchema: z.object({ city: z.string() }), execute: async () => ({ tempC: 21 }) }) },
    log,
  );
  const r = await generateText({ model, tools, prompt: "weather?", stopWhen: stepCountIs(3) });
  assert.equal(r.text, "21C");
  assert.deepEqual(
    log.leaves().map((l) => l.leaf_type),
    [1, 2],
  );
  const intent = JSON.parse(new TextDecoder().decode(log.disclose(0).payload));
  assert.deepEqual(intent.input, { city: "Oslo" });

  const dossier = log.exportDossier();
  assert.equal(verifyDossier(dossier, { identity: log.identityPubkey }).verdict, "UNANCHORED");
  assert.equal(verifyDossierNative(dossier, { identity: log.identityPubkey }).verdict, "UNANCHORED");
  const tampered = structuredClone(dossier);
  tampered.leaves[0].payload_hash = "00".repeat(32);
  assert.equal(verifyDossier(tampered).verdict, "DIVERGED");
  log.close();
});
