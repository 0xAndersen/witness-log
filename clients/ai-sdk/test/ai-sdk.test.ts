/**
 * Against the real `ai` package (v5) with `MockLanguageModelV2` from
 * `ai/test`: no network, no provider keys.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { generateText, streamText, tool, wrapLanguageModel, stepCountIs, simulateReadableStream } from "ai";
import { MockLanguageModelV2 } from "ai/test";
import { z } from "zod";
import { BasicTracerProvider, SimpleSpanProcessor } from "@opentelemetry/sdk-trace-base";

import { openLog, tempJournalPath, verifyDossier, verifyDossierNative, type Log } from "@witness-log/node";
import { witnessTools, witnessMiddleware, witnessTelemetry } from "../src/index.js";

const usage = { inputTokens: 10, outputTokens: 5, totalTokens: 15 };

/** A model that calls `weather` once, then answers. */
function twoStepModel() {
  return new MockLanguageModelV2({
    modelId: "mock-model",
    doGenerate: [
      {
        content: [{ type: "tool-call", toolCallId: "call-1", toolName: "weather", input: JSON.stringify({ city: "Oslo" }) }],
        finishReason: "tool-calls",
        usage,
        warnings: [],
      },
      {
        content: [{ type: "text", text: "It is 21C in Oslo." }],
        finishReason: "stop",
        usage,
        warnings: [],
      },
    ],
  });
}

function payloads(log: Log) {
  return log.leaves().map((l, i) => {
    const d = log.disclose(i);
    return { type: l.leaf_type, body: d?.payload ? (JSON.parse(new TextDecoder().decode(d.payload)) as Record<string, unknown>) : null };
  });
}

function assertVerifies(log: Log) {
  const d = log.exportDossier();
  const ts = verifyDossier(d, { identity: log.identityPubkey });
  const rs = verifyDossierNative(d, { identity: log.identityPubkey });
  assert.equal(ts.verdict, "UNANCHORED", ts.failures.join("; "));
  assert.equal(rs.verdict, "UNANCHORED");
}

describe("witnessTools", () => {
  it("records an intent before and a result after each tool call", async () => {
    const log = openLog(tempJournalPath(), { storePayloads: true });
    const seen: string[] = [];
    const tools = witnessTools(
      {
        weather: tool({
          description: "Weather for a city",
          inputSchema: z.object({ city: z.string() }),
          execute: async ({ city }) => {
            seen.push(`run:${log.treeSize}`); // the intent leaf exists before the tool runs
            return { city, tempC: 21 };
          },
        }),
      },
      log,
      { onLeaf: (_i, kind) => seen.push(kind) },
    );
    const result = await generateText({ model: twoStepModel(), tools, prompt: "Weather in Oslo?", stopWhen: stepCountIs(3) });
    assert.equal(result.text, "It is 21C in Oslo.");
    assert.deepEqual(seen, ["intent", "run:1", "result"]);
    const p = payloads(log);
    assert.equal(p.length, 2);
    assert.equal(p[0].type, 1);
    assert.deepEqual(p[0].body, { profile: "ai-sdk.tool-call/1", tool: "weather", tool_call_id: "call-1", input: { city: "Oslo" } });
    assert.equal(p[1].type, 2);
    assert.deepEqual(p[1].body, {
      profile: "ai-sdk.tool-result/1",
      tool: "weather",
      tool_call_id: "call-1",
      intent_index: 0,
      outcome: "ok",
      output: { city: "Oslo", tempC: 21 },
    });
    assertVerifies(log);
    log.close();
  });

  it("records errors as error results and leaves the SDK's behaviour alone", async () => {
    const log = openLog(tempJournalPath(), { storePayloads: true });
    const tools = witnessTools(
      {
        weather: tool({
          inputSchema: z.object({ city: z.string() }),
          execute: async (): Promise<{ tempC: number }> => {
            throw new Error("upstream down");
          },
        }),
      },
      log,
    );
    const result = await generateText({ model: twoStepModel(), tools, prompt: "Weather?", stopWhen: stepCountIs(3) });
    const toolErrors = result.steps[0].content.filter((c) => c.type === "tool-error");
    assert.equal(toolErrors.length, 1);
    const p = payloads(log);
    assert.equal(p[1].body?.outcome, "error");
    assert.match(String(p[1].body?.error), /Error: upstream down/);
    assert.equal("output" in (p[1].body ?? {}), false);
    log.close();
  });

  it("redacts inputs and can skip outputs; tools without execute pass through", async () => {
    const log = openLog(tempJournalPath(), { storePayloads: true });
    const clientSide = tool({ inputSchema: z.object({ q: z.string() }) });
    const tools = witnessTools(
      {
        weather: tool({
          inputSchema: z.object({ city: z.string() }),
          execute: async () => ({ secret: "do not record" }),
        }),
        clientSide,
      },
      log,
      { recordOutputs: false, redactInput: (_t, input) => ({ ...(input as object), city: "[redacted]" }) },
    );
    assert.equal(tools.clientSide, clientSide);
    await generateText({ model: twoStepModel(), tools, prompt: "x", stopWhen: stepCountIs(3) });
    const p = payloads(log);
    assert.deepEqual(p[0].body?.input, { city: "[redacted]" });
    assert.equal("output" in (p[1].body ?? {}), false);
    assert.equal(p[1].body?.outcome, "ok");
    log.close();
  });

  it("supports streaming tool outputs (AsyncIterable)", async () => {
    const log = openLog(tempJournalPath(), { storePayloads: true });
    const tools = witnessTools(
      {
        weather: {
          inputSchema: z.object({ city: z.string() }),
          async *execute() {
            yield { stage: "looking" };
            yield { stage: "done", tempC: 21 };
          },
        },
      },
      log,
    );
    const t = tools.weather as { execute: (i: unknown, o: unknown) => AsyncIterable<unknown> };
    const got: unknown[] = [];
    for await (const v of t.execute({ city: "Oslo" }, { toolCallId: "s-1" })) got.push(v);
    assert.equal(got.length, 2);
    const p = payloads(log);
    assert.equal(p.length, 2);
    assert.deepEqual(p[1].body?.output, { stage: "done", tempC: 21 });
    log.close();
  });
});

describe("witnessMiddleware", () => {
  it("records model tool calls, the results that come back, and each generation", async () => {
    const log = openLog(tempJournalPath(), { storePayloads: true });
    const model = wrapLanguageModel({ model: twoStepModel(), middleware: witnessMiddleware(log, { recordText: true }) });
    const result = await generateText({
      model,
      tools: { weather: tool({ inputSchema: z.object({ city: z.string() }), execute: async ({ city }) => ({ city, tempC: 21 }) }) },
      prompt: "Weather in Oslo?",
      stopWhen: stepCountIs(3),
    });
    assert.equal(result.text, "It is 21C in Oslo.");
    const p = payloads(log);
    assert.deepEqual(
      p.map((x) => [x.type, x.body?.profile]),
      [
        [1, "ai-sdk.model-tool-call/1"],
        [0, "ai-sdk.generation/1"],
        [2, "ai-sdk.model-tool-result/1"],
        [0, "ai-sdk.generation/1"],
      ],
    );
    assert.deepEqual(p[0].body?.input, { city: "Oslo" });
    assert.equal(p[0].body?.model, "mock-model");
    assert.equal(p[2].body?.intent_index, 0);
    assert.deepEqual(p[2].body?.output, { city: "Oslo", tempC: 21 });
    assert.equal(p[2].body?.outcome, "ok");
    assert.equal(p[1].body?.finish_reason, "tool-calls");
    assert.equal(p[3].body?.text, "It is 21C in Oslo.");
    assertVerifies(log);
    log.close();
  });

  it("records tool calls and the finish of a stream", async () => {
    const log = openLog(tempJournalPath(), { storePayloads: true });
    const base = new MockLanguageModelV2({
      modelId: "mock-stream",
      doStream: async () => ({
        stream: simulateReadableStream({
          chunks: [
            { type: "stream-start", warnings: [] },
            { type: "text-start", id: "t1" },
            { type: "text-delta", id: "t1", delta: "Checking " },
            { type: "text-delta", id: "t1", delta: "now." },
            { type: "text-end", id: "t1" },
            { type: "tool-call", toolCallId: "call-9", toolName: "weather", input: JSON.stringify({ city: "Bergen" }) },
            { type: "finish", finishReason: "tool-calls", usage },
          ],
        }),
      }),
    });
    const model = wrapLanguageModel({ model: base, middleware: witnessMiddleware(log, { recordText: true }) });
    const result = streamText({ model, prompt: "Weather in Bergen?" });
    let text = "";
    for await (const chunk of result.textStream) text += chunk;
    assert.equal(text, "Checking now.");
    const p = payloads(log);
    assert.deepEqual(
      p.map((x) => [x.type, x.body?.profile]),
      [
        [1, "ai-sdk.model-tool-call/1"],
        [0, "ai-sdk.generation/1"],
      ],
    );
    assert.deepEqual(p[0].body?.input, { city: "Bergen" });
    assert.equal(p[1].body?.mode, "stream");
    assert.equal(p[1].body?.text, "Checking now.");
    assertVerifies(log);
    log.close();
  });
});

describe("witnessTelemetry", () => {
  it("turns ai.toolCall and ai.generateText spans into leaves", async () => {
    const log = openLog(tempJournalPath(), { storePayloads: true });
    const provider = new BasicTracerProvider({ spanProcessors: [new SimpleSpanProcessor(witnessTelemetry(log, { recordText: true }))] });
    const tracer = provider.getTracer("witness-log-test");
    const result = await generateText({
      model: twoStepModel(),
      tools: { weather: tool({ inputSchema: z.object({ city: z.string() }), execute: async ({ city }) => ({ city, tempC: 21 }) }) },
      prompt: "Weather in Oslo?",
      stopWhen: stepCountIs(3),
      experimental_telemetry: { isEnabled: true, tracer, functionId: "weather-agent" },
    });
    await provider.forceFlush();
    assert.equal(result.text, "It is 21C in Oslo.");
    const p = payloads(log);
    assert.deepEqual(
      p.map((x) => [x.type, x.body?.profile]),
      [
        [1, "ai-sdk.telemetry.tool-call/1"],
        [2, "ai-sdk.telemetry.tool-result/1"],
        [0, "ai-sdk.telemetry.generation/1"],
      ],
    );
    assert.equal(p[0].body?.tool, "weather");
    assert.deepEqual(p[0].body?.input, { city: "Oslo" });
    assert.deepEqual(p[1].body?.output, { city: "Oslo", tempC: 21 });
    assert.equal(p[1].body?.intent_index, 0);
    assert.equal(p[2].body?.function_id, "weather-agent");
    assert.equal(p[2].body?.model, "mock-model");
    assert.equal(p[2].body?.text, "It is 21C in Oslo.");
    assert.equal(typeof p[2].body?.trace_id, "string");
    assertVerifies(log);
    await provider.shutdown();
    log.close();
  });
});
