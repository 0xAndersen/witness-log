/**
 * `@witness-log/ai-sdk`: witness-log for the Vercel AI SDK (v5).
 *
 * Three ways in, pick the one that matches where you want the record made:
 *
 * - `witnessTools(tools, log)` wraps each tool's `execute`: an intent leaf
 *   before the tool runs, a result leaf after. Fail-closed: if the intent
 *   cannot be committed, the tool does not run.
 * - `witnessMiddleware(log)` is a `LanguageModelV2Middleware`: records every
 *   tool call the model emits (intent) and every tool result that comes back
 *   in the next prompt (result), plus one memory leaf per generation. Works
 *   with provider-executed tools and with tools you did not write.
 * - `witnessTelemetry(log)` is an OpenTelemetry `SpanExporter` for the AI
 *   SDK's `experimental_telemetry`: `ai.toolCall` spans become intent and
 *   result leaves, `ai.generateText`/`ai.streamText` spans a memory leaf.
 *
 * Payloads are JSON objects with a `profile` field so a reader knows what
 * it is looking at. witness-log never stores them; the log holds salted
 * commitments. Keep the payloads yourself if you need to prove them later
 * (`openLog(path, { storePayloads: true })`).
 */
import type { Log } from "@witness-log/node";
import type { LanguageModelV2Middleware, LanguageModelV2StreamPart } from "@ai-sdk/provider";

export { openLog, verifyDossier, verifyDossierNative, type Log } from "@witness-log/node";

// ------------------------------------------------------------------ tools

/** The parts of an AI SDK tool this package touches; the real `Tool` type is far wider. */
interface ToolLike {
  execute?: (input: unknown, options: ToolCallOptionsLike) => unknown;
  [k: string]: unknown;
}

interface ToolCallOptionsLike {
  toolCallId?: string;
  abortSignal?: AbortSignal;
  [k: string]: unknown;
}

export interface WitnessToolsOptions {
  /** Record tool outputs in the result leaf. Default true. Set false for large or sensitive outputs (the leaf then carries only the outcome). */
  recordOutputs?: boolean;
  /** Transform a tool's input before it is recorded (drop secrets, truncate). Default: record as is. */
  redactInput?: (toolName: string, input: unknown) => unknown;
  /** Transform a tool's output before it is recorded. */
  redactOutput?: (toolName: string, output: unknown) => unknown;
  /** Called after each leaf is appended. */
  onLeaf?: (index: number, kind: "intent" | "result") => void;
}

/**
 * Wrap every tool's `execute` so that each call appends an intent leaf
 * before it runs and a result leaf after (outcome "ok" or "error"). Tools
 * without `execute` (client-side or provider-executed) are passed through.
 * Tools that stream (`AsyncIterable` outputs) get their result leaf when
 * the iteration completes, with the last value.
 */
export function witnessTools<T extends Record<string, unknown>>(tools: T, log: Log, opts: WitnessToolsOptions = {}): T {
  const out: Record<string, unknown> = {};
  for (const [name, t] of Object.entries(tools)) {
    const tool = t as ToolLike;
    if (typeof tool.execute !== "function") {
      out[name] = tool;
      continue;
    }
    const original = tool.execute;
    out[name] = {
      ...tool,
      execute: (input: unknown, options: ToolCallOptionsLike) => executeWitnessed(log, name, original, input, options, opts),
    };
  }
  return out as T;
}

function executeWitnessed(
  log: Log,
  name: string,
  original: NonNullable<ToolLike["execute"]>,
  input: unknown,
  options: ToolCallOptionsLike,
  opts: WitnessToolsOptions,
): unknown {
  const toolCallId = options?.toolCallId ?? null;
  // Fail closed: an intent that cannot be committed means the tool does not run.
  const intentIndex = log.appendIntent({
    profile: "ai-sdk.tool-call/1",
    tool: name,
    tool_call_id: toolCallId,
    input: opts.redactInput ? opts.redactInput(name, input) : jsonSafe(input),
  });
  opts.onLeaf?.(intentIndex, "intent");

  const record = (outcome: "ok" | "error", value: unknown) => {
    const payload: Record<string, unknown> = {
      profile: "ai-sdk.tool-result/1",
      tool: name,
      tool_call_id: toolCallId,
      intent_index: intentIndex,
      outcome,
    };
    if (outcome === "error") payload.error = value;
    else if (opts.recordOutputs !== false) payload.output = opts.redactOutput ? opts.redactOutput(name, value) : jsonSafe(value);
    const i = log.appendResult(payload);
    opts.onLeaf?.(i, "result");
  };

  let result: unknown;
  try {
    result = original(input, options);
  } catch (e) {
    record("error", errorString(e));
    throw e;
  }
  if (isAsyncIterable(result)) {
    const source = result;
    return (async function* () {
      let last: unknown;
      try {
        for await (const v of source) {
          last = v;
          yield v;
        }
      } catch (e) {
        record("error", errorString(e));
        throw e;
      }
      record("ok", last);
    })();
  }
  if (isPromiseLike(result)) {
    return Promise.resolve(result).then(
      (v) => {
        record("ok", v);
        return v;
      },
      (e: unknown) => {
        record("error", errorString(e));
        throw e;
      },
    );
  }
  record("ok", result);
  return result;
}

// ------------------------------------------------------------- middleware

export interface WitnessMiddlewareOptions {
  /** Record the model's text output in the per-generation memory leaf. Default false. */
  recordText?: boolean;
  /** Record tool outputs seen in prompts. Default true. */
  recordOutputs?: boolean;
  /** Also record one memory leaf per generation (model, finish reason, usage). Default true. */
  recordGenerations?: boolean;
}

/**
 * A `LanguageModelV2Middleware` for `wrapLanguageModel({ model, middleware })`.
 * Every tool call the model emits becomes an intent leaf (including
 * provider-executed ones); the tool results that come back in the next
 * call's prompt become result leaves (once per tool call id); each
 * generation adds a memory leaf. `wrapGenerate` and `wrapStream` are both
 * covered.
 */
export function witnessMiddleware(log: Log, opts: WitnessMiddlewareOptions = {}): LanguageModelV2Middleware {
  const seenResults = new Set<string>();
  const intentByCall = new Map<string, number>();

  const recordPromptResults = (prompt: unknown) => {
    if (!Array.isArray(prompt)) return;
    for (const msg of prompt as Array<{ role?: string; content?: unknown }>) {
      if (msg?.role !== "tool" || !Array.isArray(msg.content)) continue;
      for (const part of msg.content as Array<Record<string, unknown>>) {
        if (part?.type !== "tool-result" || typeof part.toolCallId !== "string") continue;
        if (seenResults.has(part.toolCallId)) continue;
        seenResults.add(part.toolCallId);
        const output = part.output as { type?: string; value?: unknown } | undefined;
        const isError = output?.type === "error-text" || output?.type === "error-json";
        const payload: Record<string, unknown> = {
          profile: "ai-sdk.model-tool-result/1",
          tool: part.toolName,
          tool_call_id: part.toolCallId,
          intent_index: intentByCall.get(part.toolCallId) ?? null,
          outcome: isError ? "error" : "ok",
        };
        if (isError) payload.error = jsonSafe(output?.value);
        else if (opts.recordOutputs !== false) payload.output = jsonSafe(output?.value ?? null);
        log.appendResult(payload);
      }
    }
  };

  const recordToolCall = (modelId: string, part: { toolCallId: string; toolName: string; input: string; providerExecuted?: boolean }) => {
    const i = log.appendIntent({
      profile: "ai-sdk.model-tool-call/1",
      model: modelId,
      tool: part.toolName,
      tool_call_id: part.toolCallId,
      input: parseJson(part.input),
      provider_executed: part.providerExecuted === true,
    });
    intentByCall.set(part.toolCallId, i);
  };

  const recordGeneration = (modelId: string, finishReason: unknown, usage: unknown, text: string | undefined, mode: "generate" | "stream") => {
    if (opts.recordGenerations === false) return;
    const payload: Record<string, unknown> = {
      profile: "ai-sdk.generation/1",
      model: modelId,
      mode,
      finish_reason: finishReason ?? null,
      usage: jsonSafe(usage ?? null),
    };
    if (opts.recordText && text !== undefined) payload.text = text;
    log.appendMemory(payload);
  };

  return {
    middlewareVersion: "v2",
    wrapGenerate: async ({ doGenerate, params, model }) => {
      recordPromptResults(params.prompt);
      const result = await doGenerate();
      let text = "";
      for (const part of result.content) {
        if (part.type === "tool-call") recordToolCall(model.modelId, part);
        if (part.type === "text") text += part.text;
      }
      recordGeneration(model.modelId, result.finishReason, result.usage, text, "generate");
      return result;
    },
    wrapStream: async ({ doStream, params, model }) => {
      recordPromptResults(params.prompt);
      const { stream, ...rest } = await doStream();
      let text = "";
      const tap = new TransformStream<LanguageModelV2StreamPart, LanguageModelV2StreamPart>({
        transform(part, controller) {
          if (part.type === "tool-call") recordToolCall(model.modelId, part);
          else if (part.type === "text-delta") text += part.delta;
          else if (part.type === "finish") recordGeneration(model.modelId, part.finishReason, part.usage, text, "stream");
          controller.enqueue(part);
        },
      });
      return { stream: stream.pipeThrough(tap), ...rest };
    },
  };
}

// -------------------------------------------------------------- telemetry

/** The slice of an OpenTelemetry `ReadableSpan` this exporter reads (structural, so `@opentelemetry/sdk-trace-base` is not a dependency). */
export interface SpanLike {
  name: string;
  attributes: Record<string, unknown>;
  status?: { code: number; message?: string };
  spanContext(): { traceId: string; spanId: string };
  parentSpanContext?: { spanId: string } | undefined;
  parentSpanId?: string;
}

export interface ExportResultLike {
  code: number;
  error?: Error;
}

export interface WitnessTelemetryOptions {
  /** Record `ai.response.text` in generation leaves. Default false. */
  recordText?: boolean;
  /** Record `ai.toolCall.result` in tool result leaves. Default true. */
  recordOutputs?: boolean;
  /** Record `ai.prompt` in generation leaves. Default false. */
  recordPrompt?: boolean;
}

const GENERATION_SPANS = new Set(["ai.generateText", "ai.streamText", "ai.generateObject", "ai.streamObject"]);
/** `gen_ai.operation.name` values recorded as one call leaf each. */
const GEN_AI_CALLS = new Set(["chat", "generate_content", "text_completion", "invoke_agent", "invoke_workflow"]);

/**
 * An OpenTelemetry `SpanExporter` that turns the AI SDK's telemetry into
 * leaves: each `ai.toolCall` span is an intent leaf and a result leaf,
 * each top-level `ai.generateText`/`ai.streamText`/`ai.generateObject`/
 * `ai.streamObject` span a memory leaf. Wire it with a `SimpleSpanProcessor`
 * and pass the provider's tracer as `experimental_telemetry.tracer`.
 *
 * Spans from other instrumentations in the same provider are recorded too
 * when they follow the OpenTelemetry GenAI conventions or OpenInference:
 * `execute_tool` / `TOOL` spans as an intent and a result leaf, `chat`,
 * `generate_content`, `text_completion`, `invoke_agent`, `invoke_workflow`
 * / `LLM`, `AGENT` spans as one memory leaf (prompts and completions only
 * with `recordPrompt` / `recordText`).
 */
export class WitnessLogSpanExporter {
  constructor(
    readonly log: Log,
    readonly options: WitnessTelemetryOptions = {},
  ) {}

  export(spans: SpanLike[], resultCallback: (result: ExportResultLike) => void): void {
    try {
      for (const span of spans) this.record(span);
      resultCallback({ code: 0 });
    } catch (e) {
      resultCallback({ code: 1, error: e instanceof Error ? e : new Error(String(e)) });
    }
  }

  record(span: SpanLike): void {
    const a = span.attributes ?? {};
    const ctx = span.spanContext();
    if (span.name === "ai.toolCall") {
      const tool = str(a["ai.toolCall.name"]);
      const toolCallId = str(a["ai.toolCall.id"]);
      const intentIndex = this.log.appendIntent({
        profile: "ai-sdk.telemetry.tool-call/1",
        tool,
        tool_call_id: toolCallId,
        input: parseJson(a["ai.toolCall.args"]),
        trace_id: ctx.traceId,
        span_id: ctx.spanId,
      });
      const failed = span.status?.code === 2; // SpanStatusCode.ERROR
      const payload: Record<string, unknown> = {
        profile: "ai-sdk.telemetry.tool-result/1",
        tool,
        tool_call_id: toolCallId,
        intent_index: intentIndex,
        outcome: failed ? "error" : "ok",
        trace_id: ctx.traceId,
        span_id: ctx.spanId,
      };
      if (failed) payload.error = span.status?.message ?? "error";
      else if (this.options.recordOutputs !== false) payload.output = parseJson(a["ai.toolCall.result"]);
      this.log.appendResult(payload);
      return;
    }
    if (GENERATION_SPANS.has(span.name)) {
      const payload: Record<string, unknown> = {
        profile: "ai-sdk.telemetry.generation/1",
        operation: str(a["operation.name"]) ?? span.name,
        function_id: str(a["ai.telemetry.functionId"]),
        model: str(a["ai.model.id"]),
        provider: str(a["ai.model.provider"]),
        finish_reason: str(a["ai.response.finishReason"]),
        usage: {
          input_tokens: num(a["ai.usage.inputTokens"]),
          output_tokens: num(a["ai.usage.outputTokens"]),
        },
        trace_id: ctx.traceId,
        span_id: ctx.spanId,
      };
      if (this.options.recordText) payload.text = str(a["ai.response.text"]);
      if (this.options.recordPrompt) payload.prompt = parseJson(a["ai.prompt"]);
      this.log.appendMemory(payload);
      return;
    }
    // Spans from any other instrumentation that follows the OpenTelemetry
    // GenAI conventions (gen_ai.*) or OpenInference (Mastra, LangChain.js,
    // OpenInference instrumentors), in the shape the Python
    // `witness_log.integrations.otel` processor writes. The AI SDK's own
    // `ai.*` spans are handled above and never twice.
    if (span.name.startsWith("ai.")) return;
    const op = str(a["gen_ai.operation.name"]);
    const oi = str(a["openinference.span.kind"]);
    const ids = { trace_id: ctx.traceId, span_id: ctx.spanId, parent_span_id: parentSpanId(span) };
    const failed = span.status?.code === 2; // SpanStatusCode.ERROR
    if (op === "execute_tool" || oi === "TOOL") {
      const tool = str(a["gen_ai.tool.name"]) ?? str(a["tool.name"]) ?? span.name.replace(/^execute_tool /, "");
      const toolCallId = str(a["gen_ai.tool.call.id"]);
      const rawArgs = a["gen_ai.tool.call.arguments"] ?? a["tool.parameters"] ?? a["input.value"];
      const intentIndex = this.log.appendIntent({
        tool,
        args: rawArgs === undefined ? null : parseJson(rawArgs),
        source: "otel",
        tool_call_id: toolCallId,
        ...ids,
      });
      const payload: Record<string, unknown> = { tool, intent_index: intentIndex, outcome: failed ? "error" : "ok", source: "otel", tool_call_id: toolCallId, ...ids };
      if (failed) payload.value = span.status?.message ?? "error";
      else if (this.options.recordOutputs !== false) {
        const out = a["gen_ai.tool.call.result"] ?? a["output.value"];
        payload.value = out === undefined ? null : parseJson(out);
      }
      this.log.appendResult(payload);
      return;
    }
    if ((op !== null && GEN_AI_CALLS.has(op)) || oi === "LLM" || oi === "AGENT") {
      const payload: Record<string, unknown> = {
        profile: "otel.gen_ai.call/1",
        source: "otel",
        span_name: span.name,
        operation: op ?? oi,
        model: str(a["gen_ai.response.model"]) ?? str(a["gen_ai.request.model"]) ?? str(a["llm.model_name"]),
        provider: str(a["gen_ai.provider.name"]) ?? str(a["gen_ai.system"]) ?? str(a["llm.provider"]),
        agent: str(a["gen_ai.agent.name"]),
        conversation_id: str(a["gen_ai.conversation.id"]) ?? str(a["session.id"]),
        usage: {
          input_tokens: num(a["gen_ai.usage.input_tokens"]) ?? num(a["llm.token_count.prompt"]),
          output_tokens: num(a["gen_ai.usage.output_tokens"]) ?? num(a["llm.token_count.completion"]),
        },
        outcome: failed ? "error" : "ok",
        ...ids,
      };
      if (failed) payload.error = span.status?.message ?? "error";
      if (this.options.recordPrompt) payload.input_messages = parseJson(a["gen_ai.input.messages"] ?? a["input.value"]);
      if (this.options.recordText) payload.output_messages = parseJson(a["gen_ai.output.messages"] ?? a["output.value"]);
      this.log.appendMemory(dropNulls(payload));
    }
  }

  shutdown(): Promise<void> {
    return Promise.resolve();
  }

  forceFlush(): Promise<void> {
    return Promise.resolve();
  }
}

/** `new WitnessLogSpanExporter(log, opts)`. */
export function witnessTelemetry(log: Log, opts: WitnessTelemetryOptions = {}): WitnessLogSpanExporter {
  return new WitnessLogSpanExporter(log, opts);
}

// ---------------------------------------------------------------- helpers

function isAsyncIterable(v: unknown): v is AsyncIterable<unknown> {
  return typeof v === "object" && v !== null && Symbol.asyncIterator in v;
}

function isPromiseLike(v: unknown): v is PromiseLike<unknown> {
  return typeof v === "object" && v !== null && typeof (v as PromiseLike<unknown>).then === "function";
}

function errorString(e: unknown): string {
  return e instanceof Error ? `${e.name}: ${e.message}` : String(e);
}

/** A JSON-encodable copy of `v` (bigint as string, undefined as null, non-JSON via String()). */
function jsonSafe(v: unknown): unknown {
  if (v === undefined) return null;
  try {
    return JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x === undefined ? null : x))) as unknown;
  } catch {
    return String(v);
  }
}

function parseJson(v: unknown): unknown {
  if (typeof v !== "string") return v === undefined ? null : jsonSafe(v);
  try {
    return JSON.parse(v) as unknown;
  } catch {
    return v;
  }
}

function str(v: unknown): string | null {
  return typeof v === "string" ? v : v === undefined || v === null ? null : String(v);
}

function num(v: unknown): number | null {
  return typeof v === "number" ? v : null;
}

function parentSpanId(span: SpanLike): string | null {
  return span.parentSpanContext?.spanId ?? span.parentSpanId ?? null;
}

/** `o` without its null members (absent attributes are not recorded as null). */
function dropNulls(o: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== null));
}
