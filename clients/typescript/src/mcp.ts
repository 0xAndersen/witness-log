/**
 * The witness-log MCP server as a TypeScript object. The server (Python,
 * Rust core) does all hashing, signing and verification; this module
 * starts it over stdio with the official MCP SDK and maps its tools onto
 * `step`, `forget`, `exportDossier`, `verify` and `submit`.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

export interface WitnessLogMCPOptions {
  /** Chain name: 1-128 of letters, digits, '.', '_' or '-'. Reuse it to resume. */
  sessionId: string;
  /** JSON object recorded as the chain's first leaf when it is created. */
  metadata?: Record<string, unknown>;
  /**
   * Path to `integrations/mcp/witness_mcp_server.py`. When omitted the
   * server is started as `python -m witness_log.mcp_server` (what the
   * `witness-log-mcp` console script runs; needs `pip install "witness-log[mcp]"`).
   */
  serverPath?: string;
  /** Python interpreter. Default: `$WITNESS_LOG_PYTHON`, else `python3` (`python` on Windows). */
  python?: string;
  /** Full command override, e.g. `{command: "uvx", args: ["--from", "witness-log[mcp]", "witness-log-mcp"]}`. */
  command?: { command: string; args: string[] };
  /** `WITNESS_LOG_HOME` for the server (where journals live). */
  home?: string;
  /** Extra environment for the server process. */
  env?: Record<string, string>;
}

export interface StepOptions {
  /** Arguments to commit to in the intent leaf (any JSON value). */
  args?: unknown;
  /** The agent's own words for what it is about to do. Default: the step name. */
  intent?: string;
  /** Commit the return value in the result leaf. Default true. */
  recordResult?: boolean;
}

export interface ChainHead {
  identityPubkey: string;
  origin: string;
  treeSize: number;
  rootHash: string;
}

export interface IntegrityReport {
  /** Lowercase, as the Python verifier reports it: witnessed, consistent_unwitnessed, unanchored, diverged. */
  verdict: string;
  tamperAlerts: string[];
  report: Record<string, unknown>;
  witnessedSize?: number;
  witnessedVerdict?: string;
}

/** A tool call the server rejected; `message` is the server's reason. */
export class WitnessLogMCPError extends Error {
  constructor(
    readonly tool: string,
    message: string,
  ) {
    super(message);
    this.name = "WitnessLogMCPError";
  }
}

export class WitnessLogMCP {
  private constructor(
    private readonly client: Client,
    readonly sessionId: string,
    readonly head: ChainHead,
    readonly resumed: boolean,
  ) {}

  /** Start the server, connect, and initialise (or resume) the chain. */
  static async start(opts: WitnessLogMCPOptions): Promise<WitnessLogMCP> {
    const python = opts.python ?? process.env.WITNESS_LOG_PYTHON ?? (process.platform === "win32" ? "python" : "python3");
    const cmd =
      opts.command ??
      (opts.serverPath !== undefined
        ? { command: python, args: [opts.serverPath] }
        : { command: python, args: ["-m", "witness_log.mcp_server"] });
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) if (v !== undefined) env[k] = v;
    Object.assign(env, opts.env ?? {});
    if (opts.home !== undefined) env.WITNESS_LOG_HOME = opts.home;
    const transport = new StdioClientTransport({ command: cmd.command, args: cmd.args, env, stderr: "pipe" });
    const client = new Client({ name: "@witness-log/client", version: "0.2.0" });
    await client.connect(transport);
    try {
      const args: Record<string, unknown> = { session_id: opts.sessionId };
      if (opts.metadata !== undefined) args.metadata = opts.metadata;
      const init = await call(client, "initialize_witness_chain", args);
      return new WitnessLogMCP(client, opts.sessionId, headOf(init), Boolean(init.resumed));
    } catch (e) {
      await client.close();
      throw e;
    }
  }

  /** Call any server tool by name; `session_id` is filled in. */
  tool(name: string, args: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    return call(this.client, name, { session_id: this.sessionId, ...args });
  }

  /**
   * Run `fn` as one audited step: an intent leaf before it runs, a result
   * leaf after (outcome "ok" with its return value, or "error" with the
   * message, in which case the error is rethrown unchanged). Resolves with
   * `fn`'s return value.
   */
  async step<T>(name: string, fn: () => T | Promise<T>, opts: StepOptions = {}): Promise<T> {
    const intent = await this.tool("append_audit_step", {
      intent: opts.intent ?? name,
      tool_name: name,
      payload: { args: opts.args ?? null },
    });
    const intentIndex = Number(intent.intent_index);
    let out: T;
    try {
      out = await fn();
    } catch (e) {
      const msg = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
      await this.tool("record_result", { intent_index: intentIndex, tool_name: name, outcome: "error", value: msg });
      throw e;
    }
    await this.tool("record_result", {
      intent_index: intentIndex,
      tool_name: name,
      outcome: "ok",
      value: opts.recordResult === false ? null : toJson(out),
    });
    return out;
  }

  /** Erase entry `index`'s payload (its salt); every proof stays valid. True if something was erased. */
  async forget(index: number): Promise<boolean> {
    const r = await this.tool("redact_audit_entry", { entry_index: index });
    return Boolean(r.erased);
  }

  /** The dossier for the current head (with cosignatures if it is the witnessed head). */
  async exportDossier(): Promise<Record<string, unknown>> {
    const r = await this.tool("export_dossier");
    return r.dossier as Record<string, unknown>;
  }

  /** The server's verifier over the whole chain. Pass a directory YOU trust to score witnesses. */
  async verify(opts: { trustedDirectory?: Record<string, unknown>; minWitnesses?: number } = {}): Promise<IntegrityReport> {
    const args: Record<string, unknown> = {};
    if (opts.trustedDirectory !== undefined) args.trusted_directory = opts.trustedDirectory;
    if (opts.minWitnesses !== undefined) args.min_witnesses = opts.minWitnesses;
    const r = await this.tool("verify_chain_integrity", args);
    const out: IntegrityReport = {
      verdict: String(r.verdict),
      tamperAlerts: (r.tamper_alerts ?? []) as string[],
      report: (r.report ?? {}) as Record<string, unknown>,
    };
    if (r.witnessed_size !== undefined) out.witnessedSize = Number(r.witnessed_size);
    if (r.witnessed_verdict !== undefined) out.witnessedVerdict = String(r.witnessed_verdict);
    return out;
  }

  /** Get the current head cosigned by witnesses from `directory`. */
  async submit(directory: Record<string, unknown>, opts: { maxWitnesses?: number; minWitnesses?: number } = {}) {
    const args: Record<string, unknown> = { directory };
    if (opts.maxWitnesses !== undefined) args.max_witnesses = opts.maxWitnesses;
    if (opts.minWitnesses !== undefined) args.min_witnesses = opts.minWitnesses;
    const r = await this.tool("submit_to_witnesses", args);
    return {
      verdict: String(r.verdict),
      cosignatures: Number(r.cosignatures_accepted),
      treeSize: Number(r.tree_size),
      outcomes: (r.outcomes ?? []) as Array<Record<string, unknown>>,
      dossier: r.dossier as Record<string, unknown>,
    };
  }

  async close(): Promise<void> {
    await this.client.close();
  }
}

async function call(client: Client, name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const res = (await client.callTool({ name, arguments: args })) as {
    isError?: boolean;
    structuredContent?: Record<string, unknown>;
    content?: Array<{ type: string; text?: string }>;
  };
  const text = (res.content ?? []).map((c) => c.text ?? "").join("");
  if (res.isError) throw new WitnessLogMCPError(name, text || `${name} failed`);
  const sc = res.structuredContent;
  if (sc !== undefined && sc !== null) {
    return ("result" in sc ? sc.result : sc) as Record<string, unknown>;
  }
  return JSON.parse(text) as Record<string, unknown>;
}

function headOf(r: Record<string, unknown>): ChainHead {
  return {
    identityPubkey: String(r.identity_pubkey),
    origin: String(r.origin),
    treeSize: Number(r.tree_size),
    rootHash: String(r.root_hash),
  };
}

/** Values the server can commit to: JSON-encodable, falling back to String(). */
function toJson(v: unknown): unknown {
  if (v === undefined) return null;
  try {
    return JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x)));
  } catch {
    return String(v);
  }
}
