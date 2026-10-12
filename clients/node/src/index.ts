/**
 * `@witness-log/node`: witness-log for Node.js, no Rust toolchain needed.
 *
 * The Rust core (Merkle log, Ed25519 identity, salted redaction, journal,
 * witness protocol, the reference verifier) is a prebuilt native addon
 * (`./native`, napi-rs). This module is the JavaScript surface on top of
 * it: `openLog`, string or JSON payloads, `submit` over `fetch`, and the
 * pure-TypeScript verifier from `@witness-log/client` re-exported so a
 * dossier can be checked by code that shares nothing with the writer.
 */
import { existsSync, mkdtempSync, openSync, readFileSync, readSync, renameSync, writeSync, closeSync, fsyncSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, basename, join } from "node:path";
import { randomBytes } from "node:crypto";

import * as native from "@witness-log/node/native";
import {
  verifyDossier,
  verifyDisclosure,
  hexToBytes,
  bytesToHex,
  EXIT_CODES,
  type Dossier,
  type DossierReport,
  type DossierVerification,
  type Leaf,
  type SignedTreeHead,
  type Verdict,
  type VerifyDossierOptions,
  type WitnessDirectory,
  type WitnessEntry,
} from "@witness-log/client";

export {
  verifyDossier,
  verifyDisclosure,
  verifyInclusion,
  verifyCheckpoint,
  verifyReceipt,
  payloadHash,
  leafCanonicalBytes,
  leafHash,
  merkleRoot,
  canonicalOrigin,
  hexToBytes,
  bytesToHex,
  EXIT_CODES,
  LEAF_TYPES,
  type Dossier,
  type DossierReport,
  type DossierVerification,
  type Leaf,
  type SignedTreeHead,
  type Verdict,
  type VerifyDossierOptions,
  type WitnessDirectory,
  type WitnessEntry,
  type WitnessReceipt,
  type KeyBindingStatement,
  type QuorumResult,
} from "@witness-log/client";

/** The raw napi-rs binding, for anything this module does not wrap. */
export { native };

// ---------------------------------------------------------------- errors

/** Every error this module raises on purpose. `code` says which kind. */
export class WitnessLogError extends Error {
  constructor(
    message: string,
    readonly code: "closed" | "io" | "invalid" | "sealed" | "refused" | "native",
  ) {
    super(message);
    this.name = "WitnessLogError";
  }
}

function wrapNative<T>(fn: () => T): T {
  try {
    return fn();
  } catch (e) {
    if (e instanceof WitnessLogError) throw e;
    const msg = e instanceof Error ? e.message : String(e);
    if (/is closed/.test(msg)) throw new WitnessLogError(msg, "closed");
    if (/must be|unknown authorization|exceeds|non-negative/.test(msg)) throw new WitnessLogError(msg, "invalid");
    throw new WitnessLogError(msg, "native");
  }
}

// -------------------------------------------------------------- payloads

/** What you can commit: raw bytes, a string (UTF-8), or any JSON value (canonical JSON). */
export type Payload = Uint8Array | string | number | boolean | null | object;

/**
 * Deterministic JSON bytes: sorted keys, no whitespace, non-ASCII escaped
 * as `\uXXXX`. Matches the Python package's `canonical_json` for strings,
 * integers, booleans, null, arrays and objects (floats may format
 * differently between the two languages). Never throws: `undefined` and
 * functions become null, bigint becomes a string, cycles become "<cycle>".
 */
export function canonicalJson(value: unknown): Uint8Array {
  const out = stringifyCanonical(value, new Set());
  return new TextEncoder().encode(out.replace(/[\u007f-￿]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`));
}

function stringifyCanonical(v: unknown, seen: Set<unknown>): string {
  if (v === null || v === undefined || typeof v === "function" || typeof v === "symbol") return "null";
  if (typeof v === "string") return JSON.stringify(v);
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "bigint") return JSON.stringify(v.toString());
  if (typeof v === "number") return Number.isFinite(v) ? JSON.stringify(v) : JSON.stringify(String(v));
  if (v instanceof Uint8Array) return JSON.stringify({ $bytes: Buffer.from(v).toString("base64") });
  if (v instanceof Date) return JSON.stringify(v.toISOString());
  if (typeof v === "object") {
    if (seen.has(v)) return JSON.stringify("<cycle>");
    seen.add(v);
    try {
      if (Array.isArray(v)) return `[${v.map((x) => stringifyCanonical(x, seen)).join(",")}]`;
      if (typeof (v as { toJSON?: unknown }).toJSON === "function") {
        return stringifyCanonical((v as { toJSON: () => unknown }).toJSON(), seen);
      }
      const keys = Object.keys(v as object).sort();
      return `{${keys
        .map((k) => `${JSON.stringify(k)}:${stringifyCanonical((v as Record<string, unknown>)[k], seen)}`)
        .join(",")}}`;
    } finally {
      seen.delete(v);
    }
  }
  return JSON.stringify(String(v));
}

/** Bytes for a payload: Uint8Array as is, string as UTF-8, anything else as canonical JSON. */
export function payloadBytes(payload: Payload): Uint8Array {
  if (payload instanceof Uint8Array) return payload;
  if (typeof payload === "string") return new TextEncoder().encode(payload);
  return canonicalJson(payload);
}

/** Options that wrap a payload in a small JSON envelope (see `Log.appendResult`). */
export interface AppendOptions {
  /** Recorded as `"outcome"`: "ok" or "error" for results. */
  outcome?: "ok" | "error";
  /** Recorded as `"intent_index"`: the intent leaf this result answers. */
  intentIndex?: number;
  /** Recorded as `"tool"`. */
  tool?: string;
}

function envelope(payload: Payload, opts: AppendOptions | undefined): Uint8Array {
  if (opts === undefined || (opts.outcome === undefined && opts.intentIndex === undefined && opts.tool === undefined)) {
    return payloadBytes(payload);
  }
  const doc: Record<string, unknown> = {};
  if (opts.tool !== undefined) doc.tool = opts.tool;
  if (opts.intentIndex !== undefined) doc.intent_index = opts.intentIndex;
  if (opts.outcome !== undefined) doc.outcome = opts.outcome;
  doc.value = payload instanceof Uint8Array ? { $bytes: Buffer.from(payload).toString("base64") } : payload;
  return canonicalJson(doc);
}

// ------------------------------------------------------------------- log

export interface OpenLogOptions {
  /** 32-byte identity seed. Required with `seal`; otherwise optional (a fresh identity is stored in the journal header). */
  identitySeed?: Uint8Array;
  /** Keep the seed out of the journal: the header holds only the public key and every open needs `identitySeed`. */
  seal?: boolean;
  /** Also keep plaintext payloads in `<path>.payloads` (0600) so `disclose(i)` can return them. Default false. */
  storePayloads?: boolean;
}

export interface LogInfo {
  path: string;
  identityPubkey: string;
  treeSize: number;
  rootHash: string;
  /** `witness-log/<identity hex>`: the C2SP origin witnesses know this log by. */
  origin: string;
  storesPayloads: boolean;
  /** Torn trailing lines healed when the journal was resumed. */
  droppedTrailingLines: number;
}

export interface Disclosure {
  index: number;
  payloadHash: string;
  /** The salt the log held for this leaf, or null if forgotten / never had a payload. */
  salt: Uint8Array | null;
  /** The plaintext payload, when this log stores payloads and the leaf has not been forgotten. */
  payload: Uint8Array | null;
  /** True when `payload` and `salt` are present and reproduce `payloadHash` (SPEC §8). */
  verified: boolean;
}

export type AuthorizationKind =
  | "granted_by_me"
  | "granted_to_me"
  | "revoked_by_me"
  | "revoked_to_me"
  | "scope_changed_by_me"
  | "scope_changed_to_me";

export interface StepOptions {
  /** Arguments to commit to in the intent leaf (any JSON value). */
  args?: unknown;
  /** Commit the return value in the result leaf. Default true. */
  recordResult?: boolean;
}

/** Peek at a journal header: true when it was created sealed (no seed stored). */
export function isSealedJournal(path: string): boolean {
  let first = "";
  try {
    const fd = openSync(path, "r");
    try {
      const buf = Buffer.alloc(4096);
      const n = readSync(fd, buf, 0, buf.length, 0);
      first = buf.subarray(0, n).toString("utf8").split("\n")[0] ?? "";
    } finally {
      closeSync(fd);
    }
    const header = JSON.parse(first) as { identity_bytes_hex?: string; identity_pubkey_hex?: string | null };
    return (header.identity_bytes_hex ?? "") === "" && typeof header.identity_pubkey_hex === "string";
  } catch {
    return false;
  }
}

/**
 * Create or resume a journaled log at `path`. If the journal exists it is
 * resumed; otherwise a new log is created (with `identitySeed`, or with a
 * fresh identity stored in the header). `seal` keeps the seed out of the
 * file and requires it on every open.
 */
export function openLog(path: string, opts: OpenLogOptions = {}): Log {
  const store = opts.storePayloads ?? false;
  if (opts.seal && opts.identitySeed === undefined) {
    throw new WitnessLogError("seal: true requires identitySeed (the seed is not stored in a sealed journal)", "invalid");
  }
  if (opts.identitySeed !== undefined && opts.identitySeed.length !== 32) {
    throw new WitnessLogError("identitySeed must be exactly 32 bytes", "invalid");
  }
  if (existsSync(path)) {
    if (opts.identitySeed !== undefined) {
      return new Log(wrapNative(() => native.NativeLog.resumeWithIdentity(path, opts.identitySeed!, store)));
    }
    if (isSealedJournal(path)) {
      throw new WitnessLogError(`${path} is a sealed journal: pass identitySeed to open it`, "sealed");
    }
    return new Log(wrapNative(() => native.NativeLog.resume(path, store)));
  }
  if (opts.seal) return new Log(wrapNative(() => native.NativeLog.createSealed(path, opts.identitySeed!, store)));
  if (opts.identitySeed !== undefined) {
    return new Log(wrapNative(() => native.NativeLog.create(path, opts.identitySeed!, store)));
  }
  return new Log(wrapNative(() => native.NativeLog.createEphemeral(path, store)));
}

/** A journaled witness-log. Create with `openLog`. */
export class Log {
  constructor(readonly native: native.NativeLog) {}

  get path(): string {
    return this.native.path;
  }

  /** This log's identity public key (64 hex). */
  get identityPubkey(): string {
    return wrapNative(() => this.native.identityPubkeyHex());
  }

  /** The 32-byte identity seed. Private key material; persist it if you need the identity elsewhere. */
  identityBytes(): Uint8Array {
    return new Uint8Array(wrapNative(() => this.native.identityBytes()));
  }

  get treeSize(): number {
    return wrapNative(() => this.native.treeSize());
  }

  get rootHash(): string {
    return wrapNative(() => this.native.rootHex());
  }

  /** `witness-log/<identity hex>` (SPEC §9.3). */
  get origin(): string {
    return wrapNative(() => this.native.canonicalOrigin());
  }

  info(): LogInfo {
    return wrapNative(() => ({
      path: this.native.path,
      identityPubkey: this.native.identityPubkeyHex(),
      treeSize: this.native.treeSize(),
      rootHash: this.native.rootHex(),
      origin: this.native.canonicalOrigin(),
      storesPayloads: this.native.storesPayloads,
      droppedTrailingLines: this.native.droppedTrailingLines,
    }));
  }

  /** 0x01 ActiveIntent: what the agent is about to do. Returns the leaf index. */
  appendIntent(payload: Payload, opts?: AppendOptions): number {
    return wrapNative(() => this.native.appendIntent(envelope(payload, opts)));
  }

  /**
   * 0x02 ActiveResult: what happened. With options the leaf's payload is
   * the canonical JSON of `{tool?, intent_index?, outcome?, value}`;
   * without them it is exactly the bytes of `payload`.
   */
  appendResult(payload: Payload, opts?: AppendOptions): number {
    return wrapNative(() => this.native.appendResult(envelope(payload, opts)));
  }

  /** 0x00 PassiveMemory: context stored, nothing acted on. */
  appendMemory(payload: Payload, opts?: AppendOptions): number {
    return wrapNative(() => this.native.appendMemory(envelope(payload, opts)));
  }

  /**
   * 0x05 HandoffAttestation (SPEC §3.1). `counterparty` is the other
   * agent's identity key (64 hex); `state` is the exact bytes handed over
   * (both sides must commit identical bytes for `bind` to match).
   */
  appendHandoff(direction: "sent" | "received", counterparty: string, state: Payload): number {
    const bytes = payloadBytes(state);
    const cp = counterparty.toLowerCase();
    return wrapNative(() =>
      direction === "sent" ? this.native.appendHandoffSent(bytes, cp) : this.native.appendHandoffReceived(bytes, cp),
    );
  }

  /** 0x06 AuthorizationEvent (SPEC §3.2). `scope` is the raw scope description; its unsalted SHA-256 is what both sides match on. */
  appendAuthorizationEvent(kind: AuthorizationKind, counterparty: string, scope: Payload): number {
    return wrapNative(() => this.native.appendAuthorizationEvent(kind, payloadBytes(scope), counterparty.toLowerCase()));
  }

  /** 0x07 ExternalAnchor (SPEC §3.3): a Rekor entry, RFC 3161 token, or similar, for the current head. */
  appendExternalAnchor(anchorUrl: string, anchorProof: string | object): number {
    const json = typeof anchorProof === "string" ? anchorProof : JSON.stringify(anchorProof);
    return wrapNative(() => this.native.appendExternalAnchor(anchorUrl, json));
  }

  /** Right to be forgotten: erase leaf `index`'s salt (and stored payload). Every proof stays valid. True if something was erased. */
  forget(index: number): boolean {
    return wrapNative(() => this.native.forget(index));
  }

  canForget(index: number): boolean {
    return wrapNative(() => this.native.canForget(index));
  }

  /**
   * Prove what leaf `index` said: its committed hash, the salt, and (when
   * this log stores payloads) the payload. Anyone can check the three
   * with `verifyDisclosure`. Null if there is no such leaf.
   */
  disclose(index: number): Disclosure | null {
    const d = wrapNative(() => this.native.disclose(index));
    if (d === null || d === undefined) return null;
    const salt = d.saltHex ? hexToBytes(d.saltHex) : null;
    const payload = d.payload ? new Uint8Array(d.payload) : null;
    const verified =
      salt !== null && payload !== null
        ? verifyDisclosure({ index, payload_hash: d.payloadHash } as Leaf, payload, salt)
        : false;
    return { index, payloadHash: d.payloadHash, salt, payload, verified };
  }

  /** Every leaf (the dossier's `leaves`). */
  leaves(): Leaf[] {
    return JSON.parse(wrapNative(() => this.native.leavesJson())) as Leaf[];
  }

  /** A signed checkpoint over the current head (SPEC §6). */
  checkpoint(): SignedTreeHead {
    return JSON.parse(wrapNative(() => this.native.checkpointJson())) as SignedTreeHead;
  }

  /** The dossier for the current head (SPEC §9), with every key binding. Receipts come from `submit`. */
  exportDossier(): Dossier {
    return JSON.parse(this.exportDossierJson()) as Dossier;
  }

  exportDossierJson(): string {
    return wrapNative(() => this.native.toDossierJson());
  }

  /** Root of the first `size` leaves (hex), or null if the log is shorter. */
  rootHashAt(size: number): string | null {
    return wrapNative(() => this.native.rootHexAt(size)) ?? null;
  }

  /** Proof that leaf `index` is in the current tree; check with `verifyInclusion`. */
  inclusionProof(index: number): { treeSize: number; rootHash: string; leafHash: string; proof: string[] } | null {
    return wrapNative(() => {
      const p = this.native.inclusionProof(index);
      const lh = this.native.leafHashHex(index);
      if (!p || !lh) return null;
      return { treeSize: p.treeSize, rootHash: p.rootHex, leafHash: lh, proof: p.proof };
    });
  }

  /**
   * Run `fn` as one audited step: an intent leaf before, a result leaf
   * after (outcome "ok" with the return value, or "error" with the
   * message, and the error rethrown unchanged).
   */
  async step<T>(name: string, fn: () => T | Promise<T>, opts: StepOptions = {}): Promise<T> {
    const intentIndex = this.appendIntent({ tool: name, args: opts.args ?? null, t: Date.now() / 1000 });
    let out: T;
    try {
      out = await fn();
    } catch (e) {
      const msg = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
      this.appendResult(msg, { tool: name, intentIndex, outcome: "error" });
      throw e;
    }
    this.appendResult(opts.recordResult === false ? null : jsonable(out), { tool: name, intentIndex, outcome: "ok" });
    return out;
  }

  /** Get the current head cosigned by witnesses from `directory`. See `submitRound`. */
  submit(directory: DirectoryInput, opts: SubmitOptions = {}): Promise<SubmitResult> {
    return submitRound(this, directory, opts);
  }

  /** fsync the journal and the salt sidecar. */
  sync(): void {
    wrapNative(() => this.native.sync());
  }

  /** Sync and release the journal and its lock. Every later call throws. */
  close(): void {
    wrapNative(() => this.native.close());
  }

  get closed(): boolean {
    return this.native.isClosed();
  }

  [Symbol.dispose](): void {
    if (!this.closed) this.close();
  }
}

function jsonable(v: unknown): Payload {
  if (v === undefined) return null;
  if (v instanceof Uint8Array || typeof v === "string") return v;
  return JSON.parse(new TextDecoder().decode(canonicalJson(v))) as Payload;
}

// ------------------------------------------------------------- verifying

export interface NativeVerifyOptions extends VerifyDossierOptions {}

const VERDICT_NAME: Record<string, Verdict> = {
  witnessed: "WITNESSED",
  consistent_unwitnessed: "CONSISTENT-UNWITNESSED",
  unanchored: "UNANCHORED",
  diverged: "DIVERGED",
};

/**
 * The reference verifier (the Rust `Dossier::verify`, exactly what
 * `witness-log verify` runs) on a dossier. Same result shape as the
 * pure-TypeScript `verifyDossier`; use both when it matters.
 */
export function verifyDossierNative(dossier: Dossier | string, opts: NativeVerifyOptions = {}): DossierVerification {
  const json = typeof dossier === "string" ? dossier : JSON.stringify(dossier);
  const report = JSON.parse(
    wrapNative(() =>
      native.verifyDossierJson(json, {
        identity: opts.identity,
        directoryJson: opts.directory === undefined ? undefined : JSON.stringify(opts.directory),
        threshold: opts.threshold,
        minWitnesses: opts.minWitnesses,
      }),
    ),
  ) as DossierReport;
  const verdict = VERDICT_NAME[report.verdict];
  let signer = "";
  try {
    signer = String((typeof dossier === "string" ? (JSON.parse(dossier) as Dossier) : dossier).checkpoint?.signer_pubkey ?? "");
  } catch {
    signer = "";
  }
  return {
    verdict,
    exitCode: EXIT_CODES[verdict],
    ok: verdict === "WITNESSED",
    identityPubkey: signer,
    identityPinned: report.identity_pinned,
    directoryPinned: report.externally_anchored,
    internallyConsistent: report.internally_consistent,
    failures: [],
    report,
  };
}

/** SPEC §3.1: do a sender's and a receiver's handoff leaves bind? Null when they do, else the reason. */
export function verifyHandoffBinding(senderIdentity: string, senderLeaf: Leaf, receiverIdentity: string, receiverLeaf: Leaf): string | null {
  return wrapNative(() => native.verifyHandoffBinding(senderIdentity, JSON.stringify(senderLeaf), receiverIdentity, JSON.stringify(receiverLeaf))) ?? null;
}

/** SPEC §3.2: do two authorization leaves bind? Null when they do, else the reason. */
export function verifyAuthorizationBinding(aIdentity: string, aLeaf: Leaf, bIdentity: string, bLeaf: Leaf): string | null {
  return wrapNative(() => native.verifyAuthorizationBinding(aIdentity, JSON.stringify(aLeaf), bIdentity, JSON.stringify(bLeaf))) ?? null;
}

/** Remove a stale `<path>.lock` left by a crashed process. Only when nothing else has the journal open. */
export function forceUnlock(path: string): void {
  wrapNative(() => native.forceUnlock(path));
}

// -------------------------------------------------------------- witnessing

/** A witness directory: `{witnesses: [...]}`, a bare array of entries, or JSON text of either. */
export type DirectoryInput = WitnessDirectory | WitnessEntry[] | string;

export interface SubmitOptions {
  /** How many witnesses to contact (diversity-first selection, then round-robin fill). Default 8. */
  want?: number;
  /** `ok` requires at least this many verified cosignatures. Default 2 (the floor for WITNESSED). */
  min?: number;
  /** Client state file, shared with the CLI and Python. Default `<journal>.witnesses.json`. */
  statePath?: string;
  /** Per-request timeout. Default 10000 ms. */
  timeoutMs?: number;
  /** Total time to spend honouring Retry-After per witness. Default 60000 ms. */
  maxWaitMs?: number;
  /** Replace the HTTP transport (tests). Default: global `fetch`. */
  fetch?: typeof fetch;
}

export interface WitnessOutcome {
  witness: string | null;
  url?: string;
  /** HTTP status, or 0 for a transport failure. */
  status: number;
  error?: string;
}

export interface SubmitResult {
  /** `refused` is unset and at least `min` witnesses cosigned. */
  ok: boolean;
  treeSize: number;
  cosignatures: number;
  contacted: number;
  outcomes: WitnessOutcome[];
  /** The dossier for this head with every cosignature that verified, plus the directory you submitted to. */
  dossier: Dossier | null;
  /** Set when the safety rule stopped the round: witnesses already cosigned a head this journal does not extend. */
  refused?: string;
}

export interface WitnessState {
  sizes: Record<string, number>;
  cosigned_size: number;
  cosigned_root: string;
}

const MAX_RETRY_AFTER_MS = 60_000;
const ATTEMPTS_PER_WITNESS = 6;

function parseDirectory(d: DirectoryInput): WitnessDirectory {
  let v: unknown = d;
  if (typeof v === "string") {
    const text = v.trimStart();
    v = text.startsWith("{") || text.startsWith("[") ? JSON.parse(text) : JSON.parse(readFileSync(v, "utf8"));
  }
  if (Array.isArray(v)) v = { witnesses: v };
  if (typeof v !== "object" || v === null || !Array.isArray((v as WitnessDirectory).witnesses)) {
    throw new WitnessLogError('directory must be {"witnesses": [...]}, an array of entries, or a path to such a file', "invalid");
  }
  return v as WitnessDirectory;
}

/** The CLI's client state (`<journal>.witnesses.json`). Missing or unreadable is an empty state. */
export function loadWitnessState(path: string): WitnessState {
  let raw: unknown = {};
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    raw = {};
  }
  const r = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
  const sizesRaw = (typeof r.sizes === "object" && r.sizes !== null ? r.sizes : r) as Record<string, unknown>;
  const sizes: Record<string, number> = {};
  for (const [k, v] of Object.entries(sizesRaw)) {
    if (typeof v === "number" && Number.isInteger(v) && v >= 0 && k.length === 64) sizes[k.toLowerCase()] = v;
  }
  return {
    sizes,
    cosigned_size: typeof r.cosigned_size === "number" && Number.isInteger(r.cosigned_size) ? r.cosigned_size : 0,
    cosigned_root: typeof r.cosigned_root === "string" ? r.cosigned_root : "",
  };
}

/** Atomic write (temp file, fsync, rename), mode 0600. */
export function saveWitnessState(path: string, state: WitnessState): void {
  const dir = dirname(path);
  const tmp = join(dir, `.${basename(path)}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`);
  const sorted: Record<string, number> = {};
  for (const k of Object.keys(state.sizes).sort()) sorted[k] = state.sizes[k];
  const data = JSON.stringify({ sizes: sorted, cosigned_size: state.cosigned_size, cosigned_root: state.cosigned_root }, null, 2);
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
}

async function post(
  fetchImpl: typeof fetch,
  url: string,
  body: string,
  timeoutMs: number,
): Promise<{ status: number; text: string; retryAfterMs: number }> {
  if (!/^https?:\/\//.test(url)) throw new WitnessLogError(`witness url must be http:// or https://, got ${JSON.stringify(url)}`, "invalid");
  const res = await fetchImpl(url.replace(/\/+$/, "") + "/add-checkpoint", {
    method: "POST",
    headers: { "content-type": "text/plain; charset=utf-8" },
    body,
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = (await res.text()).slice(0, 1 << 20);
  const ra = Number.parseInt(res.headers.get("retry-after") ?? "", 10);
  return { status: res.status, text, retryAfterMs: Number.isFinite(ra) && ra > 0 ? ra * 1000 : 0 };
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * One submission round, the same procedure as `witness-log witness
 * submit` and the Python `submit_round`: pin the current head, send it to
 * up to `want` diversity-selected witnesses over `c2sp.org/tlog-witness`,
 * follow 409 resyncs, honour Retry-After on 429/503, keep only
 * cosignatures that verify, persist what each witness has cosigned to
 * `<journal>.witnesses.json`. Never throws for network failures (they are
 * per-witness `outcomes`); throws `WitnessLogError` only on bad arguments.
 */
export async function submitRound(log: Log, directoryInput: DirectoryInput, opts: SubmitOptions = {}): Promise<SubmitResult> {
  const directory = parseDirectory(directoryInput);
  const want = opts.want ?? 8;
  const min = opts.min ?? 2;
  if (want < 1 || min < 1) throw new WitnessLogError("want and min must be at least 1", "invalid");
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const maxWaitMs = opts.maxWaitMs ?? MAX_RETRY_AFTER_MS;
  const fetchImpl = opts.fetch ?? fetch;
  const statePath = opts.statePath ?? `${log.path}.witnesses.json`;

  const ident = log.identityPubkey;
  const picks = JSON.parse(wrapNative(() => native.selectWitnesses(JSON.stringify(directory), ident, want, false))) as WitnessEntry[];
  const size = log.treeSize;
  const state = loadWitnessState(statePath);

  if (state.cosigned_size > 0) {
    const have = log.rootHashAt(state.cosigned_size);
    if (have === null || have !== state.cosigned_root.toLowerCase()) {
      const refused =
        `refusing to submit: witnesses already cosigned size ${state.cosigned_size} for this identity and this journal ` +
        `(size ${size}) does not extend it; submitting would get the identity recorded as equivocating. ` +
        `Restore the journal that was witnessed (state: ${statePath})`;
      return { ok: false, treeSize: size, cosignatures: 0, contacted: 0, outcomes: [], dossier: null, refused };
    }
  }

  const one = async (w: WitnessEntry): Promise<[WitnessOutcome, native.WitnessResponse | null]> => {
    const pk = String(w.pubkey ?? "").toLowerCase();
    const name = w.name ?? null;
    const url = String(w.url ?? "");
    let old = state.sizes[pk] ?? 0;
    if (old > size) old = 0;
    let waited = 0;
    let status = 0;
    let text = "";
    for (let attempt = 0; attempt < ATTEMPTS_PER_WITNESS; attempt++) {
      let retryAfterMs = 0;
      try {
        const body = wrapNative(() => log.native.addCheckpointBodyAt(size, old));
        ({ status, text, retryAfterMs } = await post(fetchImpl, url, body, timeoutMs));
      } catch (e) {
        return [{ witness: name, url, status: 0, error: e instanceof Error ? e.message : String(e) }, null];
      }
      if (status === 200) return [{ witness: name, url, status: 200 }, { witnessPubkey: pk, body: text }];
      if (status === 409) {
        const theirs = Number.parseInt(text.trim(), 10);
        if (!Number.isFinite(theirs) || !/^\d+$/.test(text.trim())) {
          return [{ witness: name, url, status: 409, error: `unparseable 409 body ${JSON.stringify(text.trim().slice(0, 80))}` }, null];
        }
        if (theirs > size) {
          return [
            {
              witness: name,
              url,
              status: 409,
              error: `witness already cosigned size ${theirs} but this journal has ${size} leaves (truncated journal, or a fork)`,
            },
            null,
          ];
        }
        old = theirs;
        continue;
      }
      if ((status === 429 || status === 503) && retryAfterMs > 0 && retryAfterMs <= MAX_RETRY_AFTER_MS && waited + retryAfterMs <= maxWaitMs) {
        await sleep(retryAfterMs);
        waited += retryAfterMs;
        continue;
      }
      break;
    }
    let error = text.trim().slice(0, 200);
    if (status === 422) error = "REFUSED (422): not consistent with what this witness already cosigned: " + error;
    return [{ witness: name, url, status, error }, null];
  };

  const results = await Promise.all(picks.map(one));
  const outcomes = results.map(([o]) => o);
  const responses = results.map(([, r]) => r).filter((r): r is native.WitnessResponse => r !== null);

  const built = wrapNative(() => log.native.dossierFromResponsesAt(size, responses));
  const doc = JSON.parse(built.dossierJson) as Dossier;
  const accepted = new Set((doc.witness_receipts ?? []).map((r) => String(r.witness_pubkey).toLowerCase()));
  outcomes.forEach((o, i) => {
    const pk = String(picks[i]?.pubkey ?? "").toLowerCase();
    if (o.status === 200 && !accepted.has(pk)) {
      o.status = 0;
      o.error = "HTTP 200 but no valid cosignature from the expected key";
    }
  });
  for (const pk of accepted) state.sizes[pk] = size;
  if (built.receiptsAccepted > 0 && size >= state.cosigned_size) {
    state.cosigned_size = size;
    state.cosigned_root = log.rootHashAt(size) ?? "";
  }
  try {
    saveWitnessState(statePath, state);
  } catch (e) {
    outcomes.push({ witness: null, status: 0, error: `could not save ${statePath}: ${e instanceof Error ? e.message : String(e)}` });
  }
  doc.witness_directory = directory;
  return {
    ok: built.receiptsAccepted >= min,
    treeSize: size,
    cosignatures: built.receiptsAccepted,
    contacted: picks.length,
    outcomes,
    dossier: doc,
  };
}

/** Diversity-first witness selection, then round-robin fill up to `want`. */
export function selectWitnesses(directory: DirectoryInput, subjectPubkey: string, want: number, includeProjectOperated = false): WitnessEntry[] {
  const d = parseDirectory(directory);
  return JSON.parse(wrapNative(() => native.selectWitnesses(JSON.stringify(d), subjectPubkey, want, includeProjectOperated))) as WitnessEntry[];
}

/** A throwaway directory for tests: a fresh temp dir path for a journal. */
export function tempJournalPath(prefix = "witness-log-"): string {
  return join(mkdtempSync(join(tmpdir(), prefix)), "journal.jsonl");
}

/** Version of the native addon. */
export function nativeVersion(): string {
  return native.nativeVersion();
}
