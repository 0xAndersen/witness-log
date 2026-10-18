/**
 * Reading a dossier the way the reference verifier's serde types read it
 * (outside review III, H2). `JSON.parse` loses what the reference
 * sees: it rounds integers above 2^53, reads `3.0` as `3`, keeps the last
 * of two equal keys without saying so, and accepts unpaired surrogates.
 * `parseJsonExact` keeps all of it, and `readDossier` applies the rule
 * corpus/17_dossier_parsing.json states:
 *
 * - every struct (the dossier, checkpoint, leaf, receipt, directory and
 *   entry, key binding, revocation, custody threshold) is an object, never
 *   an array; a key naming a field appears once and matches exactly; other
 *   keys are ignored;
 * - a u64 is an unsigned integer literal, at most 2^64 - 1, read exactly
 *   (a `bigint` above `Number.MAX_SAFE_INTEGER`, a `number` otherwise);
 * - string, bool and list fields have that JSON type; optional fields may
 *   be absent or null, defaulted ones absent but not null;
 * - a unit enum variant is its name or `{"name": null}`;
 * - field strings and struct keys have no unpaired surrogate;
 * - `fleet_anchor` is any JSON value with no unpaired surrogate, finite
 *   numbers and at most 126 levels of nesting.
 *
 * Anything else is not a dossier: `readDossier` throws `NotADossier`, and
 * `verifyDossier` turns that into INVALID.
 */

/** A u64: a `bigint` exactly when above `Number.MAX_SAFE_INTEGER`. */
export type U64 = number | bigint;

const U64_MAX = 0xffff_ffff_ffff_ffffn;
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

/** Thrown for a value the reference cannot deserialise as a dossier. */
export class NotADossier extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotADossier";
  }
}

/** A JSON number as written in the text. */
export class JsonNumber {
  constructor(readonly literal: string) {}
}

/** The keys each parsed object had more than once (its value is the last one). */
const DUPLICATED = new WeakMap<object, Set<string>>();

const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
const HEX4 = /^[0-9a-fA-F]{4}$/;

function setOwn(obj: Record<string, unknown>, key: string, value: unknown): void {
  if (Object.prototype.hasOwnProperty.call(obj, key)) {
    let d = DUPLICATED.get(obj);
    if (d === undefined) DUPLICATED.set(obj, (d = new Set()));
    d.add(key);
  }
  Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
}

/**
 * RFC 8259 JSON, strictly, as serde_json reads it: numbers come back as
 * {@link JsonNumber}, an object's repeated keys are recorded, escapes that
 * leave an unpaired surrogate are kept for the reader to judge, and a text
 * that is not valid Unicode is refused. Iterative, so nesting depth is
 * bounded by memory, not the call stack. Throws a SyntaxError.
 */
export function parseJsonExact(text: string): unknown {
  if (LONE_SURROGATE.test(text)) throw new SyntaxError("the text is not valid Unicode (an unpaired surrogate)");
  let i = 0;
  const fail = (what: string): never => {
    throw new SyntaxError(`${what} at position ${i}`);
  };
  const ws = () => {
    for (;;) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else return;
    }
  };
  const string = (): string => {
    if (text.charCodeAt(i) !== 0x22) fail("expected a string");
    i++;
    let out = "";
    let start = i;
    for (;;) {
      const c = text.charCodeAt(i);
      if (Number.isNaN(c)) fail("unterminated string");
      if (c === 0x22) {
        out += text.slice(start, i);
        i++;
        return out;
      }
      if (c < 0x20) fail("control character in a string");
      if (c !== 0x5c) {
        i++;
        continue;
      }
      out += text.slice(start, i);
      const e = text[i + 1];
      i += 2;
      switch (e) {
        case '"':
        case "\\":
        case "/":
          out += e;
          break;
        case "b":
          out += "\b";
          break;
        case "f":
          out += "\f";
          break;
        case "n":
          out += "\n";
          break;
        case "r":
          out += "\r";
          break;
        case "t":
          out += "\t";
          break;
        case "u": {
          const h = text.slice(i, i + 4);
          if (!HEX4.test(h)) fail("invalid \\u escape");
          out += String.fromCharCode(parseInt(h, 16));
          i += 4;
          break;
        }
        default:
          fail("invalid escape");
      }
      start = i;
    }
  };
  const key = (): string => {
    ws();
    const k = string();
    ws();
    if (text.charCodeAt(i) !== 0x3a) fail("expected ':'");
    i++;
    return k;
  };
  type Frame = { arr: unknown[]; obj?: undefined; key?: undefined } | { arr?: undefined; obj: Record<string, unknown>; key: string };
  const stack: Frame[] = [];
  for (;;) {
    ws();
    let v: unknown;
    const c = text.charCodeAt(i);
    if (c === 0x7b) {
      i++;
      ws();
      const obj: Record<string, unknown> = {};
      if (text.charCodeAt(i) === 0x7d) {
        i++;
        v = obj;
      } else {
        stack.push({ obj, key: key() });
        continue;
      }
    } else if (c === 0x5b) {
      i++;
      ws();
      const arr: unknown[] = [];
      if (text.charCodeAt(i) === 0x5d) {
        i++;
        v = arr;
      } else {
        stack.push({ arr });
        continue;
      }
    } else if (c === 0x22) {
      v = string();
    } else if (text.startsWith("true", i)) {
      i += 4;
      v = true;
    } else if (text.startsWith("false", i)) {
      i += 5;
      v = false;
    } else if (text.startsWith("null", i)) {
      i += 4;
      v = null;
    } else {
      NUMBER.lastIndex = i;
      const m = NUMBER.exec(text);
      if (m === null) fail("expected a value");
      v = new JsonNumber(m![0]);
      i += m![0].length;
    }
    // Attach v to its container and close every container that ends here.
    for (;;) {
      const top = stack[stack.length - 1];
      if (top === undefined) {
        ws();
        if (i !== text.length) fail("trailing characters");
        return v;
      }
      if (top.arr !== undefined) top.arr.push(v);
      else setOwn(top.obj, top.key, v);
      ws();
      const d = text.charCodeAt(i);
      if (d === 0x2c) {
        i++;
        if (top.obj !== undefined) top.key = key();
        break;
      }
      if (top.arr !== undefined && d === 0x5d) {
        i++;
        stack.pop();
        v = top.arr;
        continue;
      }
      if (top.obj !== undefined && d === 0x7d) {
        i++;
        stack.pop();
        v = top.obj;
        continue;
      }
      fail(top.arr !== undefined ? "expected ',' or ']'" : "expected ',' or '}'");
    }
  }
}

// ------------------------------------------------------------- reading

type Obj = Record<string, unknown>;
type Reader = (v: unknown, path: string) => unknown;

function isObject(v: unknown): v is Obj {
  return v !== null && typeof v === "object" && !Array.isArray(v) && !(v instanceof JsonNumber);
}

function describe(v: unknown): string {
  if (v instanceof JsonNumber) return `number ${v.literal}`;
  if (Array.isArray(v)) return "an array";
  if (v === null) return "null";
  return typeof v === "object" ? "an object" : `${typeof v} ${String(v).slice(0, 40)}`;
}

function bad(path: string, what: string): never {
  throw new NotADossier(`${path}: ${what}`);
}

const str: Reader = (v, path) => {
  if (typeof v !== "string") bad(path, `expected a string, got ${describe(v)}`);
  if (LONE_SURROGATE.test(v as string)) bad(path, "the string has an unpaired surrogate");
  return v;
};

const bool: Reader = (v, path) => (typeof v === "boolean" ? v : bad(path, `expected a boolean, got ${describe(v)}`));

/** An unsigned integer up to `max`, as the reference's u64 (or u8) reads it. */
function uint(max: bigint): Reader {
  return (v, path) => {
    let n: bigint;
    if (v instanceof JsonNumber) {
      if (!/^(0|[1-9][0-9]*)$/.test(v.literal)) bad(path, `${v.literal} is not an unsigned integer literal`);
      n = BigInt(v.literal);
    } else if (typeof v === "bigint") {
      n = v;
    } else if (typeof v === "number") {
      if (!Number.isInteger(v) || Object.is(v, -0)) bad(path, `${v} is not an unsigned integer`);
      if (!Number.isSafeInteger(v)) {
        bad(path, `${v} is above 2^53 - 1, so JSON.parse may have rounded it; pass the dossier as JSON text, or the value as a bigint`);
      }
      n = BigInt(v);
    } else {
      return bad(path, `expected an unsigned integer, got ${describe(v)}`);
    }
    if (n < 0n || n > max) bad(path, `${n} is out of range`);
    return n <= MAX_SAFE ? Number(n) : n;
  };
}

const u64 = uint(U64_MAX);
const u8 = uint(255n);

function list(item: Reader): Reader {
  return (v, path) => {
    if (!Array.isArray(v)) bad(path, `expected an array, got ${describe(v)}`);
    return (v as unknown[]).map((x, i) => item(x, `${path}[${i}]`));
  };
}

/** A unit variant: its name, or `{"name": null}`. */
function unitVariant(variants: readonly string[]): Reader {
  return (v, path) => {
    if (typeof v === "string" && variants.includes(v)) return v;
    if (isObject(v) && !DUPLICATED.has(v)) {
      const keys = Object.keys(v);
      if (keys.length === 1 && variants.includes(keys[0]) && v[keys[0]] === null) return keys[0];
    }
    return bad(path, `expected one of ${variants.join(", ")}, got ${describe(v)}`);
  };
}

interface Field {
  read: Reader;
  /** Must be present (and not null unless nullable). */
  required?: boolean;
  /** `Option<T>`: null reads as absent. */
  nullable?: boolean;
}

/** A struct: an object; known keys once, exactly, typed; other keys ignored. */
function struct(fields: Record<string, Field>): Reader {
  return (v, path) => {
    if (!isObject(v)) bad(path, `expected an object, got ${describe(v)}`);
    const o = v as Obj;
    for (const k of Object.keys(o)) if (LONE_SURROGATE.test(k)) bad(path, "a key has an unpaired surrogate");
    const dups = DUPLICATED.get(o);
    const out: Obj = {};
    for (const [name, f] of Object.entries(fields)) {
      if (dups?.has(name)) bad(path, `duplicate field ${name}`);
      const x = Object.prototype.hasOwnProperty.call(o, name) ? o[name] : undefined;
      if (x === undefined) {
        if (f.required) bad(path, `missing field ${name}`);
        continue;
      }
      if (x === null) {
        if (!f.nullable) bad(`${path}.${name}`, "null is not allowed");
        out[name] = null;
        continue;
      }
      out[name] = f.read(x, `${path}.${name}`);
    }
    return out;
  };
}

const req = (read: Reader): Field => ({ read, required: true });
const opt = (read: Reader): Field => ({ read, nullable: true });
const dflt = (read: Reader): Field => ({ read });

const LEAF = struct({
  index: req(u64),
  leaf_type: req(u8),
  timestamp_ms: req(u64),
  session_pubkey: req(str),
  payload_hash: req(str),
  redacted_index: opt(u64),
  revoked_identity: opt(str),
  handoff_direction: opt(unitVariant(["Sent", "Received"])),
  counterparty_pubkey: opt(str),
  handoff_state_hash: opt(str),
  authorization_event_kind: opt(
    unitVariant(["GrantedByMe", "GrantedToMe", "RevokedByMe", "RevokedToMe", "ScopeChangedByMe", "ScopeChangedToMe"]),
  ),
  authorization_scope_hash: opt(str),
  anchor_url: opt(str),
  anchor_proof_json: opt(str),
  anchor_proof_hash: opt(str),
});

const SIGNED_TREE_HEAD = struct({
  tree_size: req(u64),
  root_hash: req(str),
  timestamp_ms: req(u64),
  sig_alg: req(str),
  signer_pubkey: req(str),
  signature: req(str),
});

const WITNESS_RECEIPT = struct({
  witness_pubkey: req(str),
  tree_size: req(u64),
  root_hash: req(str),
  witnessed_at_ms: req(u64),
  signature: req(str),
  c2sp_origin: opt(str),
  witness_name: opt(str),
});

const WITNESS_ENTRY_STRUCT = struct({
  name: req(str),
  operator_org: req(str),
  url: req(str),
  pubkey: req(str),
  runtime: dflt(unitVariant(["human", "agent"])),
  compute_provider: opt(str),
  is_project_operated: dflt(bool),
});

/** A witness directory entry, with serde's defaults filled in. */
export const readWitnessEntry: Reader = (v, path) => {
  const e = WITNESS_ENTRY_STRUCT(v, path) as Obj;
  e.runtime ??= "human";
  e.is_project_operated ??= false;
  return e;
};

const WITNESS_DIRECTORY = struct({ witnesses: req(list(readWitnessEntry)) });

const CUSTODY_UNIT = ["self_held", "platform_held", "hsm", "kms", "session_delegated", "undisclosed"] as const;
const THRESHOLD = struct({ k: req(str), n: req(str) });

/** KeyCustody: a unit variant, or `{"threshold": {"k": "..", "n": ".."}}`. */
const custody: Reader = (v, path) => {
  if (isObject(v) && !DUPLICATED.has(v) && Object.keys(v).length === 1 && Object.prototype.hasOwnProperty.call(v, "threshold")) {
    return { threshold: THRESHOLD(v.threshold, `${path}.threshold`) };
  }
  return unitVariant(CUSTODY_UNIT)(v, path);
};

const KEY_BINDING = struct({
  identity_pubkey: req(str),
  session_pubkey: req(str),
  session_number: req(u64),
  timestamp_ms: req(u64),
  custody: dflt(custody),
  not_after_ms: opt(u64),
  signature: req(str),
});

const REVOCATION = struct({
  identity_pubkey: req(str),
  as_of_ms: req(u64),
  as_of_index: opt(u64),
  reason: req(str),
  signature: req(str),
});

/** A revocation statement (SPEC §5), as the reference reads one. Throws NotADossier. */
export const readRevocation: Reader = REVOCATION;

const FLEET_ANCHOR = struct({
  origin: req(str),
  entry_index: req(u64),
  entry_bytes_b64: req(str),
  inclusion_proof: req(list(str)),
  fleet_checkpoint_note: req(str),
});

/** serde_json's limit on nesting, less the dossier object around the field. */
const MAX_FLEET_ANCHOR_DEPTH = 126;

/** The rules a `serde_json::Value` imposes: no unpaired surrogate, finite numbers, bounded nesting. */
function checkJsonValue(v: unknown, path: string, depth: number): void {
  if (v instanceof JsonNumber) {
    if (!Number.isFinite(Number(v.literal))) bad(path, `number ${v.literal.slice(0, 20)}… is out of range`);
  } else if (typeof v === "number") {
    if (!Number.isFinite(v)) bad(path, "number out of range");
  } else if (typeof v === "string") {
    if (LONE_SURROGATE.test(v)) bad(path, "a string has an unpaired surrogate");
  } else if (v !== null && typeof v === "object") {
    if (depth + 1 > MAX_FLEET_ANCHOR_DEPTH) bad(path, "nested too deep");
    if (Array.isArray(v)) {
      for (const x of v) checkJsonValue(x, path, depth + 1);
    } else {
      for (const [k, x] of Object.entries(v)) {
        if (LONE_SURROGATE.test(k)) bad(path, "a key has an unpaired surrogate");
        checkJsonValue(x, path, depth + 1);
      }
    }
  }
}

/** `fleet_anchor` read as the reference reads it: well-formed, or malformed with the reason. */
export type FleetAnchorField =
  | { parsed: { origin: string; entry_index: U64; entry_bytes_b64: string; inclusion_proof: string[]; fleet_checkpoint_note: string } }
  | { malformed: string };

/** What `readDossier` returns: the dossier with every field typed, and its fleet anchor read. */
export interface ReadDossier {
  dossier: Obj;
  fleetAnchor: FleetAnchorField | undefined;
}

const DOSSIER = struct({
  identity_pubkey: req(str),
  leaves: req(list(LEAF)),
  checkpoint: req(SIGNED_TREE_HEAD),
  witness_receipts: dflt(list(WITNESS_RECEIPT)),
  witness_directory: dflt(WITNESS_DIRECTORY),
  key_bindings: dflt(list(KEY_BINDING)),
  revocations: dflt(list(REVOCATION)),
  fleet_anchor: opt((v, path) => {
    checkJsonValue(v, path, 0);
    return v;
  }),
});

/**
 * A dossier, from the value `parseJsonExact` or `JSON.parse` produced (or
 * one built in code), as the reference deserialises it. Throws
 * {@link NotADossier}.
 */
export function readDossier(value: unknown): ReadDossier {
  const d = DOSSIER(value, "dossier") as Obj;
  d.witness_receipts ??= [];
  d.witness_directory ??= { witnesses: [] };
  d.key_bindings ??= [];
  d.revocations ??= [];
  let fleetAnchor: FleetAnchorField | undefined;
  if (d.fleet_anchor !== undefined && d.fleet_anchor !== null) {
    try {
      fleetAnchor = { parsed: FLEET_ANCHOR(d.fleet_anchor, "fleet_anchor") as never };
    } catch (e) {
      if (!(e instanceof NotADossier)) throw e;
      fleetAnchor = { malformed: e.message };
    }
  }
  delete d.fleet_anchor;
  return { dossier: d, fleetAnchor };
}
