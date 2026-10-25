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
 *   numbers and at most 126 levels of nesting;
 * - the whole text nests at most {@link MAX_DOSSIER_DEPTH} (1000) arrays
 *   and objects deep, the dossier object being depth 1, ignored keys
 *   included.
 *
 * Anything else is not a dossier: `readDossier` throws `NotADossier`, and
 * `verifyDossier` turns that into INVALID.
 *
 * Reading stays bounded on hostile text (outside audit of 0.6.1, where an
 * ignored key nested 5 million deep held a parser frame per level and a
 * 10-million-digit literal took seconds and came back whole in the
 * failure): `readDossierText` stops at the 1001st level, builds only the
 * members the dossier's types name (an ignored key's value is checked as
 * JSON and dropped), reads a u64 literal of more than 20 digits as out of
 * range without converting it, and quotes at most a bounded part of any
 * input in a message ({@link echo}).
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

/**
 * The members of a parsed object that its {@link Shape} does not name: not
 * kept as properties (a million ignored keys held about 215 MB), only how
 * many there were and whether any key had an unpaired surrogate, which is
 * all a reader asks of them.
 */
const UNNAMED = new WeakMap<object, { count: number; loneSurrogate: boolean }>();

/** How many members `o` had in its text, named or not. */
function memberCount(o: object): number {
  return Object.keys(o).length + (UNNAMED.get(o)?.count ?? 0);
}

function setOwn(obj: Record<string, unknown>, key: string, value: unknown): void {
  if (Object.prototype.hasOwnProperty.call(obj, key)) {
    let d = DUPLICATED.get(obj);
    if (d === undefined) DUPLICATED.set(obj, (d = new Set()));
    d.add(key);
  }
  Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
}

/**
 * How deep any JSON input a verifier reads may nest (SPEC.md §9, "Reading a
 * dossier"): a dossier, a trusted directory, revocations, an evidence item.
 * Arrays and objects are counted outside strings, the input's top-level
 * value being depth 1. A deeper dossier is not a dossier, and a deeper
 * directory, revocations or evidence option is refused as a malformed one
 * is ({@link nestsDeeperThan}), wherever the nesting is. Every dossier an
 * implementation writes nests at most 5 deep and a readable `fleet_anchor`
 * at most 127; Go's encoding/json stops at 10,000. The reference's
 * `MAX_DOSSIER_DEPTH`.
 */
export const MAX_DOSSIER_DEPTH = 1000;

/** How many characters of an input a message quotes ({@link echo}). */
const ECHO_CHARS = 64;

/**
 * `s` quoted, cut to its first 64 characters with its length in bytes when
 * it is longer: what a message quotes of untrusted input. The reference
 * and the Go verifier bound theirs the same way; the wording of a failure
 * is not normative.
 */
export function echo(value: unknown): string {
  // Public verifiers (validateLeaf, verifyFleetAnchor) may be handed
  // values of any type.
  const s = typeof value === "string" ? value : String(value);
  if (s.length <= ECHO_CHARS) return JSON.stringify(s);
  const head = Array.from(s.slice(0, 2 * ECHO_CHARS)).slice(0, ECHO_CHARS).join("");
  if (head.length === s.length) return JSON.stringify(s);
  return `${JSON.stringify(head)}… (${Buffer.byteLength(s, "utf8")} bytes)`;
}

/** A number literal as written, cut to its first 64 characters when longer. */
function literal(s: string): string {
  return s.length <= ECHO_CHARS ? s : `${s.slice(0, ECHO_CHARS)}… (${s.length} characters)`;
}

/**
 * What {@link parseJsonExact} builds of a value: `"all"` builds it whole;
 * `"scalar"` builds a string, number, boolean or null; `{fields}` builds an
 * object's members that `fields` names, each by its own shape, and checks
 * every other member's value as JSON without building it (it reads as
 * {@link IGNORED}); `{items}` builds every item of an array by that shape.
 * An array or object where its shape wants another kind (an array where a
 * struct's object or a string belongs) is checked as JSON and not built:
 * it reads as {@link WRONG_ARRAY} or {@link WRONG_OBJECT}, which every
 * reader refuses with the same message it gives the value itself. A list
 * keeps no item after the first one its item shape refuses, and an object
 * keeps only the members its shape names ({@link UNNAMED} counts the
 * rest). So hostile text costs the reader about its own size, not a
 * multiple of it (outside audit of 0.6.1 and the review of 0.7.0: a
 * wrong-kind value, a list of wrong-kind items or a million unknown keys
 * held 110-580 MB for 8-12 MB of text). Still built whole: `fleet_anchor`,
 * which is any JSON value by design, and right-kind items, which are only
 * refused once read.
 */
export type Shape =
  | "all"
  | "scalar"
  // `scalar`: a string also fits (a unit variant's name), so a list of these
  // is not cut short at one.
  | { fields: Readonly<Record<string, Shape>>; scalar?: true }
  | { items: Shape };

/** The value of a member its object's {@link Shape} does not name: checked as JSON, not built. */
export const IGNORED: unique symbol = Symbol("ignored");

/** An array where its {@link Shape} wants another kind: checked as JSON, not built. */
export const WRONG_ARRAY: unique symbol = Symbol("an array");

/** An object where its {@link Shape} wants another kind: checked as JSON, not built. */
export const WRONG_OBJECT: unique symbol = Symbol("an object");

/**
 * RFC 8259 JSON, strictly, as serde_json reads it: numbers come back as
 * {@link JsonNumber}, an object's repeated keys are recorded, escapes that
 * leave an unpaired surrogate are kept for the reader to judge, and a text
 * that is not valid Unicode is refused. Iterative, so nesting depth is
 * bounded by `maxDepth`, never the call stack: the parser holds one frame
 * per open array or object and fails at the first one past `maxDepth`.
 * `shape` says what to build ({@link Shape}). Throws a SyntaxError.
 */
export function parseJsonExact(text: string, shape: Shape = "all", maxDepth = Infinity): unknown {
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
  /** A string checked as string() checks it, without building it. */
  const skipString = (): void => {
    if (text.charCodeAt(i) !== 0x22) fail("expected a string");
    i++;
    for (;;) {
      const c = text.charCodeAt(i);
      if (Number.isNaN(c)) fail("unterminated string");
      if (c === 0x22) {
        i++;
        return;
      }
      if (c < 0x20) fail("control character in a string");
      if (c !== 0x5c) {
        i++;
        continue;
      }
      const e = text[i + 1];
      if (e === "u") {
        if (!HEX4.test(text.slice(i + 2, i + 6))) fail("invalid \\u escape");
        i += 6;
      } else if (e !== undefined && '"\\/bfnrt'.includes(e)) {
        i += 2;
      } else {
        fail("invalid escape");
      }
    }
  };
  /**
   * One open array or object. `shape` null: the container is skipped
   * (checked, not built), and so is everything in it.
   */
  type Frame = {
    isArray: boolean;
    shape: Shape | null;
    /** Of another kind than its shape wants: skipped, and read as WRONG_ARRAY / WRONG_OBJECT. */
    wrong: boolean;
    arr: unknown[] | undefined;
    obj: Record<string, unknown> | undefined;
    key: string;
    /**
     * An array whose item shape refused an item: items after it are checked
     * but not kept (the reader stops at that item, so nothing after it is
     * ever read).
     */
    cut: boolean;
  };
  /** Whether a value its item shape `s` can never read sits in a list. */
  const refusedItem = (s: Shape, v: unknown): boolean => {
    if (s === "scalar") return v === WRONG_ARRAY || v === WRONG_OBJECT;
    if (s === "all") return false;
    if ("items" in s) return !Array.isArray(v);
    const isObj = v !== null && typeof v === "object" && !Array.isArray(v) && !(v instanceof JsonNumber);
    return !isObj && !(s.scalar === true && typeof v === "string");
  };
  const key = (f: Frame): void => {
    ws();
    if (f.shape === null) skipString();
    else f.key = string();
    ws();
    if (text.charCodeAt(i) !== 0x3a) fail("expected ':'");
    i++;
  };
  /** The shape of the next value in `f`: null to skip it. */
  const inner = (f: Frame): Shape | null => {
    const s = f.shape;
    // A container's own shape is never "scalar": one under it is skipped (wrong).
    if (s === null || s === "all" || s === "scalar") return s === "scalar" ? null : s;
    if ("items" in s) return s.items;
    return Object.prototype.hasOwnProperty.call(s.fields, f.key) ? s.fields[f.key] : null;
  };
  const stack: Frame[] = [];
  let next: Shape | null = shape;
  for (;;) {
    ws();
    let v: unknown;
    const c = text.charCodeAt(i);
    if (c === 0x7b || c === 0x5b) {
      // Its depth is one more than the containers open around it.
      if (stack.length >= maxDepth) fail(`nested deeper than ${maxDepth} arrays and objects`);
      const isArray = c === 0x5b;
      i++;
      ws();
      // The container's own shape; one of another kind is skipped.
      const fits =
        next === null || next === "all" || (next !== "scalar" && (isArray ? "items" in next : "fields" in next));
      const s: Shape | null = fits ? next : null;
      const wrong = !fits;
      if (text.charCodeAt(i) === (isArray ? 0x5d : 0x7d)) {
        i++;
        v = wrong ? (isArray ? WRONG_ARRAY : WRONG_OBJECT) : s === null ? IGNORED : isArray ? [] : {};
      } else {
        const f: Frame = {
          isArray,
          shape: s,
          wrong,
          cut: false,
          arr: s !== null && isArray ? [] : undefined,
          obj: s !== null && !isArray ? {} : undefined,
          key: "",
        };
        stack.push(f);
        if (!isArray) key(f);
        next = inner(f);
        continue;
      }
    } else if (c === 0x22) {
      if (next === null) {
        skipString();
        v = IGNORED;
      } else {
        v = string();
      }
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
      v = next === null ? IGNORED : new JsonNumber(m![0]);
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
      if (top.arr !== undefined) {
        if (!top.cut) {
          top.arr.push(v);
          const s = top.shape;
          if (s !== null && s !== "all" && s !== "scalar" && "items" in s && refusedItem(s.items, v)) top.cut = true;
        }
      } else if (top.obj !== undefined) {
        const s = top.shape;
        if (s !== null && s !== "all" && s !== "scalar" && "fields" in s && !Object.prototype.hasOwnProperty.call(s.fields, top.key)) {
          const u = UNNAMED.get(top.obj) ?? { count: 0, loneSurrogate: false };
          u.count++;
          u.loneSurrogate ||= LONE_SURROGATE.test(top.key);
          UNNAMED.set(top.obj, u);
        } else {
          setOwn(top.obj, top.key, v);
        }
      }
      ws();
      const d = text.charCodeAt(i);
      if (d === 0x2c) {
        i++;
        if (!top.isArray) key(top);
        next = inner(top);
        break;
      }
      if (d === (top.isArray ? 0x5d : 0x7d)) {
        i++;
        stack.pop();
        v = top.wrong ? (top.isArray ? WRONG_ARRAY : WRONG_OBJECT) : top.shape === null ? IGNORED : (top.arr ?? top.obj);
        continue;
      }
      fail(top.isArray ? "expected ',' or ']'" : "expected ',' or '}'");
    }
  }
}

/**
 * Whether a value nests deeper than `max` arrays and objects, the value
 * itself being depth 1: SPEC.md §9's nesting limit for an input passed as
 * a value, not as text (a dossier, and every option `verifyDossier` reads:
 * the directory, the revocations, each evidence item). A cycle nests
 * without end. Iterative, and linear in the value's size: a sub-value
 * reached twice is measured once.
 */
export function nestsDeeperThan(root: unknown, max: number = MAX_DOSSIER_DEPTH): boolean {
  const container = (x: unknown): x is object => x !== null && typeof x === "object" && !(x instanceof JsonNumber);
  if (!container(root)) return false;
  const height = new Map<object, number>();
  const open = new Set<object>();
  type Frame = { node: object; children: unknown[]; next: number; height: number };
  const stack: Frame[] = [];
  const enter = (node: object): boolean => {
    if (stack.length + 1 > max) return false;
    open.add(node);
    stack.push({ node, children: Array.isArray(node) ? node : Object.values(node), next: 0, height: 1 });
    return true;
  };
  if (!enter(root)) return true;
  while (stack.length > 0) {
    const f = stack[stack.length - 1];
    if (f.next < f.children.length) {
      const c = f.children[f.next++];
      if (!container(c)) continue;
      if (open.has(c)) return true;
      const h = height.get(c);
      if (h === undefined) {
        if (!enter(c)) return true;
      } else if (stack.length + h > max) {
        return true;
      } else {
        f.height = Math.max(f.height, h + 1);
      }
      continue;
    }
    stack.pop();
    open.delete(f.node);
    height.set(f.node, f.height);
    const parent = stack[stack.length - 1];
    if (parent !== undefined) parent.height = Math.max(parent.height, f.height + 1);
  }
  return false;
}

// ------------------------------------------------------------- reading

type Obj = Record<string, unknown>;
type Reader = (v: unknown, path: string) => unknown;

/** What of a value each reader reads, for parseJsonExact to build; "all" when absent. */
const SHAPES = new WeakMap<Reader, Shape>();
const shapeOf = (r: Reader): Shape => SHAPES.get(r) ?? "all";
function withShape<R extends Reader>(r: R, s: Shape): R {
  SHAPES.set(r, s);
  return r;
}

function isObject(v: unknown): v is Obj {
  return v !== null && typeof v === "object" && !Array.isArray(v) && !(v instanceof JsonNumber);
}

function describe(v: unknown): string {
  if (v instanceof JsonNumber) return `number ${literal(v.literal)}`;
  if (Array.isArray(v) || v === WRONG_ARRAY) return "an array";
  if (v === WRONG_OBJECT) return "an object";
  if (v === null) return "null";
  if (typeof v === "string") return `string ${echo(v)}`;
  if (typeof v === "bigint") return `bigint ${bigintText(v)}`;
  return typeof v === "object" ? "an object" : `${typeof v} ${String(v).slice(0, ECHO_CHARS)}`;
}

/** A bigint in decimal, or a note of its size when that would run past 64 digits. */
function bigintText(n: bigint): string {
  const limit = 10n ** BigInt(ECHO_CHARS);
  return n < limit && n > -limit ? String(n) : "a number of more than 64 digits";
}

function bad(path: string, what: string): never {
  throw new NotADossier(`${path}: ${what}`);
}

const str: Reader = withShape((v, path) => {
  if (typeof v !== "string") bad(path, `expected a string, got ${describe(v)}`);
  if (LONE_SURROGATE.test(v as string)) bad(path, "the string has an unpaired surrogate");
  return v;
}, "scalar");

const bool: Reader = withShape(
  (v, path) => (typeof v === "boolean" ? v : bad(path, `expected a boolean, got ${describe(v)}`)),
  "scalar",
);

/** An unsigned integer up to `max`, as the reference's u64 (or u8) reads it. */
function uint(max: bigint): Reader {
  return withShape((v, path) => {
    let n: bigint;
    if (v instanceof JsonNumber) {
      if (!/^(0|[1-9][0-9]*)$/.test(v.literal)) bad(path, `${literal(v.literal)} is not an unsigned integer literal`);
      // 2^64 - 1 has 20 digits: a longer literal is out of range, and is
      // not converted (BigInt of millions of digits takes seconds).
      if (v.literal.length > 20) bad(path, `${literal(v.literal)} is out of range`);
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
    if (n < 0n || n > max) bad(path, `${bigintText(n)} is out of range`);
    return n <= MAX_SAFE ? Number(n) : n;
  }, "scalar");
}

const u64 = uint(U64_MAX);
const u8 = uint(255n);

function list(item: Reader): Reader {
  return withShape(
    (v, path) => {
      if (!Array.isArray(v)) bad(path, `expected an array, got ${describe(v)}`);
      return (v as unknown[]).map((x, i) => item(x, `${path}[${i}]`));
    },
    { items: shapeOf(item) },
  );
}

/** A unit variant: its name, or `{"name": null}`. */
function unitVariant(variants: readonly string[]): Reader {
  return withShape((v, path) => {
    if (typeof v === "string" && variants.includes(v)) return v;
    if (isObject(v) && !DUPLICATED.has(v)) {
      const keys = Object.keys(v);
      if (memberCount(v) === 1 && keys.length === 1 && variants.includes(keys[0]) && v[keys[0]] === null) return keys[0];
    }
    return bad(path, `expected one of ${variants.join(", ")}, got ${describe(v)}`);
  }, unitShape(variants));
}

/** A unit variant's shape: its name (a string), or an object of variant names, each null. */
function unitShape(variants: readonly string[]): Shape {
  const fields: Record<string, Shape> = Object.create(null);
  for (const name of variants) fields[name] = "scalar";
  return { fields, scalar: true };
}

interface Field {
  read: Reader;
  /** Must be present (and not null unless nullable). */
  required?: boolean;
  /** `Option<T>`: null reads as absent. */
  nullable?: boolean;
}

/**
 * A struct: an object; known keys once, exactly, typed; other keys ignored
 * (and, read from text, never built: their values are {@link IGNORED}).
 */
function struct(fields: Record<string, Field>): Reader {
  const shape: Record<string, Shape> = Object.create(null);
  for (const [name, f] of Object.entries(fields)) shape[name] = shapeOf(f.read);
  return withShape(structReader(fields), { fields: shape });
}

function structReader(fields: Record<string, Field>): Reader {
  return (v, path) => {
    if (!isObject(v)) bad(path, `expected an object, got ${describe(v)}`);
    const o = v as Obj;
    if (UNNAMED.get(o)?.loneSurrogate || Object.keys(o).some((k) => LONE_SURROGATE.test(k))) {
      bad(path, "a key has an unpaired surrogate");
    }
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
export const readWitnessEntry: Reader = withShape((v, path) => {
  const e = WITNESS_ENTRY_STRUCT(v, path) as Obj;
  e.runtime ??= "human";
  e.is_project_operated ??= false;
  return e;
}, shapeOf(WITNESS_ENTRY_STRUCT));

const WITNESS_DIRECTORY = struct({ witnesses: req(list(readWitnessEntry)) });

const CUSTODY_UNIT = ["self_held", "platform_held", "hsm", "kms", "session_delegated", "undisclosed"] as const;
const THRESHOLD = struct({ k: req(str), n: req(str) });

/** KeyCustody: a unit variant, or `{"threshold": {"k": "..", "n": ".."}}`. */
const CUSTODY_VARIANT = unitVariant(CUSTODY_UNIT);
const custody: Reader = withShape(
  (v, path) => {
    if (isObject(v) && !DUPLICATED.has(v) && memberCount(v) === 1 && Object.prototype.hasOwnProperty.call(v, "threshold")) {
      return { threshold: THRESHOLD(v.threshold, `${path}.threshold`) };
    }
    return CUSTODY_VARIANT(v, path);
  },
  { fields: { ...(unitShape(CUSTODY_UNIT) as { fields: Record<string, Shape> }).fields, threshold: shapeOf(THRESHOLD) }, scalar: true },
);

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
    // Number() rounds to nearest, ties to even, as serde_json with
    // float_roundtrip and Go's strconv.ParseFloat do: 1.7976931348623158e308
    // is finite, 1.7976931348623159e308 is not.
    if (!Number.isFinite(Number(v.literal))) bad(path, `number ${literal(v.literal)} is out of range`);
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
 * A dossier from its JSON text, as the reference reads it
 * (`Dossier::from_json`): parsed exactly, stopping at the first array or
 * object past {@link MAX_DOSSIER_DEPTH}, with only the members the
 * dossier's types name built. Throws {@link NotADossier} or a SyntaxError.
 */
export function readDossierText(text: string): ReadDossier {
  return readParsed(parseJsonExact(text, shapeOf(DOSSIER), MAX_DOSSIER_DEPTH));
}

/**
 * A dossier, from the value `JSON.parse` produced (or one built in code),
 * as the reference deserialises it; a value nested deeper than
 * {@link MAX_DOSSIER_DEPTH} is not a dossier, as its text would not be.
 * Throws {@link NotADossier}.
 */
export function readDossier(value: unknown): ReadDossier {
  if (nestsDeeperThan(value, MAX_DOSSIER_DEPTH)) {
    bad("dossier", `nested deeper than ${MAX_DOSSIER_DEPTH} arrays and objects`);
  }
  return readParsed(value);
}

function readParsed(value: unknown): ReadDossier {
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
