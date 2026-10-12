/**
 * An offline dossier verifier in TypeScript (spec/SPEC.md §3–§9), with no
 * native code and no `witness-log` binary: SHA-256 and Ed25519 come from
 * `node:crypto`. It is a second implementation of the verification
 * procedure, independent of the Rust reference verifier, and it produces
 * the same four verdicts for the same inputs.
 *
 * One known difference, stated rather than hidden: SPEC §6 requires strict
 * Ed25519 verification (reject small-order and mixed-order components).
 * `node:crypto` rejects non-canonical scalars but does not reject
 * small-order points, so a deliberately degenerate signature that the
 * reference verifier refuses could pass here. Honestly generated
 * signatures are identical under both. For a load-bearing decision, run
 * the Rust verifier as well (`WitnessLogCLI.verify`, or
 * `verifyDossierNative` in `@witness-log/node`).
 */
import { createHash, createPublicKey, verify as cryptoVerify, type KeyObject } from "node:crypto";
import { EXIT_CODES, type Verdict } from "./cli.js";

// ---------------------------------------------------------------- types

/** A leaf as it appears in a dossier (SPEC §3). */
export interface Leaf {
  index: number;
  leaf_type: number;
  timestamp_ms: number;
  session_pubkey: string;
  payload_hash: string;
  redacted_index?: number | null;
  revoked_identity?: string | null;
  handoff_direction?: "Sent" | "Received" | null;
  counterparty_pubkey?: string | null;
  handoff_state_hash?: string | null;
  authorization_event_kind?: AuthorizationEventKind | null;
  authorization_scope_hash?: string | null;
  anchor_url?: string | null;
  anchor_proof_json?: string | null;
  anchor_proof_hash?: string | null;
}

export type AuthorizationEventKind =
  | "GrantedByMe"
  | "GrantedToMe"
  | "RevokedByMe"
  | "RevokedToMe"
  | "ScopeChangedByMe"
  | "ScopeChangedToMe";

/** SPEC §6. */
export interface SignedTreeHead {
  tree_size: number;
  root_hash: string;
  timestamp_ms: number;
  sig_alg: string;
  signer_pubkey: string;
  signature: string;
}

/** SPEC §7 (native) or §9.3 (with `c2sp_origin`). */
export interface WitnessReceipt {
  witness_pubkey: string;
  tree_size: number;
  root_hash: string;
  witnessed_at_ms: number;
  signature: string;
  c2sp_origin?: string | null;
}

export interface WitnessEntry {
  name: string;
  operator_org: string;
  url: string;
  pubkey: string;
  runtime?: "human" | "agent";
  compute_provider?: string | null;
  is_project_operated?: boolean;
}

export interface WitnessDirectory {
  witnesses: WitnessEntry[];
}

/** SPEC §5. */
export interface KeyBindingStatement {
  identity_pubkey: string;
  session_pubkey: string;
  session_number: number;
  timestamp_ms: number;
  custody?: unknown;
  not_after_ms?: number | null;
  signature: string;
}

export interface RevocationStatement {
  identity_pubkey: string;
  as_of_ms: number;
  reason: string;
  signature: string;
}

/** SPEC §9. */
export interface Dossier {
  identity_pubkey: string;
  leaves: Leaf[];
  checkpoint: SignedTreeHead;
  witness_receipts?: WitnessReceipt[];
  witness_directory?: WitnessDirectory;
  key_bindings?: KeyBindingStatement[];
  revocations?: RevocationStatement[];
}

export interface QuorumResult {
  tree_size: number;
  valid_receipts: number;
  total_directory_witnesses: number;
  distinct_operators_represented: number;
  distinct_operators_in_directory: number;
  quorum_fraction: number;
  diversity_fraction: number;
  distinct_compute_providers_represented: number;
  distinct_compute_providers_in_directory: number;
  compute_diversity_fraction: number;
  project_operated_receipts: number;
  distinct_independent_operators: number;
  independent_operators_represented: string[];
  meets_count_threshold: boolean;
  count_gate: string;
  split_view_resistant: boolean;
  newest_trusted_witness_ms: number | null;
}

/** Same fields as the Rust `DossierReport` (what `witness-log verify --json` prints under `report`). */
export interface DossierReport {
  checkpoint_signature_valid: boolean;
  identity_bound: boolean;
  leaves_structurally_valid: boolean;
  bindings_valid: boolean;
  bindings_asserted: boolean;
  leaf_count: number;
  claimed_tree_size: number;
  merkle_continuity_valid: boolean;
  externally_anchored: boolean;
  identity_pinned: boolean;
  internally_consistent: boolean;
  quorum: QuorumResult | null;
  verdict: "witnessed" | "consistent_unwitnessed" | "unanchored" | "diverged";
}

export interface VerifyDossierOptions {
  /** The identity you expect (64 hex), obtained out of band. Never read it from the dossier. */
  identity?: string;
  /** A witness directory YOU trust: `{witnesses: [...]}` or a bare array. Without it the verdict is capped at UNANCHORED. */
  directory?: WitnessDirectory | WitnessEntry[];
  /** Receipt-count gate as a fraction of the directory. Default 0.66 (the CLI's default). */
  threshold?: number;
  /** Receipt-count gate as an absolute number of distinct cosigning witnesses; replaces `threshold`. */
  minWitnesses?: number;
}

export interface DossierVerification {
  verdict: Verdict;
  /** 0 / 10 / 20 / 30, the CLI's contract. */
  exitCode: number;
  /** True only for WITNESSED. */
  ok: boolean;
  identityPubkey: string;
  identityPinned: boolean;
  directoryPinned: boolean;
  internallyConsistent: boolean;
  /** Which checks failed, in plain words. Empty unless DIVERGED. */
  failures: string[];
  report: DossierReport;
}

export const MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED = 2;
const DEFAULT_THRESHOLD = 0.66;
const CANONICAL_ORIGIN_PREFIX = "witness-log/";
const PROJECT_OPERATED_BUCKET = "\0witness-log-project-operated\0";

// ------------------------------------------------------------ primitives

export function sha256(...parts: Uint8Array[]): Uint8Array {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error(`not hex: ${hex.slice(0, 16)}`);
  return new Uint8Array(Buffer.from(hex, "hex"));
}

export function bytesToHex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

function u64be(n: number | bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n));
  return out;
}

function u32be(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n);
  return out;
}

const utf8 = new TextEncoder();

/** `lp(field)`: 4-byte big-endian length, then the bytes (SPEC §3). */
function lp(bytes: Uint8Array): Uint8Array[] {
  return [u32be(bytes.length), bytes];
}

function concat(parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

const SPKI_ED25519_PREFIX = hexToBytes("302a300506032b6570032100");

function ed25519Key(pubkeyHex: string): KeyObject | null {
  let raw: Uint8Array;
  try {
    raw = hexToBytes(pubkeyHex);
  } catch {
    return null;
  }
  if (raw.length !== 32) return null;
  try {
    return createPublicKey({ key: Buffer.from(concat([SPKI_ED25519_PREFIX, raw])), format: "der", type: "spki" });
  } catch {
    return null;
  }
}

/** Ed25519 verification of `message` under a hex public key and hex signature. False on any malformed input. */
export function ed25519Verify(pubkeyHex: string, message: Uint8Array, signatureHex: string): boolean {
  const key = ed25519Key(pubkeyHex);
  if (key === null) return false;
  let sig: Uint8Array;
  try {
    sig = hexToBytes(signatureHex);
  } catch {
    return false;
  }
  if (sig.length !== 64) return false;
  try {
    return cryptoVerify(null, message, key, sig);
  } catch {
    return false;
  }
}

// ------------------------------------------------------------- SPEC §3

const HANDOFF_DIRECTION_TAG: Record<string, number> = { Sent: 0, Received: 1 };
const AUTH_KIND_TAG: Record<string, number> = {
  GrantedByMe: 0,
  GrantedToMe: 1,
  RevokedByMe: 2,
  RevokedToMe: 3,
  ScopeChangedByMe: 4,
  ScopeChangedToMe: 5,
};

export const LEAF_TYPES = {
  PassiveMemory: 0,
  ActiveIntent: 1,
  ActiveResult: 2,
  Redaction: 3,
  KeyRevocation: 4,
  HandoffAttestation: 5,
  AuthorizationEvent: 6,
  ExternalAnchor: 7,
} as const;

/** The canonical bytes hashed into the tree for a leaf (SPEC §3). */
export function leafCanonicalBytes(leaf: Leaf): Uint8Array {
  const parts: Uint8Array[] = [];
  parts.push(new Uint8Array([leaf.leaf_type]));
  parts.push(u64be(leaf.index));
  parts.push(u64be(leaf.timestamp_ms));
  parts.push(...lp(utf8.encode(leaf.session_pubkey)));
  parts.push(...lp(utf8.encode(leaf.payload_hash)));
  if (leaf.redacted_index !== undefined && leaf.redacted_index !== null) {
    parts.push(new Uint8Array([1]), u64be(leaf.redacted_index));
  } else {
    parts.push(new Uint8Array([0]));
  }
  if (leaf.revoked_identity !== undefined && leaf.revoked_identity !== null) {
    parts.push(new Uint8Array([1]), ...lp(utf8.encode(leaf.revoked_identity)));
  } else {
    parts.push(new Uint8Array([0]));
  }
  const optStr = (v: string | null | undefined) => {
    if (v !== undefined && v !== null) parts.push(new Uint8Array([1]), ...lp(utf8.encode(v)));
    else parts.push(new Uint8Array([0]));
  };
  const optTag = (v: string | null | undefined, table: Record<string, number>) => {
    if (v !== undefined && v !== null && v in table) parts.push(new Uint8Array([1, table[v]]));
    else parts.push(new Uint8Array([0]));
  };
  if (leaf.leaf_type === LEAF_TYPES.HandoffAttestation) {
    optTag(leaf.handoff_direction, HANDOFF_DIRECTION_TAG);
    optStr(leaf.counterparty_pubkey);
    optStr(leaf.handoff_state_hash);
  }
  if (leaf.leaf_type === LEAF_TYPES.AuthorizationEvent) {
    optTag(leaf.authorization_event_kind, AUTH_KIND_TAG);
    optStr(leaf.counterparty_pubkey);
    optStr(leaf.authorization_scope_hash);
  }
  if (leaf.leaf_type === LEAF_TYPES.ExternalAnchor) {
    optStr(leaf.anchor_url);
    optStr(leaf.anchor_proof_hash);
  }
  return concat(parts);
}

/** RFC 6962 leaf hash: `SHA256(0x00 || data)`. */
export function leafHash(canonicalBytes: Uint8Array): Uint8Array {
  return sha256(new Uint8Array([0]), canonicalBytes);
}

function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(new Uint8Array([1]), left, right);
}

/** RFC 6962 §2.1 root over leaf hashes. Empty tree: `SHA256("")`. */
export function merkleRoot(leafHashes: Uint8Array[]): Uint8Array {
  const n = leafHashes.length;
  if (n === 0) return sha256();
  if (n === 1) return leafHashes[0];
  let k = 1;
  while (k * 2 < n) k *= 2;
  return nodeHash(merkleRoot(leafHashes.slice(0, k)), merkleRoot(leafHashes.slice(k)));
}

/** RFC 6962 §2.1.1 inclusion proof check. All hashes raw bytes. */
export function verifyInclusion(
  leaf: Uint8Array,
  leafIndex: number,
  treeSize: number,
  proof: Uint8Array[],
  root: Uint8Array,
): boolean {
  if (leafIndex >= treeSize) return false;
  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      r = nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && Buffer.from(r).equals(Buffer.from(root));
}

/** SPEC §8: `SHA256(bucket_pad(payload) || salt || leaf_index)`. */
export function payloadHash(payload: Uint8Array, salt: Uint8Array, leafIndex: number): Uint8Array {
  if (salt.length !== 32) throw new Error("salt must be 32 bytes");
  const bucket = (Math.floor(payload.length / 256) + 1) * 256;
  const padded = new Uint8Array(8 + bucket);
  padded.set(u64be(payload.length), 0);
  padded.set(payload, 8);
  return sha256(padded, salt, u64be(leafIndex));
}

/**
 * Check a disclosed payload against a leaf's committed `payload_hash`
 * (SPEC §8). `salt` is the 32-byte salt the log held for that leaf.
 */
export function verifyDisclosure(leaf: Leaf, payload: Uint8Array, salt: Uint8Array): boolean {
  return bytesToHex(payloadHash(payload, salt, leaf.index)) === leaf.payload_hash.toLowerCase();
}

/** `witness-log/<64 lowercase hex of the identity key>` (SPEC §9.3). */
export function canonicalOrigin(identityPubkeyHex: string): string {
  return CANONICAL_ORIGIN_PREFIX + identityPubkeyHex.toLowerCase();
}

// ------------------------------------------------------- leaf validity

const LOWER_HEX64 = /^[0-9a-f]{64}$/;

/** `Leaf::validate` for one leaf at `expectedIndex`; the reason it is invalid, or null. */
/** The payload_hash every marker leaf (0x03, 0x04) commits. */
export const ZERO_HASH_HEX = "0".repeat(64);

export function validateLeaf(leaf: Leaf, expectedIndex: number): string | null {
  if (leaf.index !== expectedIndex) return `leaf index ${leaf.index} does not match its position ${expectedIndex}`;
  if (!Number.isInteger(leaf.leaf_type) || leaf.leaf_type < 0 || leaf.leaf_type > 7) {
    return `unrecognized leaf_type tag: ${leaf.leaf_type}`;
  }
  if (typeof leaf.session_pubkey !== "string" || !LOWER_HEX64.test(leaf.session_pubkey)) {
    return `field session_pubkey must be exactly 64 lowercase hex characters`;
  }
  if (typeof leaf.payload_hash !== "string" || !LOWER_HEX64.test(leaf.payload_hash)) {
    return `field payload_hash must be exactly 64 lowercase hex characters`;
  }
  const present = (v: unknown) => v !== undefined && v !== null;
  const need = (ok: boolean, field: string) => (ok ? null : `leaf_type ${leaf.leaf_type} requires field ${field}`);
  // Fields of another leaf type are not committed by the root, so they are
  // refused rather than displayed (SPEC §2, 0.4.2). Markers commit the
  // all-zero payload hash and a redaction names an earlier leaf.
  const t = leaf.leaf_type;
  const stray: Array<[boolean, unknown, string]> = [
    [t !== LEAF_TYPES.Redaction, leaf.redacted_index, "redacted_index"],
    [t !== LEAF_TYPES.KeyRevocation, leaf.revoked_identity, "revoked_identity"],
    [t !== LEAF_TYPES.HandoffAttestation, leaf.handoff_direction, "handoff_direction"],
    [t !== LEAF_TYPES.HandoffAttestation, leaf.handoff_state_hash, "handoff_state_hash"],
    [t !== LEAF_TYPES.AuthorizationEvent, leaf.authorization_event_kind, "authorization_event_kind"],
    [t !== LEAF_TYPES.AuthorizationEvent, leaf.authorization_scope_hash, "authorization_scope_hash"],
    [t !== LEAF_TYPES.HandoffAttestation && t !== LEAF_TYPES.AuthorizationEvent, leaf.counterparty_pubkey, "counterparty_pubkey"],
    [t !== LEAF_TYPES.ExternalAnchor, leaf.anchor_url, "anchor_url"],
    [t !== LEAF_TYPES.ExternalAnchor, leaf.anchor_proof_json, "anchor_proof_json"],
    [t !== LEAF_TYPES.ExternalAnchor, leaf.anchor_proof_hash, "anchor_proof_hash"],
  ];
  for (const [when, v, field] of stray) {
    if (when && present(v)) return `leaf_type ${t} must not carry field ${field} (it is not committed by the root)`;
  }
  if ((t === LEAF_TYPES.Redaction || t === LEAF_TYPES.KeyRevocation) && leaf.payload_hash !== ZERO_HASH_HEX) {
    return `field payload_hash is invalid: markers commit the all-zero hash`;
  }
  if (t === LEAF_TYPES.Redaction && present(leaf.redacted_index) && leaf.redacted_index! >= expectedIndex) {
    return `field redacted_index is invalid: must name an earlier leaf`;
  }
  let e: string | null = null;
  switch (leaf.leaf_type) {
    case LEAF_TYPES.Redaction:
      e = need(present(leaf.redacted_index), "redacted_index");
      break;
    case LEAF_TYPES.KeyRevocation:
      e = need(present(leaf.revoked_identity), "revoked_identity");
      break;
    case LEAF_TYPES.HandoffAttestation:
      e =
        need(present(leaf.handoff_direction) && leaf.handoff_direction! in HANDOFF_DIRECTION_TAG, "handoff_direction") ??
        need(present(leaf.counterparty_pubkey), "counterparty_pubkey") ??
        need(present(leaf.handoff_state_hash), "handoff_state_hash");
      break;
    case LEAF_TYPES.AuthorizationEvent:
      e =
        need(
          present(leaf.authorization_event_kind) && leaf.authorization_event_kind! in AUTH_KIND_TAG,
          "authorization_event_kind",
        ) ??
        need(present(leaf.counterparty_pubkey), "counterparty_pubkey") ??
        need(present(leaf.authorization_scope_hash), "authorization_scope_hash");
      break;
    case LEAF_TYPES.ExternalAnchor: {
      e = need(present(leaf.anchor_url), "anchor_url") ?? need(present(leaf.anchor_proof_hash), "anchor_proof_hash");
      if (e === null && present(leaf.anchor_proof_json)) {
        const actual = bytesToHex(sha256(utf8.encode(leaf.anchor_proof_json!)));
        if (actual !== leaf.anchor_proof_hash) {
          e = `anchor_proof_json does not hash to the committed anchor_proof_hash (committed ${leaf.anchor_proof_hash}, actual ${actual})`;
        }
      }
      if (e === null && !/^https?:\/\//.test(leaf.anchor_url!)) {
        e = `field anchor_url must be an http:// or https:// URL`;
      }
      break;
    }
    default:
      break;
  }
  return e;
}

/** `validate_sequence`: every leaf against its own position. */
export function validateLeaves(leaves: Leaf[]): string | null {
  for (let i = 0; i < leaves.length; i++) {
    const e = validateLeaf(leaves[i], i);
    if (e !== null) return e;
  }
  return null;
}

// ---------------------------------------------------- signed statements

/** SPEC §6 checkpoint signature. */
export function verifyCheckpoint(sth: SignedTreeHead): boolean {
  if (sth.sig_alg !== "ed25519") return false;
  let root: Uint8Array;
  try {
    root = hexToBytes(sth.root_hash);
  } catch {
    return false;
  }
  if (root.length !== 32) return false;
  const msg = concat([
    utf8.encode("witness-log-sth-v2"),
    ...lp(utf8.encode(sth.sig_alg)),
    ...lp(utf8.encode(sth.signer_pubkey)),
    u64be(sth.tree_size),
    root,
    u64be(sth.timestamp_ms),
  ]);
  return ed25519Verify(sth.signer_pubkey, msg, sth.signature);
}

/** SPEC §5 key binding signature (signature only, not expiry). */
export function verifyKeyBinding(b: KeyBindingStatement): boolean {
  let identity: Uint8Array;
  let session: Uint8Array;
  try {
    identity = hexToBytes(b.identity_pubkey);
    session = hexToBytes(b.session_pubkey);
  } catch {
    return false;
  }
  if (identity.length !== 32 || session.length !== 32) return false;
  const parts = [
    utf8.encode("witness-log-key-bind-v1"),
    identity,
    session,
    u64be(b.session_number),
    u64be(b.timestamp_ms),
  ];
  if (b.not_after_ms !== undefined && b.not_after_ms !== null) parts.push(new Uint8Array([1]), u64be(b.not_after_ms));
  else parts.push(new Uint8Array([0]));
  return ed25519Verify(b.identity_pubkey, concat(parts), b.signature);
}

/** SPEC §5 revocation signature. */
export function verifyRevocation(r: RevocationStatement): boolean {
  let identity: Uint8Array;
  try {
    identity = hexToBytes(r.identity_pubkey);
  } catch {
    return false;
  }
  if (identity.length !== 32) return false;
  const msg = concat([utf8.encode("witness-log-revoke-v1"), identity, u64be(r.as_of_ms), utf8.encode(r.reason)]);
  return ed25519Verify(r.identity_pubkey, msg, r.signature);
}

/** SPEC §7 native receipt or §9.3 C2SP cosignature receipt, against the dossier's checkpoint. */
export function verifyReceipt(r: WitnessReceipt, against: SignedTreeHead): boolean {
  if (r.tree_size !== against.tree_size || r.root_hash !== against.root_hash) return false;
  if (r.c2sp_origin !== undefined && r.c2sp_origin !== null) {
    if (ed25519Key(against.signer_pubkey) === null) return false;
    if (r.c2sp_origin !== canonicalOrigin(against.signer_pubkey)) return false;
    if (r.witnessed_at_ms % 1000 !== 0) return false;
    let root: Uint8Array;
    try {
      root = hexToBytes(r.root_hash);
    } catch {
      return false;
    }
    if (root.length !== 32) return false;
    const body = `${r.c2sp_origin}\n${r.tree_size}\n${Buffer.from(root).toString("base64")}\n`;
    const msg = `cosignature/v1\ntime ${r.witnessed_at_ms / 1000}\n${body}`;
    return ed25519Verify(r.witness_pubkey, utf8.encode(msg), r.signature);
  }
  const msg = concat([
    utf8.encode("witness-log-witness-receipt-v2"),
    ...lp(utf8.encode(r.witness_pubkey)),
    ...lp(utf8.encode(against.signer_pubkey)),
    u64be(r.tree_size),
    ...lp(utf8.encode(r.root_hash)),
    u64be(r.witnessed_at_ms),
  ]);
  return ed25519Verify(r.witness_pubkey, msg, r.signature);
}

// ---------------------------------------------------------------- quorum

function normalizeLabel(s: string): string {
  return s.split(/\s+/).filter((x) => x !== "").join(" ").toLowerCase();
}

function operatorKey(w: WitnessEntry): string {
  return w.is_project_operated ? PROJECT_OPERATED_BUCKET : normalizeLabel(w.operator_org ?? "");
}

function computeProviderKey(w: WitnessEntry): string {
  if (w.is_project_operated) return PROJECT_OPERATED_BUCKET;
  return w.compute_provider === undefined || w.compute_provider === null ? "undisclosed" : normalizeLabel(w.compute_provider);
}

export function evaluateQuorum(
  sth: SignedTreeHead,
  receipts: WitnessReceipt[],
  directory: WitnessDirectory,
  threshold: number,
): QuorumResult {
  const signer = sth.signer_pubkey.toLowerCase();
  const subjectEntry = directory.witnesses.find((w) => w.pubkey.toLowerCase() === signer);
  const subjectOperator = subjectEntry ? operatorKey(subjectEntry) : undefined;
  const operators = new Set<string>();
  const providers = new Set<string>();
  const counted = new Set<string>();
  const independent = new Set<string>();
  let projectOperated = 0;
  let newest: number | null = null;
  for (const r of receipts) {
    if (!verifyReceipt(r, sth)) continue;
    const key = r.witness_pubkey.toLowerCase();
    const entry = directory.witnesses.find((w) => w.pubkey.toLowerCase() === key);
    if (!entry) continue;
    if (counted.has(key)) continue;
    counted.add(key);
    operators.add(operatorKey(entry));
    if (!entry.is_project_operated) {
      const op = normalizeLabel(entry.operator_org ?? "");
      if (subjectOperator !== op) independent.add(op);
    }
    providers.add(computeProviderKey(entry));
    if (entry.is_project_operated) projectOperated += 1;
    newest = newest === null ? r.witnessed_at_ms : Math.max(newest, r.witnessed_at_ms);
  }
  const valid = counted.size;
  const total = Math.max(directory.witnesses.length, 1);
  const opsInDir = Math.max(new Set(directory.witnesses.map(operatorKey)).size, 1);
  const provsInDir = Math.max(new Set(directory.witnesses.map(computeProviderKey)).size, 1);
  const fraction = valid / total;
  return {
    tree_size: sth.tree_size,
    valid_receipts: valid,
    total_directory_witnesses: directory.witnesses.length,
    distinct_operators_represented: operators.size,
    distinct_operators_in_directory: opsInDir,
    quorum_fraction: fraction,
    diversity_fraction: operators.size / opsInDir,
    distinct_compute_providers_represented: providers.size,
    distinct_compute_providers_in_directory: provsInDir,
    compute_diversity_fraction: providers.size / provsInDir,
    project_operated_receipts: projectOperated,
    distinct_independent_operators: independent.size,
    independent_operators_represented: [...independent].sort(),
    meets_count_threshold: fraction >= threshold,
    count_gate: `fraction >= ${threshold}`,
    split_view_resistant: 2 * valid > directory.witnesses.length,
    newest_trusted_witness_ms: newest,
  };
}

// --------------------------------------------------------------- verify

function bindingsAndRevocationsValid(
  leaves: Leaf[],
  identity: string,
  bindings: KeyBindingStatement[],
  revocations: RevocationStatement[],
): string | null {
  if (bindings.length === 0 && revocations.length === 0) return null;
  const id = identity.toLowerCase();
  const bySession = new Map<string, KeyBindingStatement>();
  for (const b of bindings) {
    if (b.identity_pubkey.toLowerCase() !== id) return "a key binding names a different identity";
    if (!verifyKeyBinding(b)) return `key binding for session ${b.session_pubkey.slice(0, 8)}… has an invalid signature`;
    bySession.set(b.session_pubkey.toLowerCase(), b);
  }
  let revokedAsOf: number | null = null;
  for (const r of revocations) {
    if (r.identity_pubkey.toLowerCase() !== id) return "a revocation names a different identity";
    if (!verifyRevocation(r)) return "a revocation has an invalid signature";
    revokedAsOf = revokedAsOf === null ? r.as_of_ms : Math.min(revokedAsOf, r.as_of_ms);
  }
  for (const l of leaves) {
    const b = bySession.get(l.session_pubkey.toLowerCase());
    if (!b) return `leaf ${l.index} was authored by a session key with no binding to this identity`;
    if (b.not_after_ms !== undefined && b.not_after_ms !== null && l.timestamp_ms > b.not_after_ms) {
      return `leaf ${l.index} postdates its session binding's expiry`;
    }
    if (revokedAsOf !== null && l.timestamp_ms >= revokedAsOf) {
      return `leaf ${l.index} postdates the identity's revocation`;
    }
  }
  return null;
}

function asDirectory(d: WitnessDirectory | WitnessEntry[] | undefined): WitnessDirectory | undefined {
  if (d === undefined) return undefined;
  if (Array.isArray(d)) return { witnesses: d };
  if (typeof d === "object" && d !== null && Array.isArray(d.witnesses)) return d;
  throw new TypeError('directory must be {"witnesses": [...]} or an array of witness entries');
}

const VERDICT_NAME: Record<DossierReport["verdict"], Verdict> = {
  witnessed: "WITNESSED",
  consistent_unwitnessed: "CONSISTENT-UNWITNESSED",
  unanchored: "UNANCHORED",
  diverged: "DIVERGED",
};

/**
 * Verify a dossier offline (SPEC §9.1–§9.2). Synchronous; never throws on
 * a hostile dossier (a malformed one is DIVERGED), only on bad options.
 */
export function verifyDossier(dossier: Dossier | string, opts: VerifyDossierOptions = {}): DossierVerification {
  const d: Dossier = typeof dossier === "string" ? (JSON.parse(dossier) as Dossier) : dossier;
  if (opts.identity !== undefined && !/^[0-9a-fA-F]{64}$/.test(opts.identity)) {
    throw new TypeError("identity must be a 32-byte Ed25519 public key as 64 hex characters");
  }
  const threshold = opts.threshold ?? DEFAULT_THRESHOLD;
  if (!(threshold >= 0 && threshold <= 1)) throw new RangeError(`threshold must be between 0 and 1, got ${threshold}`);
  if (opts.minWitnesses !== undefined && (!Number.isInteger(opts.minWitnesses) || opts.minWitnesses < 1)) {
    throw new RangeError("minWitnesses must be at least 1");
  }
  const trusted = asDirectory(opts.directory);

  const failures: string[] = [];
  const checkpoint = d.checkpoint ?? ({} as SignedTreeHead);
  const leaves = Array.isArray(d.leaves) ? d.leaves : [];
  const signer = String(checkpoint.signer_pubkey ?? "");

  const checkpointSignatureValid = verifyCheckpoint(checkpoint);
  if (!checkpointSignatureValid) failures.push("checkpoint signature does not verify");

  const selfConsistent = String(d.identity_pubkey ?? "").toLowerCase() === signer.toLowerCase();
  const pinOk = opts.identity === undefined || opts.identity.toLowerCase() === signer.toLowerCase();
  const identityBound = selfConsistent && pinOk;
  if (!selfConsistent) failures.push("dossier identity_pubkey does not match checkpoint.signer_pubkey");
  if (!pinOk) failures.push("checkpoint.signer_pubkey is not the identity you expected");

  const leafError = validateLeaves(leaves);
  if (leafError !== null) failures.push(leafError);

  const bindingError = bindingsAndRevocationsValid(
    leaves,
    String(d.identity_pubkey ?? ""),
    d.key_bindings ?? [],
    d.revocations ?? [],
  );
  if (bindingError !== null) failures.push(bindingError);
  const bindingsAsserted = (d.key_bindings ?? []).length > 0 || (d.revocations ?? []).length > 0;

  let rebuilt = "";
  try {
    rebuilt = bytesToHex(merkleRoot(leaves.map((l) => leafHash(leafCanonicalBytes(l)))));
  } catch {
    rebuilt = "";
  }
  const merkleOk = leaves.length === checkpoint.tree_size && rebuilt === checkpoint.root_hash;
  if (!merkleOk) failures.push("leaves do not reproduce the signed root");

  const externallyAnchored = trusted !== undefined;
  let quorum: QuorumResult | null = null;
  const receipts = Array.isArray(d.witness_receipts) ? d.witness_receipts : [];
  if (trusted !== undefined && receipts.length > 0) {
    quorum = evaluateQuorum(checkpoint, receipts, trusted, threshold);
    if (opts.minWitnesses !== undefined) {
      quorum.meets_count_threshold = quorum.valid_receipts >= opts.minWitnesses;
      quorum.count_gate = `count >= ${opts.minWitnesses}`;
    }
  }

  const internallyConsistent =
    checkpointSignatureValid && identityBound && leafError === null && bindingError === null && merkleOk;
  let verdict: DossierReport["verdict"];
  if (!internallyConsistent) verdict = "diverged";
  else if (!externallyAnchored) verdict = "unanchored";
  else if (quorum === null || !quorum.meets_count_threshold) verdict = "consistent_unwitnessed";
  else if (quorum.distinct_independent_operators >= MIN_INDEPENDENT_OPERATORS_FOR_WITNESSED) verdict = "witnessed";
  else verdict = "consistent_unwitnessed";

  const report: DossierReport = {
    checkpoint_signature_valid: checkpointSignatureValid,
    identity_bound: identityBound,
    leaves_structurally_valid: leafError === null,
    bindings_valid: bindingError === null,
    bindings_asserted: bindingsAsserted,
    leaf_count: leaves.length,
    claimed_tree_size: Number(checkpoint.tree_size ?? 0),
    merkle_continuity_valid: merkleOk,
    externally_anchored: externallyAnchored,
    identity_pinned: opts.identity !== undefined,
    internally_consistent: internallyConsistent,
    quorum,
    verdict,
  };
  const name = VERDICT_NAME[verdict];
  return {
    verdict: name,
    exitCode: EXIT_CODES[name],
    ok: name === "WITNESSED",
    identityPubkey: signer,
    identityPinned: opts.identity !== undefined,
    directoryPinned: externallyAnchored,
    internallyConsistent,
    failures: verdict === "diverged" ? failures : [],
    report,
  };
}
