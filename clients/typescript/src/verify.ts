/**
 * An offline dossier verifier in TypeScript (spec/SPEC.md §3–§9), with no
 * native code and no `witness-log` binary: SHA-256 and Ed25519 come from
 * `node:crypto`. It is a second implementation of the verification
 * procedure, independent of the Rust reference verifier, and it produces
 * the same five verdicts and exit codes for the same inputs.
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
  /** RFC-0005: the tree size at which the revocation takes effect; absent in v1. */
  as_of_index?: number | null;
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
  /**
   * RFC-0001, EXPERIMENTAL: this checkpoint's entry in an organisation's
   * fleet checkpoint log (a {@link FleetAnchor} when well-formed). Read
   * only with `acceptFleetAnchor`.
   */
  fleet_anchor?: unknown;
}

/** RFC-0001 (EXPERIMENTAL): the dossier's `fleet_anchor`. */
export interface FleetAnchor {
  origin: string;
  entry_index: number;
  entry_bytes_b64: string;
  /** Hex hashes, innermost first. */
  inclusion_proof: string[];
  fleet_checkpoint_note: string;
}

/** What the verifier did with a dossier's fleet anchor. */
export interface FleetAnchorReport {
  status: "ignored" | "verified" | "failed";
  origin: string | null;
  entry_index: number | null;
  /** Only for a verified anchor. */
  fleet_tree_size: number | null;
  /** Why it failed; wording not normative. */
  failures: string[];
}

/** Distinct trusted witness keys on one path, and the independent operators among them. */
export interface PathCount {
  witnesses: number;
  independent_operators: number;
}

/** Per-path counts (only with `acceptFleetAnchor`). */
export interface WitnessPaths {
  direct: PathCount;
  fleet: PathCount;
  on_both: number;
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
  /**
   * WITNESSED, but the cosigning witnesses are not a strict majority of
   * the trusted directory, so a conflicting history could have been
   * cosigned by the rest (RFC-0002). Exit 11 unless `allowSubMajority`.
   */
  split_view_unsafe: boolean;
  /** Why the verdict is INVALID, one entry per failed check; empty otherwise. */
  failures: string[];
  /** Why the verdict is DIVERGED: each known head or evidence proof this dossier contradicts. */
  contradictions: string[];
  /** Known heads larger than this dossier, which it cannot be checked against (`"<size>:<root>"`). */
  known_heads_unchecked: string[];
  verdict: "witnessed" | "consistent_unwitnessed" | "unanchored" | "diverged" | "invalid";
  /** RFC-0001 (EXPERIMENTAL): present only when the dossier carries a `fleet_anchor`. */
  fleet_anchor?: FleetAnchorReport;
  /**
   * Present only with `acceptFleetAnchor`: which path the counted witness
   * keys of a WITNESSED verdict came by; null for any other verdict.
   */
  witnessed_via?: "direct" | "fleet" | "both" | null;
  /** Present only with `acceptFleetAnchor`. */
  witness_paths?: WitnessPaths;
}

/** A (tree size, root) the verifier already trusts for this identity. */
export interface KnownHead {
  /** Any u64: a bigint when it is above `Number.MAX_SAFE_INTEGER`. */
  tree_size: number | bigint;
  /** 64 hex. */
  root_hash: string;
}

/** A witness's evidence that one log signed two roots for one tree size (`witness serve` writes it under `"proof"`). */
export interface EquivocationProof {
  origin: string;
  log_vkey: string;
  earlier_note: string;
  conflicting_note: string;
}

/** An evidence file's contents: a bare proof, or the proof under `"proof"` as `witness serve` writes it. */
export type EvidenceItem = EquivocationProof | { observed_unix?: number; kind?: string; proof: EquivocationProof };

export interface VerifyDossierOptions {
  /** The identity you expect (64 hex), obtained out of band. Never read it from the dossier. */
  identity?: string;
  /** A witness directory YOU trust: `{witnesses: [...]}` or a bare array. Without it the verdict is capped at UNANCHORED. */
  directory?: WitnessDirectory | WitnessEntry[];
  /** Receipt-count gate as a fraction of the directory. Default 0.66 (the CLI's default). */
  threshold?: number;
  /** Receipt-count gate as an absolute number of distinct cosigning witnesses; replaces `threshold`. */
  minWitnesses?: number;
  /** Revocations you know about out of band; applied even when the dossier omits them (SPEC §5). */
  revocations?: RevocationStatement[];
  /**
   * Heads you already trust for this identity (`{tree_size, root_hash}` or
   * `"<size>:<root hex>"`). A dossier whose first `tree_size` leaves do not
   * reproduce one is DIVERGED (RFC-0002).
   */
  knownHeads?: Array<KnownHead | string>;
  /**
   * Witness equivocation proofs, bare or as `witness serve` writes them
   * (`{"kind": "equivocation", "proof": {...}}`). One that verifies for this
   * identity makes the verdict DIVERGED. An item that is neither throws a
   * TypeError (see `parseEvidence`).
   */
  evidence?: EvidenceItem[];
  /**
   * Accept WITNESSED from fewer than a strict majority of the directory as
   * exit 0 instead of 11. Default false (strict, the CLI's default since 0.5.0).
   */
  allowSubMajority?: boolean;
  /**
   * The organisation that operates this log, as you know it. Witnesses
   * with that `operator_org` never count as independent operators.
   */
  subjectOrg?: string;
  /**
   * RFC-0001, EXPERIMENTAL: count the cosigners of a fleet checkpoint that
   * includes this dossier's checkpoint, when its `fleet_anchor` fully
   * verifies. Needs `subjectOrg` (the organisation that runs the fleet
   * log). Fleet cosigners never count toward split-view resistance.
   * Default false: the field is ignored.
   */
  acceptFleetAnchor?: boolean;
}

export interface DossierVerification {
  verdict: Verdict;
  /**
   * The CLI's contract: 0 WITNESSED, 11 WITNESSED by fewer than a strict
   * majority (unless `allowSubMajority`), 10, 20, 30 DIVERGED, 40 INVALID.
   */
  exitCode: number;
  /** True only for WITNESSED with exit 0. */
  ok: boolean;
  /** See `DossierReport.split_view_unsafe`. */
  splitViewUnsafe: boolean;
  identityPubkey: string;
  identityPinned: boolean;
  directoryPinned: boolean;
  internallyConsistent: boolean;
  /** Which checks failed, in plain words. Empty unless INVALID. */
  failures: string[];
  /** What the dossier contradicts. Empty unless DIVERGED. */
  contradictions: string[];
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

/** SPEC §5 revocation message: v1 without an index, v2 (RFC-0005) with one. */
export function revocationMessage(identity: Uint8Array, asOfMs: number, asOfIndex: number | null | undefined, reason: string): Uint8Array {
  if (asOfIndex === undefined || asOfIndex === null) {
    return concat([utf8.encode("witness-log-revoke-v1"), identity, u64be(asOfMs), utf8.encode(reason)]);
  }
  return concat([
    utf8.encode("witness-log-revoke-v2"),
    identity,
    u64be(asOfMs),
    new Uint8Array([1]),
    u64be(asOfIndex),
    utf8.encode(reason),
  ]);
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
  return ed25519Verify(r.identity_pubkey, revocationMessage(identity, r.as_of_ms, r.as_of_index, r.reason), r.signature);
}

/**
 * SPEC §5 cut-off on already-verified revocations: no leaf and no checkpoint at or after the
 * earliest `as_of_ms`; RFC-0005: no leaf at or past the smallest `as_of_index`, no head larger than it.
 */
export function revocationCutOff(
  revocations: RevocationStatement[],
  leaves: Pick<Leaf, "index" | "timestamp_ms">[],
  checkpointTimestampMs: number,
  checkpointTreeSize: number,
): string | null {
  let asOf: number | null = null;
  let atIndex: number | null = null;
  for (const r of revocations) {
    asOf = asOf === null ? r.as_of_ms : Math.min(asOf, r.as_of_ms);
    if (r.as_of_index !== undefined && r.as_of_index !== null) {
      atIndex = atIndex === null ? r.as_of_index : Math.min(atIndex, r.as_of_index);
    }
  }
  if (asOf !== null) {
    if (checkpointTimestampMs >= asOf) return "the checkpoint is signed at or after the identity's revocation";
    for (const l of leaves) if (l.timestamp_ms >= asOf) return `leaf ${l.index} postdates the identity's revocation`;
  }
  if (atIndex !== null) {
    if (checkpointTreeSize > atIndex) return `checkpoint tree_size ${checkpointTreeSize} is past the revocation index ${atIndex}`;
    for (const l of leaves) if (l.index >= atIndex) return `leaf ${l.index} is at or past the revocation index ${atIndex}`;
  }
  return null;
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

// -------------------------------------------- signed notes (c2sp.org)

const EM_DASH = "\u2014";
const SIG_TYPE_ED25519 = 0x01;
/** As the reference and Go verifiers (signed-note: at least 16; 64 bounds hostile input). */
const MAX_NOTE_SIGNATURES = 64;

/**
 * Unicode White_Space, exactly: what Rust's `char::is_whitespace` and Go's
 * `unicode.IsSpace` test. JavaScript's `\s` and `trim()` differ from it
 * (they include U+FEFF and exclude U+0085), which made labels and known
 * heads parse differently here (security review of 0.5.0, F10/F12).
 */
const WHITE_SPACE = "\\t\\n\\v\\f\\r \\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
const WHITE_SPACE_RUN = new RegExp(`[${WHITE_SPACE}]+`);
const WHITE_SPACE_TRIM = new RegExp(`^[${WHITE_SPACE}]+|[${WHITE_SPACE}]+$`, "g");
const INVALID_KEY_NAME = new RegExp(`[+${WHITE_SPACE}]`);

/** `str::trim` / `strings.TrimSpace`: strip leading and trailing Unicode White_Space only. */
function trimWhiteSpace(s: string): string {
  return s.replace(WHITE_SPACE_TRIM, "");
}

/**
 * A signed-note key name: non-empty, no Unicode space and no `+` (the
 * signed-note Format section). A signature line whose name breaks this makes
 * the note malformed, known key or not, as in the reference parser
 * (golang.org/x/mod/sumdb/note) and the Rust and Go verifiers.
 */
function isValidKeyName(name: string): boolean {
  return name !== "" && !INVALID_KEY_NAME.test(name);
}

interface NoteSignature {
  name: string;
  keyId: Uint8Array;
  signature: Uint8Array;
}

/** A c2sp.org/signed-note: the text (with its final newline) and its signature lines. Null if malformed. */
function parseSignedNote(raw: string): { text: string; signatures: NoteSignature[] } | null {
  for (const ch of raw) {
    const c = ch.codePointAt(0)!;
    if (c < 0x20 && c !== 0x0a) return null;
  }
  const lines = raw.split("\n");
  let sep = -1;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i] === "" && lines.slice(i + 1).some((l) => l !== "")) sep = i;
  }
  if (sep < 0) return null;
  const signatures: NoteSignature[] = [];
  for (const line of lines.slice(sep + 1)) {
    if (line === "") continue;
    if (signatures.length >= MAX_NOTE_SIGNATURES) return null;
    if (!line.startsWith(EM_DASH + " ")) return null;
    const rest = line.slice(EM_DASH.length + 1);
    const space = rest.lastIndexOf(" ");
    if (space <= 0) return null;
    const name = rest.slice(0, space);
    const b64 = rest.slice(space + 1);
    if (!isValidKeyName(name)) return null;
    const payload = strictBase64(b64);
    if (payload === null || payload.length < 5) return null;
    signatures.push({ name, keyId: payload.slice(0, 4), signature: payload.slice(4) });
  }
  if (signatures.length === 0) return null;
  return { text: lines.slice(0, sep).join("\n") + "\n", signatures };
}

function strictBase64(s: string): Uint8Array | null {
  if (s.length === 0 || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  const b = Buffer.from(s, "base64");
  return b.toString("base64") === s ? new Uint8Array(b) : null;
}

function noteKeyId(name: string, sigType: number, publicKey: Uint8Array): Uint8Array {
  return sha256(utf8.encode(name), new Uint8Array([0x0a, sigType]), publicKey).slice(0, 4);
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/** The identity a canonical origin (`witness-log/<64 hex>`) names, or null. */
function identityFromCanonicalOrigin(origin: string): string | null {
  if (!origin.startsWith(CANONICAL_ORIGIN_PREFIX)) return null;
  const hex = origin.slice(CANONICAL_ORIGIN_PREFIX.length);
  return LOWER_HEX64.test(hex) && ed25519Key(hex) !== null ? hex : null;
}

/** Origin, size and root of a checkpoint note whose Ed25519 signature by `name`/`pubkeyHex` verifies; null otherwise. */
function verifiedCheckpoint(raw: string, name: string, pubkeyHex: string): { origin: string; size: string; root: string } | null {
  const note = parseSignedNote(raw);
  if (note === null) return null;
  const id = noteKeyId(name, SIG_TYPE_ED25519, hexToBytes(pubkeyHex));
  let verified = false;
  for (const sig of note.signatures) {
    if (sig.name !== name || !sameBytes(sig.keyId, id)) continue; // unknown key: ignored
    if (sig.signature.length !== 64) return null;
    if (!ed25519Verify(pubkeyHex, utf8.encode(note.text), bytesToHex(sig.signature))) return null;
    verified = true;
  }
  if (!verified) return null;
  const lines = note.text.replace(/\n+$/, "").split("\n");
  if (lines.length < 3 || lines.slice(3).some((l) => l === "")) return null;
  const [origin, size, rootB64] = lines;
  if (origin === "" || !/^(0|[1-9][0-9]*)$/.test(size) || BigInt(size) > 0xffff_ffff_ffff_ffffn) return null;
  const root = strictBase64(rootB64);
  if (root === null || root.length !== 32) return null;
  return { origin, size, root: bytesToHex(root) };
}

/**
 * Verify a witness equivocation proof with the key its canonical origin
 * names: the proof's own `log_vkey` must be exactly that key (name, 8-hex
 * key ID computed from the origin and key, type and key), and both notes
 * must verify under it, name the origin, and show one tree size with two
 * different roots. The key ID is never taken from the file.
 */
export function verifyEquivocationProof(p: EquivocationProof): boolean {
  if (p === null || typeof p !== "object") return false;
  const identity = identityFromCanonicalOrigin(String(p.origin ?? ""));
  if (identity === null) return false;
  const vkey = String(p.log_vkey ?? "");
  const plus1 = vkey.indexOf("+");
  const plus2 = plus1 < 0 ? -1 : vkey.indexOf("+", plus1 + 1);
  if (plus2 < 0 || vkey.slice(0, plus1) !== p.origin) return false;
  const keyIdHex = vkey.slice(plus1 + 1, plus2);
  const expectedId = bytesToHex(noteKeyId(p.origin, SIG_TYPE_ED25519, hexToBytes(identity)));
  if (!/^[0-9a-fA-F]{8}$/.test(keyIdHex) || keyIdHex.toLowerCase() !== expectedId) return false;
  const material = strictBase64(vkey.slice(plus2 + 1));
  if (material === null || material[0] !== SIG_TYPE_ED25519 || bytesToHex(material.slice(1)) !== identity) return false;
  const a = verifiedCheckpoint(String(p.earlier_note ?? ""), p.origin, identity);
  const b = verifiedCheckpoint(String(p.conflicting_note ?? ""), p.origin, identity);
  return a !== null && b !== null && a.origin === p.origin && b.origin === p.origin && a.size === b.size && a.root !== b.root;
}

/**
 * One evidence item, read as every verifier reads it: a JSON object that is
 * the proof itself or, as `witness serve` and the Python WitnessService
 * write it, carries the proof under `"proof"` (`{"observed_unix", "kind":
 * "equivocation", "proof": {...}}`). The proof must be an object whose
 * `origin`, `log_vkey`, `earlier_note` and `conflicting_note` are strings;
 * other keys are ignored. Throws a TypeError for anything else (the CLI's
 * exit 2), as the reference and Go verifiers refuse it. Before this, a
 * wrapped item was silently ignored here and counted by the reference
 * (security review of 0.5.0, F1).
 */
export function parseEvidence(item: unknown): EquivocationProof {
  const isObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
  if (!isObject(item)) {
    throw new TypeError('evidence: an item must be a JSON object, a proof or {"proof": {...}} as witness serve writes it');
  }
  let proof: Record<string, unknown> = item;
  if (Object.prototype.hasOwnProperty.call(item, "proof")) {
    const inner = item.proof;
    if (!isObject(inner)) throw new TypeError('evidence: the item\'s "proof" must be a JSON object');
    proof = inner;
  }
  const field = (k: keyof EquivocationProof): string => {
    if (!Object.prototype.hasOwnProperty.call(proof, k)) throw new TypeError(`evidence: equivocation proof is missing field ${k}`);
    const v = proof[k];
    if (typeof v !== "string") throw new TypeError(`evidence: equivocation proof field ${k} must be a string`);
    return v;
  };
  return {
    origin: field("origin"),
    log_vkey: field("log_vkey"),
    earlier_note: field("earlier_note"),
    conflicting_note: field("conflicting_note"),
  };
}

/** 2^64 - 1: a tree size is a u64 in the reference and Go verifiers. */
const U64_MAX = 0xffff_ffff_ffff_ffffn;

/**
 * Parse `"<size>:<root hex>"` (or pass a `KnownHead` through, checked).
 * Surrounding Unicode White_Space is ignored (U+FEFF is not White_Space and
 * is refused, as the reference refuses it). A size is any u64; one above
 * `Number.MAX_SAFE_INTEGER` comes back as a bigint, and is always larger
 * than a dossier, so it is reported unchecked rather than refused.
 */
export function parseKnownHead(h: KnownHead | string): KnownHead {
  let size: string;
  let root: string;
  if (typeof h === "string") {
    const i = h.indexOf(":");
    if (i < 0) throw new TypeError(`known head: expected <size>:<root hex>, got ${JSON.stringify(h)}`);
    size = trimWhiteSpace(h.slice(0, i));
    root = trimWhiteSpace(h.slice(i + 1));
  } else {
    if (typeof h.tree_size === "number" && !Number.isSafeInteger(h.tree_size)) {
      throw new TypeError(`known head: size ${h.tree_size} is not a safe integer; pass a bigint or "<size>:<root>"`);
    }
    size = String(h.tree_size);
    root = String(h.root_hash);
  }
  if (!/^(0|[1-9][0-9]*)$/.test(size) || BigInt(size) > U64_MAX) {
    throw new TypeError(`known head: size ${JSON.stringify(size)} is not a canonical decimal integer`);
  }
  if (!/^[0-9a-fA-F]{64}$/.test(root)) throw new TypeError(`known head: root ${JSON.stringify(root)} is not 32 bytes of hex`);
  const n = Number(size);
  return { tree_size: Number.isSafeInteger(n) ? n : BigInt(size), root_hash: root.toLowerCase() };
}

// ---------------------------------------------------------------- quorum

/**
 * The reference's `normalize_label`, exactly: split on Unicode White_Space
 * runs, join with one space, then Unicode full default lowercasing
 * (`toLowerCase` applies SpecialCasing, Final_Sigma included, as Rust's
 * `str::to_lowercase` does). spec/SPEC.md §7.
 */
function normalizeLabel(s: string): string {
  return s.split(WHITE_SPACE_RUN).filter((x) => x !== "").join(" ").toLowerCase();
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
  subjectOrg?: string,
): QuorumResult {
  return scoreAttestations(sth, directAttestations(sth, receipts), directory, threshold, subjectOrg).quorum;
}

/** One witness key's verified statement on one path. */
interface Attestation {
  key: string;
  atMs: number;
  fleet: boolean;
}

function directAttestations(sth: SignedTreeHead, receipts: WitnessReceipt[]): Attestation[] {
  return receipts
    .filter((r) => verifyReceipt(r, sth))
    .map((r) => ({ key: r.witness_pubkey.toLowerCase(), atMs: r.witnessed_at_ms, fleet: false }));
}

/**
 * The quorum over verified attestations plus per-path counts, as the
 * reference's score_attestations: each witness key counts once (direct
 * attestations come first and set its time), and only keys with a direct
 * receipt count toward split_view_resistant.
 */
function scoreAttestations(
  sth: SignedTreeHead,
  atts: Attestation[],
  directory: WitnessDirectory,
  threshold: number,
  subjectOrg?: string,
): { quorum: QuorumResult; paths: WitnessPaths } {
  const signer = sth.signer_pubkey.toLowerCase();
  const subjectEntry = directory.witnesses.find((w) => w.pubkey.toLowerCase() === signer);
  const subjectOperator = subjectEntry ? operatorKey(subjectEntry) : undefined;
  const declaredSubject = subjectOrg === undefined ? undefined : normalizeLabel(subjectOrg) || undefined;
  const operators = new Set<string>();
  const providers = new Set<string>();
  const counted = new Set<string>();
  const independent = new Set<string>();
  const directKeys = new Set<string>();
  const fleetKeys = new Set<string>();
  const directIndep = new Set<string>();
  const fleetIndep = new Set<string>();
  let projectOperated = 0;
  let newest: number | null = null;
  for (const a of atts) {
    const key = a.key;
    const entry = directory.witnesses.find((w) => w.pubkey.toLowerCase() === key);
    if (!entry) continue;
    let indepOp: string | null = null;
    if (!entry.is_project_operated) {
      const op = normalizeLabel(entry.operator_org ?? "");
      if (subjectOperator !== op && declaredSubject !== op) indepOp = op;
    }
    (a.fleet ? fleetKeys : directKeys).add(key);
    if (indepOp !== null) (a.fleet ? fleetIndep : directIndep).add(indepOp);
    if (counted.has(key)) continue;
    counted.add(key);
    operators.add(operatorKey(entry));
    if (indepOp !== null) independent.add(indepOp);
    providers.add(computeProviderKey(entry));
    if (entry.is_project_operated) projectOperated += 1;
    newest = newest === null ? a.atMs : Math.max(newest, a.atMs);
  }
  const valid = counted.size;
  const total = Math.max(directory.witnesses.length, 1);
  const opsInDir = Math.max(new Set(directory.witnesses.map(operatorKey)).size, 1);
  const provsInDir = Math.max(new Set(directory.witnesses.map(computeProviderKey)).size, 1);
  const fraction = valid / total;
  const paths: WitnessPaths = {
    direct: { witnesses: directKeys.size, independent_operators: directIndep.size },
    fleet: { witnesses: fleetKeys.size, independent_operators: fleetIndep.size },
    on_both: [...directKeys].filter((k) => fleetKeys.has(k)).length,
  };
  const quorum: QuorumResult = {
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
    split_view_resistant: 2 * directKeys.size > directory.witnesses.length,
    newest_trusted_witness_ms: newest,
  };
  return { quorum, paths };
}

// ------------------------------------- fleet anchors (RFC-0001, EXPERIMENTAL)

const MAX_FLEET_ENTRY_BYTES = 4096;
const MAX_FLEET_NOTE_TEXT_BYTES = 1024;
const MAX_FLEET_NOTE_BYTES = 64 * 1024;
const MAX_FLEET_NOTE_SIGNATURES = 64;
const MAX_INCLUSION_PROOF_HASHES = 64;
const SIG_TYPE_COSIGNATURE_V1 = 0x04;
const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** The field as the reference's serde reads it: all five fields with the right types; anything else is malformed. */
function parseFleetAnchor(raw: unknown): FleetAnchor | string {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return "fleet_anchor: expected an object";
  const a = raw as Record<string, unknown>;
  if (typeof a.origin !== "string") return "fleet_anchor: origin must be a string";
  if (typeof a.entry_index !== "number" || !Number.isInteger(a.entry_index) || a.entry_index < 0) {
    return "fleet_anchor: entry_index must be a non-negative integer";
  }
  if (typeof a.entry_bytes_b64 !== "string") return "fleet_anchor: entry_bytes_b64 must be a string";
  if (!Array.isArray(a.inclusion_proof) || a.inclusion_proof.some((h) => typeof h !== "string")) {
    return "fleet_anchor: inclusion_proof must be an array of strings";
  }
  if (typeof a.fleet_checkpoint_note !== "string") return "fleet_anchor: fleet_checkpoint_note must be a string";
  return a as unknown as FleetAnchor;
}

/** A C2SP origin (no space, '+' or control character, at most 255 bytes) that is not a witness-log agent origin. */
export function validFleetOrigin(origin: string): boolean {
  return (
    origin !== "" &&
    Buffer.byteLength(origin, "utf8") <= 255 &&
    !origin.startsWith(CANONICAL_ORIGIN_PREFIX) &&
    !/[ +\u0000-\u001f\u007f-\u009f]/.test(origin)
  );
}

/** origin, size, root and extension lines of a checkpoint note's text; null if malformed. */
function parseCheckpointText(text: string): { origin: string; size: bigint; root: Uint8Array; extensions: string[] } | null {
  const lines = text.replace(/\n+$/, "").split("\n");
  if (lines.length < 3 || lines.slice(3).some((l) => l === "")) return null;
  const [origin, size, rootB64] = lines;
  if (origin === "" || /[ +\n]/.test(origin)) return null;
  if (!/^(0|[1-9][0-9]*)$/.test(size) || BigInt(size) > U64_MAX) return null;
  const root = strictBase64(rootB64);
  if (root === null || root.length !== 32) return null;
  return { origin, size: BigInt(size), root, extensions: lines.slice(3) };
}

/** RFC-0001 step 2's shape check: a checkpoint note for `identityHex`, no extension lines, signed by it. */
function agentCheckpointFromEntry(entry: Uint8Array, identityHex: string): { size: bigint; root: Uint8Array } | string {
  if (entry.length > MAX_FLEET_ENTRY_BYTES) return `entry is larger than ${MAX_FLEET_ENTRY_BYTES} bytes`;
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(entry);
  } catch {
    return "entry is not UTF-8";
  }
  const note = parseSignedNote(text);
  if (note === null) return "entry is not a signed note";
  if (Buffer.byteLength(note.text, "utf8") > MAX_FLEET_NOTE_TEXT_BYTES) return "entry checkpoint body is too large";
  const cp = parseCheckpointText(note.text);
  if (cp === null) return "entry is not a checkpoint note";
  if (cp.extensions.length > 0) return "entry checkpoint has extension lines";
  const origin = canonicalOrigin(identityHex);
  if (cp.origin !== origin) return `entry is a checkpoint of ${cp.origin}, not of this identity (${origin})`;
  if (verifiedCheckpoint(text, origin, identityHex.toLowerCase()) === null) return "entry is not signed by this identity";
  return { size: cp.size, root: cp.root };
}

/**
 * RFC-0001 steps 2-4 against the dossier's own checkpoint: the entry is
 * this checkpoint signed by its identity, it is included in the fleet
 * checkpoint, and every cosignature line that verifies under a key in
 * `directory` is a cosigner. The fleet log's own signature is not a trust
 * input and is not checked. Returns the failure reason as a string.
 */
export function verifyFleetAnchor(
  anchor: FleetAnchor,
  sth: SignedTreeHead,
  directory: WitnessDirectory | undefined,
): { fleetTreeSize: number; cosigners: Array<{ witness_pubkey: string; witnessed_at_ms: number }> } | string {
  const r = verifyFleetAnchorInternal(anchor, sth, directory);
  if (typeof r === "string") return r;
  return {
    fleetTreeSize: r.size,
    cosigners: r.atts.map((a) => ({ witness_pubkey: a.key, witnessed_at_ms: a.atMs })),
  };
}

function verifyFleetAnchorInternal(
  anchor: FleetAnchor,
  sth: SignedTreeHead,
  directory: WitnessDirectory | undefined,
): { size: number; atts: Attestation[] } | string {
  if (!validFleetOrigin(anchor.origin)) {
    return `fleet origin ${JSON.stringify(anchor.origin)} is not a fleet log origin (a C2SP origin that is not witness-log/...)`;
  }
  const identity = String(sth.signer_pubkey ?? "");
  if (ed25519Key(identity) === null) return "the checkpoint's signer_pubkey is not an Ed25519 key";
  const entry = strictBase64(anchor.entry_bytes_b64);
  if (entry === null) return "entry_bytes_b64 is not canonical standard base64";
  const cp = agentCheckpointFromEntry(entry, identity);
  if (typeof cp === "string") return cp;
  if (cp.size !== BigInt(sth.tree_size) || bytesToHex(cp.root) !== String(sth.root_hash ?? "").toLowerCase()) {
    return `the entry commits to size ${cp.size}, not this checkpoint (size ${sth.tree_size})`;
  }

  if (Buffer.byteLength(anchor.fleet_checkpoint_note, "utf8") > MAX_FLEET_NOTE_BYTES) {
    return "fleet_checkpoint_note is too large";
  }
  const note = parseSignedNote(anchor.fleet_checkpoint_note);
  if (note === null) return "fleet_checkpoint_note is not a signed note";
  if (Buffer.byteLength(note.text, "utf8") > MAX_FLEET_NOTE_TEXT_BYTES || note.signatures.length > MAX_FLEET_NOTE_SIGNATURES) {
    return "fleet_checkpoint_note is larger than a witness accepts";
  }
  const fleet = parseCheckpointText(note.text);
  if (fleet === null) return "fleet_checkpoint_note is not a checkpoint";
  if (fleet.origin !== anchor.origin) return `the fleet checkpoint is for origin ${fleet.origin}, not ${anchor.origin}`;
  if (anchor.inclusion_proof.length > MAX_INCLUSION_PROOF_HASHES) return "inclusion_proof is longer than any tree needs";
  if (anchor.inclusion_proof.some((h) => !/^[0-9a-fA-F]{64}$/.test(h))) {
    return "inclusion_proof holds a value that is not 32 bytes of hex";
  }
  if (BigInt(anchor.entry_index) >= fleet.size) {
    return `entry_index ${anchor.entry_index} is not inside the fleet checkpoint (size ${fleet.size})`;
  }
  if (fleet.size > BigInt(Number.MAX_SAFE_INTEGER)) return "fleet checkpoint size is beyond this verifier's range";
  const size = Number(fleet.size);
  if (!verifyInclusion(leafHash(entry), anchor.entry_index, size, anchor.inclusion_proof.map(hexToBytes), fleet.root)) {
    return `the inclusion proof for entry ${anchor.entry_index} does not verify under the fleet checkpoint's root`;
  }

  const atts: Attestation[] = [];
  for (const sig of directory === undefined ? [] : note.signatures) {
    for (const w of directory!.witnesses) {
      if (!/^[0-9a-fA-F]{64}$/.test(w.pubkey ?? "") || ed25519Key(w.pubkey) === null) continue;
      if (!sameBytes(noteKeyId(sig.name, SIG_TYPE_COSIGNATURE_V1, hexToBytes(w.pubkey)), sig.keyId)) continue;
      if (sig.signature.length !== 72) continue;
      const ts = new DataView(sig.signature.buffer, sig.signature.byteOffset, 8).getBigUint64(0);
      const msg = `cosignature/v1\ntime ${ts}\n${note.text}`;
      if (ed25519Verify(w.pubkey, utf8.encode(msg), bytesToHex(sig.signature.slice(8)))) {
        const ms = ts * 1000n > U64_MAX ? U64_MAX : ts * 1000n;
        atts.push({ key: w.pubkey.toLowerCase(), atMs: Number(ms), fleet: true });
      }
    }
  }
  return { size, atts };
}

/** The report on `d.fleet_anchor`, and its cosigners when it fully verifies (null otherwise). */
function evaluateFleetAnchor(
  d: Dossier,
  checkpoint: SignedTreeHead,
  trusted: WitnessDirectory | undefined,
  opts: VerifyDossierOptions,
): { report: FleetAnchorReport | undefined; atts: Attestation[] | null } {
  if (d.fleet_anchor === undefined || d.fleet_anchor === null) return { report: undefined, atts: null };
  const parsed = parseFleetAnchor(d.fleet_anchor);
  const report: FleetAnchorReport = {
    status: "ignored",
    origin: typeof parsed === "string" ? null : parsed.origin,
    entry_index: typeof parsed === "string" ? null : parsed.entry_index,
    fleet_tree_size: null,
    failures: [],
  };
  if (!opts.acceptFleetAnchor) return { report, atts: null };
  report.status = "failed";
  if (typeof parsed === "string") {
    report.failures.push(`fleet_anchor is not well-formed: ${parsed}`);
    return { report, atts: null };
  }
  if (normalizeLabel(opts.subjectOrg ?? "") === "") {
    report.failures.push(
      "no subject_org: a fleet log is run by its agents' own organisation, and without knowing which one its own witnesses could count as independent",
    );
    return { report, atts: null };
  }
  const r = verifyFleetAnchorInternal(parsed, checkpoint, trusted);
  if (typeof r === "string") {
    report.failures.push(r);
    return { report, atts: null };
  }
  report.status = "verified";
  report.fleet_tree_size = r.size;
  return { report, atts: r.atts };
}

// --------------------------------------------------------------- verify

function bindingsAndRevocationsValid(
  leaves: Leaf[],
  identity: string,
  bindings: KeyBindingStatement[],
  revocations: RevocationStatement[],
  checkpointTimestampMs: number,
  checkpointTreeSize: number,
): string | null {
  if (bindings.length === 0 && revocations.length === 0) return null;
  const id = identity.toLowerCase();
  const bySession = new Map<string, KeyBindingStatement>();
  for (const b of bindings) {
    if (b.identity_pubkey.toLowerCase() !== id) return "a key binding names a different identity";
    if (!verifyKeyBinding(b)) return `key binding for session ${b.session_pubkey.slice(0, 8)}… has an invalid signature`;
    bySession.set(b.session_pubkey.toLowerCase(), b);
  }
  for (const r of revocations) {
    if (r.identity_pubkey.toLowerCase() !== id) return "a revocation names a different identity";
    if (!verifyRevocation(r)) return "a revocation has an invalid signature";
  }
  for (const l of leaves) {
    const b = bySession.get(l.session_pubkey.toLowerCase());
    if (!b) return `leaf ${l.index} was authored by a session key with no binding to this identity`;
    if (b.not_after_ms !== undefined && b.not_after_ms !== null && l.timestamp_ms > b.not_after_ms) {
      return `leaf ${l.index} postdates its session binding's expiry`;
    }
  }
  return revocationCutOff(revocations, leaves, checkpointTimestampMs, checkpointTreeSize);
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
  invalid: "INVALID",
};

/** Exit status for WITNESSED by fewer than a strict majority of the directory (RFC-0002). */
export const EXIT_SPLIT_VIEW_UNSAFE = 11;

/**
 * Verify a dossier offline (SPEC §9.1–§9.2). Synchronous; never throws on
 * a hostile dossier (a malformed one is INVALID), only on bad options.
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
  const knownHeads = (opts.knownHeads ?? []).map(parseKnownHead);
  if (opts.evidence !== undefined && !Array.isArray(opts.evidence)) throw new TypeError("evidence must be an array of evidence items");
  const evidence = (opts.evidence ?? []).map((item) => parseEvidence(item));

  const failures: string[] = [];
  const checkpoint = d.checkpoint ?? ({} as SignedTreeHead);
  const leaves = Array.isArray(d.leaves) ? d.leaves : [];
  const signer = String(checkpoint.signer_pubkey ?? "");

  const checkpointSignatureValid = verifyCheckpoint(checkpoint);
  if (!checkpointSignatureValid) failures.push("checkpoint signature does not verify");

  const selfConsistent = String(d.identity_pubkey ?? "").toLowerCase() === signer.toLowerCase();
  const pinOk = opts.identity === undefined || opts.identity.toLowerCase() === signer.toLowerCase();
  const identityBound = selfConsistent && pinOk;
  if (!selfConsistent) failures.push("identity_pubkey does not match the key that signed the checkpoint");
  else if (!pinOk) failures.push("the checkpoint is not signed by the identity you expected");

  const leafError = validateLeaves(leaves);
  if (leafError !== null) failures.push(`leaf structure: ${leafError}`);

  const ownRevocations = d.revocations ?? [];
  const idLower = String(d.identity_pubkey ?? "").toLowerCase();
  const allRevocations = ownRevocations.concat(
    (opts.revocations ?? []).filter(
      (r) => r.identity_pubkey.toLowerCase() === idLower && !ownRevocations.some((o) => o.signature === r.signature),
    ),
  );
  const bindingError = bindingsAndRevocationsValid(
    leaves,
    String(d.identity_pubkey ?? ""),
    d.key_bindings ?? [],
    allRevocations,
    Number(checkpoint.timestamp_ms),
    Number(checkpoint.tree_size),
  );
  if (bindingError !== null) failures.push(`key bindings or revocations: ${bindingError}`);
  const bindingsAsserted = (d.key_bindings ?? []).length > 0 || allRevocations.length > 0;

  let leafHashes: Uint8Array[] | null = null;
  try {
    leafHashes = leaves.map((l) => leafHash(leafCanonicalBytes(l)));
  } catch {
    leafHashes = null;
  }
  const rebuilt = leafHashes === null ? "" : bytesToHex(merkleRoot(leafHashes));
  const sizeMatches = leaves.length === checkpoint.tree_size;
  const merkleOk = sizeMatches && rebuilt === checkpoint.root_hash;
  if (!sizeMatches) failures.push(`${leaves.length} leaves but the checkpoint claims tree_size ${checkpoint.tree_size}`);
  else if (!merkleOk) failures.push("the leaves do not reproduce the signed root");

  // Contradictions with evidence the verifier brought (RFC-0002), only
  // for a valid file: an invalid one is INVALID whatever else is true.
  const contradictions: string[] = [];
  const knownHeadsUnchecked: string[] = [];
  if (failures.length === 0 && leafHashes !== null) {
    for (const kh of knownHeads) {
      if (kh.tree_size > leafHashes.length) {
        knownHeadsUnchecked.push(`${kh.tree_size}:${kh.root_hash}`);
        continue;
      }
      const prefix = bytesToHex(merkleRoot(leafHashes.slice(0, Number(kh.tree_size))));
      if (prefix !== kh.root_hash) {
        contradictions.push(
          `known head ${kh.tree_size}:${kh.root_hash} is not what this dossier's first ${kh.tree_size} leaves produce (${prefix})`,
        );
      }
    }
    const origin = ed25519Key(String(d.identity_pubkey ?? "")) === null ? null : canonicalOrigin(String(d.identity_pubkey));
    for (const proof of evidence) {
      if (origin !== null && proof.origin === origin && verifyEquivocationProof(proof)) {
        contradictions.push(`witness evidence: this identity signed two different roots for one tree size (${proof.origin})`);
      }
    }
  }

  const externallyAnchored = trusted !== undefined;
  let quorum: QuorumResult | null = null;
  const receipts = Array.isArray(d.witness_receipts) ? d.witness_receipts : [];
  // RFC-0001 (experimental): read only with the opt-in.
  const fleet = evaluateFleetAnchor(d, checkpoint, trusted, opts);
  let paths: WitnessPaths = {
    direct: { witnesses: 0, independent_operators: 0 },
    fleet: { witnesses: 0, independent_operators: 0 },
    on_both: 0,
  };
  if (trusted !== undefined && (receipts.length > 0 || fleet.atts !== null)) {
    const scored = scoreAttestations(
      checkpoint,
      directAttestations(checkpoint, receipts).concat(fleet.atts ?? []),
      trusted,
      threshold,
      opts.subjectOrg,
    );
    quorum = scored.quorum;
    paths = scored.paths;
    if (opts.minWitnesses !== undefined) {
      quorum.meets_count_threshold = quorum.valid_receipts >= opts.minWitnesses;
      quorum.count_gate = `count >= ${opts.minWitnesses}`;
    }
  }

  const internallyConsistent =
    checkpointSignatureValid && identityBound && leafError === null && bindingError === null && merkleOk;
  let verdict: DossierReport["verdict"];
  if (failures.length > 0) verdict = "invalid";
  else if (contradictions.length > 0) verdict = "diverged";
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
    split_view_unsafe: verdict === "witnessed" && !(quorum?.split_view_resistant ?? false),
    failures,
    contradictions,
    known_heads_unchecked: knownHeadsUnchecked,
    verdict,
  };
  if (fleet.report !== undefined) report.fleet_anchor = fleet.report;
  if (opts.acceptFleetAnchor) {
    const fleetOnly = paths.fleet.witnesses - paths.on_both;
    report.witnessed_via =
      verdict !== "witnessed" ? null : fleetOnly === 0 ? "direct" : paths.direct.witnesses === 0 ? "fleet" : "both";
    report.witness_paths = paths;
  }
  const name = VERDICT_NAME[verdict];
  const exitCode = report.split_view_unsafe && !opts.allowSubMajority ? EXIT_SPLIT_VIEW_UNSAFE : EXIT_CODES[name];
  return {
    verdict: name,
    exitCode,
    ok: name === "WITNESSED" && exitCode === 0,
    splitViewUnsafe: report.split_view_unsafe,
    identityPubkey: signer,
    identityPinned: opts.identity !== undefined,
    directoryPinned: externallyAnchored,
    internallyConsistent,
    failures,
    contradictions,
    report,
  };
}
