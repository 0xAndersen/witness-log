/**
 * The TypeScript verifier against the conformance corpus (/corpus) and the
 * repository's sample dossier. Pure Node: no binary, no network.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  bytesToHex,
  hexToBytes,
  leafCanonicalBytes,
  leafHash,
  merkleRoot,
  payloadHash,
  verifyCheckpoint,
  verifyDossier,
  verifyInclusion,
  sha256,
  verifyDisclosure,
  ed25519Verify,
  verifyRevocation,
  revocationMessage,
  revocationCutOff,
  verifyEquivocationProof,
  parseEvidence,
  parseKnownHead,
  type Dossier,
  type Leaf,
  type WitnessDirectory,
} from "../src/index.js";
import { IGNORED, MAX_DOSSIER_DEPTH, parseJsonExact } from "../src/dossier-json.js";

const here = dirname(fileURLToPath(import.meta.url)); // clients/typescript/dist/test
const repo = resolve(here, "..", "..", "..", "..");
const corpus = (name: string) => JSON.parse(readFileSync(join(repo, "corpus", name), "utf8"));

describe("corpus vectors", { skip: existsSync(join(repo, "corpus")) ? false : "no corpus directory" }, () => {
  it("01: leaf canonical bytes and leaf hashes", () => {
    for (const v of corpus("01_leaf_encoding.json").vectors) {
      const bytes = leafCanonicalBytes(v.leaf as Leaf);
      assert.equal(bytesToHex(bytes), v.canonical_bytes_hex);
      assert.equal(bytesToHex(leafHash(bytes)), v.leaf_hash_hex);
    }
  });

  it("07/08/09: handoff, authorization and anchor leaves encode byte for byte", () => {
    const h = corpus("07_handoff_attestation.json");
    for (const v of [h.sent_leaf, h.received_leaf]) {
      assert.equal(bytesToHex(leafCanonicalBytes(v.leaf)), v.canonical_bytes_hex);
      assert.equal(bytesToHex(leafHash(leafCanonicalBytes(v.leaf))), v.leaf_hash_hex);
    }
    const a = corpus("08_authorization_event.json");
    for (const k of Object.keys(a)) {
      if (a[k] && typeof a[k] === "object" && "canonical_bytes_hex" in a[k] && "leaf" in a[k]) {
        assert.equal(bytesToHex(leafCanonicalBytes(a[k].leaf)), a[k].canonical_bytes_hex, k);
      }
    }
    const x = corpus("09_external_anchor.json");
    assert.equal(bytesToHex(leafCanonicalBytes(x.anchor_leaf.leaf)), x.anchor_leaf.canonical_bytes_hex);
    assert.equal(bytesToHex(leafHash(leafCanonicalBytes(x.anchor_leaf.leaf))), x.anchor_leaf.leaf_hash_hex);
    if (x.swapped_proof_case?.leaf) {
      assert.equal(bytesToHex(leafCanonicalBytes(x.swapped_proof_case.leaf)), x.swapped_proof_case.canonical_bytes_hex);
    }
  });

  it("02: Merkle roots for sizes 1..8", () => {
    const leaves = corpus("01_leaf_encoding.json").vectors.map((v: { leaf: Leaf }) => v.leaf as Leaf);
    // fixed_leaf(i): same shape as vector 01's leaves; the corpus builds roots from fixed_leaf(0..n).
    const fixed = (i: number): Leaf => ({
      ...leaves[0],
      index: i,
      leaf_type: 1,
      timestamp_ms: 1700000000000 + i * 1000,
      payload_hash: ((i + 1) & 0xff).toString(16).padStart(2, "0").repeat(32),
    });
    const hashes = Array.from({ length: 8 }, (_, i) => leafHash(leafCanonicalBytes(fixed(i))));
    const vectors = corpus("02_merkle_roots.json").vectors as Array<{ root_hex: string; tree_size: number }>;
    assert.equal(bytesToHex(hashes[0]), corpus("01_leaf_encoding.json").vectors[0].leaf_hash_hex);
    for (const v of vectors) {
      assert.equal(bytesToHex(merkleRoot(hashes.slice(0, v.tree_size))), v.root_hex, `size ${v.tree_size}`);
    }
  });

  it("03: inclusion proofs", () => {
    const d = corpus("03_inclusion_proofs.json");
    for (const v of d.vectors) {
      const ok = verifyInclusion(
        hexToBytes(v.leaf_hash_hex),
        v.leaf_index,
        v.tree_size,
        v.proof_hex.map(hexToBytes),
        hexToBytes(d.root_hex),
      );
      assert.equal(ok, true, `leaf ${v.leaf_index}`);
      const wrong = verifyInclusion(hexToBytes(v.leaf_hash_hex), v.leaf_index, v.tree_size, v.proof_hex.map(hexToBytes), hexToBytes("00".repeat(32)));
      assert.equal(wrong, false);
    }
  });

  it("04: signed tree head verifies, and not after a change", () => {
    const sth = corpus("04_signed_tree_head.json").sth;
    assert.equal(verifyCheckpoint(sth), true);
    assert.equal(verifyCheckpoint({ ...sth, tree_size: sth.tree_size + 1 }), false);
    assert.equal(verifyCheckpoint({ ...sth, sig_alg: "ml-dsa-65" }), false);
  });

  it("05: a redaction marker leaves earlier leaf hashes unchanged", () => {
    const d = corpus("05_redaction_continuity.json");
    const before = (d.leaves_before_redaction as Leaf[]).map((l) => leafHash(leafCanonicalBytes(l)));
    assert.equal(bytesToHex(merkleRoot(before)), d.root_before_hex);
    const after = [...before, leafHash(leafCanonicalBytes(d.redaction_marker_leaf as Leaf))];
    assert.equal(bytesToHex(merkleRoot(after)), d.root_after_hex);
  });

  it("10: C2SP cosignature message verifies under the witness key", () => {
    const d = corpus("10_c2sp_checkpoint.json");
    const vkey = String(d.cosignature.witness_vkey);
    const [, , b64] = vkey.split("+", 3);
    const keyBytes = Buffer.from(b64, "base64"); // sig type byte || 32-byte key
    const witnessHex = keyBytes.subarray(1).toString("hex");
    const lines = String(d.cosignature.cosigned_note).split("\n");
    const sigLine = lines.find((l) => l.startsWith("— corpus-witness.example/w1 "))!;
    const payload = Buffer.from(sigLine.split(" ")[2], "base64"); // key id (4) || timestamp (8) || sig (64)
    const sig = payload.subarray(12).toString("hex");
    assert.equal(ed25519Verify(witnessHex, new TextEncoder().encode(d.cosignature.signed_message), sig), true);
  });

  it("11: payload hash with an explicit salt", () => {
    for (const c of corpus("11_payload_hash.json").cases) {
      const h = payloadHash(hexToBytes(c.payload_hex), hexToBytes(c.salt_hex), c.leaf_index);
      assert.equal(bytesToHex(h), c.payload_hash, c.name);
      const leaf = { index: c.leaf_index, payload_hash: c.payload_hash } as Leaf;
      assert.equal(verifyDisclosure(leaf, hexToBytes(c.payload_hex), hexToBytes(c.salt_hex)), true);
    }
  });
});

describe("corpus 12: revocation statements", () => {
  it("v1 and v2 messages, signatures, and the cut-off rules", () => {
    const v = corpus("12_revocation.json");
    const pk = hexToBytes(v.identity_pubkey);
    for (const k of ["v1", "v2"]) {
      const st = v[k].statement;
      assert.equal(bytesToHex(revocationMessage(pk, st.as_of_ms, st.as_of_index, st.reason)), v[k].message_hex, k);
      assert.equal(verifyRevocation(st), true, k);
    }
    assert.equal(verifyRevocation({ ...v.v2.statement, as_of_index: undefined }), false, "index stripped");
    assert.equal(verifyRevocation({ ...v.v2.statement, as_of_index: v.v2.statement.as_of_index + 1 }), false, "index moved");
    for (const c of v.cut_off_cases) {
      const st = c.revocation === "v2" ? v.v2.statement : v.v1.statement;
      const leaves = Array.from({ length: c.max_leaf_index + 1 }, (_, i) => ({ index: i, timestamp_ms: 0 }));
      const err = revocationCutOff([st], leaves, c.checkpoint_timestamp_ms, c.checkpoint_tree_size);
      assert.equal(err === null, c.valid, JSON.stringify(c) + " " + err);
    }
  });
});

describe("corpus 13: verdicts (RFC-0002)", () => {
  it("every case: verdict, exit code and report fields", () => {
    const v = corpus("13_verdicts.json");
    const exits = new Set<number>();
    for (const c of v.cases) {
      const r = verifyDossier(v.dossiers[c.dossier], {
        directory: c.trusted_directory ? v.trusted_directory : undefined,
        identity: c.expected_identity ?? undefined,
        threshold: c.threshold,
        minWitnesses: c.min_witnesses ?? undefined,
        knownHeads: c.known_heads,
        evidence: c.evidence.map((k: string) => v.evidence[k]),
        allowSubMajority: c.allow_sub_majority,
        subjectOrg: c.subject_org ?? undefined,
      });
      const e = c.expect;
      assert.equal(r.report.verdict, e.verdict, c.name);
      assert.equal(r.exitCode, e.exit_code, c.name);
      assert.equal(r.report.split_view_unsafe, e.split_view_unsafe, c.name);
      assert.equal(r.report.internally_consistent, e.internally_consistent, c.name);
      assert.equal(r.report.failures.length > 0, e.has_failures, c.name);
      assert.equal(r.report.contradictions.length, e.contradictions, c.name);
      assert.equal(r.report.known_heads_unchecked.length, e.known_heads_unchecked, c.name);
      assert.equal(r.report.quorum?.valid_receipts ?? null, e.valid_receipts, c.name);
      assert.equal(r.report.quorum?.distinct_independent_operators ?? null, e.independent_operators, c.name);
      exits.add(e.exit_code);
    }
    assert.deepEqual([...exits].sort((a, b) => a - b), [0, 10, 11, 20, 30, 40]);
  });

  it("equivocation proofs verify only under the origin's own key", () => {
    const v = corpus("13_verdicts.json");
    assert.equal(verifyEquivocationProof(v.evidence.equivocation), true);
    assert.equal(verifyEquivocationProof(v.evidence.other_identity), true);
    assert.equal(verifyEquivocationProof(v.evidence.stranger_key), false);
    const p = v.evidence.equivocation;
    assert.equal(verifyEquivocationProof({ ...p, conflicting_note: p.earlier_note }), false, "same root twice");
    assert.equal(verifyEquivocationProof({ ...p, log_vkey: v.evidence.stranger_key.log_vkey }), false, "foreign vkey");
    assert.equal(verifyEquivocationProof({ ...p, earlier_note: p.earlier_note.replace("\n2\n", "\n3\n") }), false, "edited note");
  });
});

describe("corpus 14: fleet anchors (RFC-0001, experimental)", () => {
  it("the fleet log's own values recompute", () => {
    const f = corpus("14_fleet_anchor.json").fleet_log;
    const hashes = f.entries_b64.map((e: string) => leafHash(new Uint8Array(Buffer.from(e, "base64"))));
    assert.deepEqual(hashes.map(bytesToHex), f.leaf_hashes_hex);
    assert.equal(bytesToHex(merkleRoot(hashes)), f.root_hex);
    assert.equal(
      verifyInclusion(hashes[2], 2, f.tree_size, f.entry_2_inclusion_proof_hex.map(hexToBytes), hexToBytes(f.root_hex)),
      true,
    );
  });

  it("every case: verdict, exit code, quorum, fleet status and path fields", () => {
    const v = corpus("14_fleet_anchor.json");
    const exits = new Set<number>();
    for (const c of v.cases) {
      const r = verifyDossier(v.dossiers[c.dossier], {
        directory: c.trusted_directory ? v.trusted_directory : undefined,
        threshold: c.threshold,
        minWitnesses: c.min_witnesses ?? undefined,
        allowSubMajority: c.allow_sub_majority,
        subjectOrg: c.subject_org ?? undefined,
        acceptFleetAnchor: c.accept_fleet_anchor,
      });
      const e = c.expect;
      assert.equal(r.report.verdict, e.verdict, c.name);
      assert.equal(r.exitCode, e.exit_code, c.name);
      assert.equal(r.report.split_view_unsafe, e.split_view_unsafe, c.name);
      assert.equal(r.report.quorum?.valid_receipts ?? null, e.valid_receipts, c.name);
      assert.equal(r.report.quorum?.distinct_independent_operators ?? null, e.independent_operators, c.name);
      assert.equal(r.report.fleet_anchor?.status ?? null, e.fleet_anchor_status, c.name);
      assert.equal(r.report.fleet_anchor?.fleet_tree_size ?? null, e.fleet_tree_size, c.name);
      if (c.accept_fleet_anchor) {
        assert.deepEqual(r.report.witnessed_via, e.witnessed_via, c.name);
        assert.deepEqual(r.report.witness_paths, e.witness_paths, c.name);
      } else {
        assert.equal("witnessed_via" in r.report, false, c.name);
        assert.equal("witness_paths" in r.report, false, c.name);
      }
      exits.add(e.exit_code);
    }
    assert.deepEqual([...exits].sort((a, b) => a - b), [0, 10, 11, 20]);
  });

  it("without the opt-in an anchor changes nothing else in any corpus 13 report", () => {
    const v13 = corpus("13_verdicts.json");
    const anchor = corpus("14_fleet_anchor.json").dossiers.fleet_only.fleet_anchor;
    for (const [name, d] of Object.entries(v13.dossiers)) {
      for (const opts of [{}, { directory: v13.trusted_directory, minWitnesses: 2, subjectOrg: "corpus-operator-1" }]) {
        const plain = verifyDossier(d as Dossier, opts).report;
        const anchored = verifyDossier({ ...(d as Dossier), fleet_anchor: anchor }, opts).report;
        assert.equal(anchored.fleet_anchor?.status, "ignored", name);
        delete anchored.fleet_anchor;
        assert.deepEqual(anchored, plain, name);
      }
    }
  });
});

describe("verifyDossier on examples/sample-dossier.json", () => {
  const dossierPath = join(repo, "examples", "sample-dossier.json");
  const dirPath = join(repo, "examples", "trusted-directory.json");
  const have = existsSync(dossierPath) && existsSync(dirPath);
  const load = () => ({
    dossier: JSON.parse(readFileSync(dossierPath, "utf8")) as Dossier,
    directory: JSON.parse(readFileSync(dirPath, "utf8")) as WitnessDirectory,
  });

  it("is UNANCHORED with no trusted inputs", { skip: !have }, () => {
    const { dossier } = load();
    const r = verifyDossier(dossier);
    assert.equal(r.verdict, "UNANCHORED");
    assert.equal(r.exitCode, 20);
    assert.equal(r.internallyConsistent, true);
    assert.equal(r.report.bindings_asserted, true);
    assert.equal(r.report.leaf_count, dossier.leaves.length);
  });

  it("reaches WITNESSED with the trusted directory and pinned identity", { skip: !have }, () => {
    const { dossier, directory } = load();
    const r = verifyDossier(dossier, { directory, identity: dossier.identity_pubkey, minWitnesses: 2 });
    assert.equal(r.verdict, "WITNESSED", JSON.stringify(r.report.quorum));
    assert.equal(r.ok, true);
    assert.equal(r.identityPinned, true);
    assert.ok(r.report.quorum);
    assert.ok(r.report.quorum.distinct_independent_operators >= 2);
    assert.equal(r.report.quorum.count_gate, "count >= 2");
  });

  it("is CONSISTENT-UNWITNESSED when the gate is not met", { skip: !have }, () => {
    const { dossier, directory } = load();
    const r = verifyDossier(dossier, { directory, minWitnesses: 50 });
    assert.equal(r.verdict, "CONSISTENT-UNWITNESSED");
    assert.equal(r.exitCode, 10);
    const none = verifyDossier(dossier, { directory: { witnesses: [] } });
    assert.equal(none.verdict, "CONSISTENT-UNWITNESSED");
  });

  it("is INVALID after tampering, with a reason", { skip: !have }, () => {
    const { dossier, directory } = load();
    const t = structuredClone(dossier);
    t.leaves[1].payload_hash = "00".repeat(32);
    const r = verifyDossier(t, { directory });
    assert.equal(r.verdict, "INVALID");
    assert.equal(r.exitCode, 40);
    assert.ok(r.failures.some((f) => /signed root/.test(f)));
    assert.deepEqual(r.report.failures, r.failures);

    const wrongIdentity = verifyDossier(dossier, { identity: "ab".repeat(32) });
    assert.equal(wrongIdentity.verdict, "INVALID");
    assert.ok(wrongIdentity.failures.some((f) => /expected/.test(f)));

    const reordered = structuredClone(dossier);
    [reordered.leaves[0], reordered.leaves[1]] = [reordered.leaves[1], reordered.leaves[0]];
    assert.equal(verifyDossier(reordered).verdict, "INVALID");

    const noBinding = structuredClone(dossier);
    noBinding.key_bindings = [{ ...noBinding.key_bindings![0], session_pubkey: "cd".repeat(32) }];
    assert.equal(verifyDossier(noBinding).verdict, "INVALID");

    const forgedReceipt = structuredClone(dossier);
    forgedReceipt.witness_receipts![0].signature = "00".repeat(64);
    const fr = verifyDossier(forgedReceipt, { directory, minWitnesses: 2 });
    assert.equal(fr.report.quorum?.valid_receipts, dossier.witness_receipts!.length - 1);
  });

  it("rejects bad options rather than guessing", () => {
    const d = { identity_pubkey: "", leaves: [], checkpoint: {} } as unknown as Dossier;
    assert.throws(() => verifyDossier(d, { identity: "zz" }), TypeError);
    assert.throws(() => verifyDossier(d, { threshold: 2 }), RangeError);
    assert.throws(() => verifyDossier(d, { minWitnesses: 0 }), RangeError);
    assert.equal(verifyDossier(d).verdict, "INVALID");
    assert.equal(verifyDossier("{}").verdict, "INVALID");
    assert.throws(() => verifyDossier(d, { knownHeads: ["7"] }), TypeError);
    assert.throws(() => verifyDossier(d, { knownHeads: ["007:" + "ab".repeat(32)] }), TypeError);
  });
});

describe("corpus 15: evidence items, known heads and labels (security review of 0.5.0)", () => {
  it("every case: refused (exit 2) or verdict, exit code and report fields", () => {
    const v = corpus("15_evidence_and_args.json");
    const exits = new Set<number>();
    for (const c of v.cases) {
      const e = c.expect;
      exits.add(e.exit_code);
      const run = () =>
        verifyDossier(v.dossiers[c.dossier], {
          directory: c.directory === null ? undefined : v.directories[c.directory],
          identity: c.expected_identity ?? undefined,
          threshold: c.threshold,
          minWitnesses: c.min_witnesses ?? undefined,
          knownHeads: c.known_heads,
          evidence: c.evidence.map((k: string) => v.evidence[k]),
          allowSubMajority: c.allow_sub_majority,
          subjectOrg: c.subject_org ?? undefined,
        });
      if (e.exit_code === 2) {
        assert.throws(run, TypeError, c.name);
        continue;
      }
      const r = run();
      assert.equal(r.report.verdict, e.verdict, c.name);
      assert.equal(r.exitCode, e.exit_code, c.name);
      assert.equal(r.report.split_view_unsafe, e.split_view_unsafe, c.name);
      assert.equal(r.report.internally_consistent, e.internally_consistent, c.name);
      assert.equal(r.report.failures.length > 0, e.has_failures, c.name);
      assert.equal(r.report.contradictions.length, e.contradictions, c.name);
      assert.equal(r.report.known_heads_unchecked.length, e.known_heads_unchecked, c.name);
      assert.equal(r.report.quorum?.valid_receipts ?? null, e.valid_receipts, c.name);
      assert.equal(r.report.quorum?.distinct_independent_operators ?? null, e.independent_operators, c.name);
    }
    assert.deepEqual([...exits].sort((a, b) => a - b), [2, 10, 11, 20, 30, 40]);
  });

  it("F1: a proof as witness serve writes it counts, as in the reference", () => {
    const v = corpus("15_evidence_and_args.json");
    const wrapped = v.evidence.wrapped;
    assert.deepEqual(parseEvidence(wrapped), v.evidence.bare);
    assert.equal(verifyDossier(v.dossiers.full, { evidence: [wrapped] }).verdict, "DIVERGED");
    assert.throws(() => parseEvidence({ kind: "equivocation" }), TypeError);
    assert.throws(() => verifyDossier(v.dossiers.full, { evidence: {} as never }), TypeError);
  });

  it("F10: sizes above 2^53 are kept exactly; the BOM is not whitespace", () => {
    const root = "ab".repeat(32);
    assert.equal(parseKnownHead(`9007199254740993:${root}`).tree_size, 9007199254740993n);
    assert.equal(parseKnownHead(`18446744073709551615:${root}`).tree_size, 18446744073709551615n);
    assert.equal(parseKnownHead(`7:${root}`).tree_size, 7);
    assert.equal(parseKnownHead({ tree_size: 9007199254740993n, root_hash: root }).tree_size, 9007199254740993n);
    assert.throws(() => parseKnownHead({ tree_size: 2 ** 60, root_hash: root }), TypeError);
    assert.throws(() => parseKnownHead(`18446744073709551616:${root}`), TypeError);
    const bom = String.fromCodePoint(0xfeff);
    const nel = String.fromCodePoint(0x85);
    assert.throws(() => parseKnownHead(`${bom}2:${root}`), TypeError);
    assert.equal(parseKnownHead(`${nel}2:${root}${nel}`).tree_size, 2);
  });
});

interface CorpusCase {
  name: string;
  dossier: string;
  directory: string | null;
  expected_identity: string | null;
  threshold: number;
  min_witnesses: number | null;
  known_heads: string[];
  evidence: string[];
  allow_sub_majority: boolean;
  subject_org: string | null;
  expect: Record<string, unknown>;
}

/** A corpus 15/16/17-style case through verifyDossier: verdict, exit code and report fields. */
function assertCase(
  v: { dossiers: Record<string, unknown>; directories: Record<string, unknown>; evidence?: Record<string, unknown> },
  c: CorpusCase,
  dossier: unknown = v.dossiers[c.dossier],
) {
  const e = c.expect;
  const r = verifyDossier(dossier as Dossier | string, {
    directory: c.directory === null ? undefined : (v.directories[c.directory] as WitnessDirectory),
    identity: c.expected_identity ?? undefined,
    threshold: c.threshold,
    minWitnesses: c.min_witnesses ?? undefined,
    knownHeads: c.known_heads,
    evidence: c.evidence.map((k) => v.evidence![k]) as never,
    allowSubMajority: c.allow_sub_majority,
    subjectOrg: c.subject_org ?? undefined,
  });
  assert.equal(r.report.verdict, e.verdict, c.name);
  assert.equal(r.exitCode, e.exit_code, c.name);
  assert.equal(r.report.split_view_unsafe, e.split_view_unsafe, c.name);
  assert.equal(r.report.internally_consistent, e.internally_consistent, c.name);
  assert.equal(r.report.failures.length > 0, e.has_failures, c.name);
  assert.equal(r.report.contradictions.length, e.contradictions, c.name);
  assert.equal(r.report.known_heads_unchecked.length, e.known_heads_unchecked, c.name);
  assert.equal(r.report.quorum?.valid_receipts ?? null, e.valid_receipts, c.name);
  assert.equal(r.report.quorum?.distinct_independent_operators ?? null, e.independent_operators, c.name);
  return r;
}

describe("corpus 16: strict Ed25519 (outside review III, H3/M3)", () => {
  it("every signature: ed25519Verify answers what the reference's verify_strict answers", () => {
    const v = corpus("16_ed25519_strict.json");
    assert.ok(v.signatures.length >= 45);
    for (const s of v.signatures) {
      assert.equal(ed25519Verify(s.public_key, hexToBytes(s.message), s.signature), s.valid, s.name);
    }
    // What the vector is for: signatures a non-strict check accepts and the
    // reference refuses (every small-order key and the identity as R).
    const lax = v.signatures.filter((s: { valid: boolean; cofactorless_non_strict: boolean }) => !s.valid && s.cofactorless_non_strict);
    assert.ok(lax.length >= 18, `${lax.length}`);
  });

  it("every case: verdict, exit code and report fields", () => {
    const v = corpus("16_ed25519_strict.json");
    const exits = new Set<number>();
    for (const c of v.cases as CorpusCase[]) {
      exits.add(c.expect.exit_code as number);
      assertCase(v, c);
    }
    assert.deepEqual([...exits].sort((a, b) => a - b), [10, 20, 40]);
  });

  it("verifyCheckpoint itself refuses the degenerate checkpoints", () => {
    const v = corpus("16_ed25519_strict.json");
    assert.equal(verifyCheckpoint(v.dossiers.honest.checkpoint), true);
    assert.equal(verifyCheckpoint(v.dossiers.identity_point_checkpoint.checkpoint), false);
    assert.equal(verifyCheckpoint(v.dossiers.small_order_key_checkpoint.checkpoint), false);
    assert.equal(verifyCheckpoint(v.dossiers.small_order_r_checkpoint.checkpoint), false);
    assert.equal(verifyCheckpoint(v.dossiers.mixed_order_key_checkpoint.checkpoint), true);
  });
});

describe("corpus 17: reading a dossier (outside review III, H2 and P3)", () => {
  it("every text: not a dossier (INVALID, never a throw) or the reference's verdict", () => {
    const v = corpus("17_dossier_parsing.json");
    assert.ok(v.cases.length >= 100);
    for (const c of v.cases as Array<CorpusCase & { dossier_json: string }>) {
      if (c.expect.not_a_dossier) {
        const r = verifyDossier(c.dossier_json, {
          directory: c.directory === null ? undefined : v.directories[c.directory],
          minWitnesses: c.min_witnesses ?? undefined,
        });
        assert.equal(r.verdict, "INVALID", c.name);
        assert.equal(r.exitCode, 40, c.name);
        assert.match(r.failures[0], /^not a dossier: /, c.name);
        continue;
      }
      const r = assertCase(v, c, c.dossier_json);
      assert.ok(!r.failures.some((f) => f.startsWith("not a dossier")), c.name);
    }
  });

  it("inputs: a directory, revocations or evidence item nested deeper than 1000 throws, as a malformed one does", () => {
    // Before, an option of any depth was read here (the options are values,
    // so nothing stopped them), while Go refused 10,000 levels.
    const v = corpus("17_dossier_parsing.json");
    const kinds = new Map<string, number>();
    for (const c of v.inputs as Array<{ name: string; input: string; text: string; dossier: string; min_witnesses: number | null; expect: any }>) {
      kinds.set(c.input, (kinds.get(c.input) ?? 0) + 1);
      const dossier = v.cases.find((x: { name: string }) => x.name === c.dossier).dossier_json;
      // The option as a caller holds it: the text parsed (V8's JSON.parse
      // takes 100,000 levels), an evidence item in the list of them.
      const value = parseJsonExact(c.text);
      const opts =
        c.input === "directory"
          ? { directory: value as WitnessDirectory, minWitnesses: c.min_witnesses ?? undefined }
          : c.input === "revocations"
            ? { revocations: value as never }
            : { evidence: [value] as never };
      const t0 = performance.now();
      if (c.expect.refused) {
        assert.throws(() => verifyDossier(dossier, opts), (e: Error) => e instanceof TypeError && /nested deeper than 1000/.test(e.message), c.name);
      } else {
        const r = verifyDossier(dossier, opts);
        assert.equal(r.report.verdict, c.expect.verdict, c.name);
        assert.equal(r.exitCode, c.expect.exit_code, c.name);
        assert.equal(r.failures.length > 0, c.expect.has_failures, c.name);
        assert.equal(r.contradictions.length, c.expect.contradictions, c.name);
        assert.equal(r.report.quorum?.valid_receipts ?? null, c.expect.valid_receipts, c.name);
      }
      assert.ok(performance.now() - t0 < 1500, c.name);
    }
    assert.deepEqual([...kinds.keys()].sort(), ["directory", "evidence", "revocations"]);
    // parseEvidence on its own refuses the item too.
    const deep = v.inputs.find((c: { name: string }) => c.name === "a bare equivocation proof with an unknown member nested to depth 1001");
    assert.throws(() => parseEvidence(JSON.parse(deep.text)), /evidence: nested deeper than 1000/);
  });

  it("revocations: one statement or an array, as --revocations reads them", () => {
    const v = corpus("17_dossier_parsing.json");
    const dossier = v.cases.find((x: { name: string }) => x.name === "valid").dossier_json;
    const statement = JSON.parse(v.inputs.find((c: { input: string }) => c.input === "revocations").text);
    delete statement.zz;
    assert.equal(verifyDossier(dossier).verdict, "UNANCHORED");
    assert.equal(verifyDossier(dossier, { revocations: statement }).verdict, "INVALID");
    assert.equal(verifyDossier(dossier, { revocations: [statement] }).verdict, "INVALID");
    assert.throws(() => verifyDossier(dossier, { revocations: "x" as never }), TypeError);
  });

  it("the report names a fleet origin only up to 255 bytes, as the reference does", () => {
    const min = corpus("17_dossier_parsing.json")
      .cases.find((c: { name: string }) => c.name === "whitespace around the object")
      .dossier_json.trim();
    for (const [origin, reported] of [
      ["example.com/fleet", true],
      ["o".repeat(255), true],
      ["é".repeat(127), true],
      ["é".repeat(128), false],
      ["o".repeat(256), false],
      ["o".repeat(10_000_000), false],
    ] as const) {
      const text = `${min.slice(0, -1)},"fleet_anchor":{"origin":"${origin}","entry_index":0,"entry_bytes_b64":"","inclusion_proof":[],"fleet_checkpoint_note":""}}`;
      for (const acceptFleetAnchor of [false, true]) {
        const r = verifyDossier(text, { acceptFleetAnchor, subjectOrg: "org" });
        assert.equal(r.report.fleet_anchor?.origin, reported ? origin : null, `${origin.length} characters`);
        assert.ok(JSON.stringify(r.report).length < 10_000);
      }
    }
  });

  it("the review's reproductions never throw", () => {
    const v = corpus("13_verdicts.json");
    const tries: Record<string, (d: any) => void> = {
      fractional_tree_size: (d) => (d.checkpoint.tree_size = 3.5),
      fractional_timestamp: (d) => (d.checkpoint.timestamp_ms = 1.5),
      negative_tree_size: (d) => (d.checkpoint.tree_size = -1),
      nan_tree_size: (d) => (d.checkpoint.tree_size = NaN),
      receipts_object: (d) => (d.witness_receipts = {}),
      leaves_null: (d) => (d.leaves = null),
      checkpoint_null: (d) => (d.checkpoint = null),
      leaf_index_string: (d) => (d.leaves[0].index = "0"),
      signature_number: (d) => (d.checkpoint.signature = 5),
      custody_array: (d) => (d.key_bindings = [{ custody: [] }]),
    };
    for (const [name, edit] of Object.entries(tries)) {
      const d = structuredClone(v.dossiers.full);
      edit(d);
      const r = verifyDossier(d, { directory: v.trusted_directory });
      assert.equal(r.verdict, "INVALID", name);
      assert.match(r.failures[0], /^not a dossier: /, name);
    }
    for (const text of ["{not json", "", "null", "[]", "42", '"x"', "﻿{}", "{} x"]) {
      const r = verifyDossier(text);
      assert.equal(r.exitCode, 40, JSON.stringify(text));
      assert.match(r.failures[0], /^not a dossier: /);
    }
    for (const value of [null, undefined, 42, "", [], () => 0]) {
      assert.equal(verifyDossier(value as never).verdict, "INVALID");
    }
  });

  it("u64 values: exact from text; a parsed number above 2^53 - 1 is refused, a bigint is not", () => {
    const v = corpus("17_dossier_parsing.json");
    const c = v.cases.find((x: { name: string }) => x.name === "checkpoint timestamp_ms 2^53 + 1, signed exactly");
    assert.equal(verifyDossier(c.dossier_json).verdict, "UNANCHORED");
    // JSON.parse rounds 2^53 + 1 to 2^53: refused, never verified as the wrong number.
    const parsed = JSON.parse(c.dossier_json);
    const r = verifyDossier(parsed);
    assert.equal(r.verdict, "INVALID");
    assert.match(r.failures[0], /above 2\^53 - 1/);
    parsed.checkpoint.timestamp_ms = 2n ** 53n + 1n;
    const exact = verifyDossier(parsed);
    assert.equal(exact.verdict, "UNANCHORED");
    // Below 2^53 a u64 stays a number; above, a bigint.
    assert.equal(typeof exact.report.claimed_tree_size, "number");
    const big = v.cases.find((x: { name: string }) => x.name === "checkpoint timestamp_ms 2^64 - 1, signed exactly");
    assert.equal(verifyDossier(big.dossier_json).verdict, "UNANCHORED");
  });

  it("inclusion proofs are checked with exact arithmetic above 2^53", () => {
    const leaf = new Uint8Array(32).fill(1);
    const sibling = new Uint8Array(32).fill(2);
    // In a tree of size 2^53 + 2, leaf 2^53 + 1 is the right child of the
    // last pair: one hash up, then the size-2^53 subtree on the left.
    const left = new Uint8Array(32).fill(3);
    const n = 2n ** 53n;
    const pair = sha256(new Uint8Array([1]), sibling, leaf);
    const root = sha256(new Uint8Array([1]), left, pair);
    assert.equal(verifyInclusion(leaf, n + 1n, n + 2n, [sibling, left], root), true);
    // Number arithmetic would have read 2^53 + 1 as 2^53.
    assert.equal(verifyInclusion(leaf, n, n + 2n, [sibling, left], root), false);
    assert.equal(verifyInclusion(leaf, 1.5, 4, [], root), false);
  });
});

describe("hostile dossier text (outside audit of 0.6.1)", { skip: existsSync(join(repo, "corpus")) ? false : "no corpus directory" }, () => {
  const minimal = (): string =>
    corpus("17_dossier_parsing.json")
      .cases.find((c: { name: string }) => c.name === "whitespace around the object")
      .dossier_json.trim();
  const withField = (text: string, field: string) => `${text.slice(0, -1)},${field}}`;
  const nested = (n: number) => "[".repeat(n) + "]".repeat(n);
  const fast = (t0: number, what: string) => {
    const ms = performance.now() - t0;
    assert.ok(ms < 1500, `${what} took ${Math.round(ms)} ms`);
  };

  it("a text nests at most 1000 deep, and reading stops at the 1001st level however deep it goes", () => {
    const min = minimal();
    assert.equal(verifyDossier(withField(min, `"zz":${nested(999)}`)).verdict, "UNANCHORED");
    // 5 million deep is the audit's 10 MB text: 1.3 GB and seconds before, or
    // a fatal out-of-memory on a smaller heap.
    for (const n of [1000, 9999, 5_000_000]) {
      const t0 = performance.now();
      const r = verifyDossier(withField(min, `"zz":${nested(n)}`));
      assert.equal(r.verdict, "INVALID", `${n} deep`);
      assert.match(r.failures[0], /^not a dossier: nested deeper than 1000 arrays and objects/);
      fast(t0, `${n} deep`);
    }
  });

  it("a parsed value nests at most 1000 deep too; a cycle is refused, a shared value measured once", () => {
    const min = minimal();
    assert.equal(verifyDossier(JSON.parse(withField(min, `"zz":${nested(999)}`))).verdict, "UNANCHORED");
    const over = verifyDossier(JSON.parse(withField(min, `"zz":${nested(1000)}`)));
    assert.equal(over.verdict, "INVALID");
    assert.match(over.failures[0], /^not a dossier: dossier: nested deeper than 1000/);
    const cyclic = JSON.parse(min);
    cyclic.zz = { a: [] };
    cyclic.zz.a.push(cyclic.zz);
    assert.equal(verifyDossier(cyclic).verdict, "INVALID");
    // 60 levels, 2^60 paths through them.
    let shared: unknown = [];
    for (let i = 0; i < 60; i++) shared = [shared, shared];
    const wide = JSON.parse(min);
    wide.zz = shared;
    const t0 = performance.now();
    assert.equal(verifyDossier(wide).verdict, "UNANCHORED");
    fast(t0, "a shared value");
  });

  it("a 10-million-digit literal is refused in linear time and quoted only in part", () => {
    const min = minimal();
    const digits = "1" + "0".repeat(10_000_000);
    for (const [what, text] of [
      ["tree_size", min.replace('"tree_size":0', `"tree_size":${digits}`)],
      ["a string field", min.replace('"sig_alg":"ed25519"', `"sig_alg":${digits}`)],
      ["fleet_anchor", withField(min, `"fleet_anchor":{"x":${digits}}`)],
    ]) {
      const t0 = performance.now();
      const r = verifyDossier(text);
      assert.equal(r.verdict, "INVALID", what);
      assert.ok(r.failures[0].length < 300, `${what}: a ${r.failures[0].length}-character failure`);
      fast(t0, what);
    }
    // In an ignored key it costs one scan and is read as nothing.
    const t0 = performance.now();
    assert.equal(verifyDossier(withField(min, `"zz":${digits}`)).verdict, "UNANCHORED");
    fast(t0, "an ignored literal");
  });

  it("a huge string is quoted only in part", () => {
    const min = minimal();
    const huge = "S".repeat(10_000_000);
    for (const text of [
      min.replace('"tree_size":0', `"tree_size":"${huge}"`),
      min.replace(
        '"witness_directory":{"witnesses":[]}',
        `"witness_directory":{"witnesses":[{"name":"n","operator_org":"o","url":"u","pubkey":"p","runtime":"${huge}"}]}`,
      ),
    ]) {
      const r = verifyDossier(text);
      assert.equal(r.verdict, "INVALID");
      assert.match(r.failures[0], /^not a dossier: /);
      assert.ok(r.failures[0].length < 300, `a ${r.failures[0].length}-character failure`);
    }
    assert.throws(
      () => parseKnownHead(huge),
      (e: Error) => e instanceof TypeError && e.message.length < 300,
    );
  });
});

describe("parseJsonExact builds only what a dossier reads", () => {
  it("an ignored key's value is checked as JSON and not built", () => {
    const shape = { fields: { a: "all" as const } };
    const v = parseJsonExact('{"a":[1,{"b":2}],"zz":[[1,2],{"c":"\\u00e9"}],"zz2":"x","zz3":-1.5e3}', shape) as Record<string, unknown>;
    assert.deepEqual(Object.keys(v), ["a", "zz", "zz2", "zz3"]);
    assert.equal((v.a as unknown[]).length, 2);
    for (const k of ["zz", "zz2", "zz3"]) assert.equal(v[k], IGNORED, k);
    for (const text of ['{"zz":[1,]}', '{"zz":"\\x"}', '{"zz":[1}', '{"zz":01}', '{"zz":"\u0001"}', '{"zz":{"a" 1}}', '{"zz":"\\u12"}', '{"zz":tru}']) {
      assert.throws(() => parseJsonExact(text, shape), SyntaxError, text);
    }
  });

  it("nesting is counted outside strings, the outer value being depth 1", () => {
    assert.deepEqual(parseJsonExact("[[]]", "all", 2), [[]]);
    assert.throws(() => parseJsonExact("[[[]]]", "all", 2), /nested deeper than 2/);
    assert.throws(() => parseJsonExact('{"a":{"b":{}}}', { fields: {} }, 2), /nested deeper than 2/);
    assert.deepEqual(parseJsonExact('["\\"[[[["]', "all", 1), ['"[[[[']);
    assert.equal(MAX_DOSSIER_DEPTH, 1000);
  });
});
