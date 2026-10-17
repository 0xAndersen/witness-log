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
  verifyDisclosure,
  ed25519Verify,
  verifyRevocation,
  revocationMessage,
  revocationCutOff,
  verifyEquivocationProof,
  type Dossier,
  type Leaf,
  type WitnessDirectory,
} from "../src/index.js";

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
