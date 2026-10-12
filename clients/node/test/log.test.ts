import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";

import {
  openLog,
  verifyDossier,
  verifyDossierNative,
  verifyDisclosure,
  verifyInclusion,
  verifyHandoffBinding,
  verifyAuthorizationBinding,
  canonicalJson,
  hexToBytes,
  tempJournalPath,
  WitnessLogError,
  type Dossier,
} from "../src/index.js";

/** The two verifiers must agree; returns the TypeScript verdict. */
function bothVerdicts(d: Dossier, opts: Parameters<typeof verifyDossier>[1] = {}) {
  const ts = verifyDossier(d, opts);
  const rs = verifyDossierNative(d, opts);
  assert.equal(ts.verdict, rs.verdict, `TS ${ts.verdict} vs Rust ${rs.verdict}: ${ts.failures.join("; ")}`);
  assert.equal(ts.report.internally_consistent, rs.report.internally_consistent);
  assert.equal(ts.report.leaf_count, rs.report.leaf_count);
  assert.deepEqual(ts.report.quorum?.valid_receipts, rs.report.quorum?.valid_receipts);
  return ts;
}

describe("openLog, append, export, verify", () => {
  it("append -> export -> verify, with the pure-TS and the Rust verifier agreeing", () => {
    const path = tempJournalPath();
    const log = openLog(path);
    assert.equal(log.treeSize, 0);
    const i = log.appendIntent({ tool: "search", args: { q: "weather in Oslo" } });
    assert.equal(i, 0);
    const r = log.appendResult("21C, clear", { tool: "search", intentIndex: i, outcome: "ok" });
    assert.equal(r, 1);
    log.appendMemory(new Uint8Array([1, 2, 3]));
    assert.equal(log.treeSize, 3);
    assert.match(log.identityPubkey, /^[0-9a-f]{64}$/);
    assert.equal(log.origin, `witness-log/${log.identityPubkey}`);

    const d = log.exportDossier();
    assert.equal(d.leaves.length, 3);
    assert.deepEqual(
      d.leaves.map((l) => l.leaf_type),
      [1, 2, 0],
    );
    assert.equal(d.key_bindings?.length, 1);
    const v = bothVerdicts(d);
    assert.equal(v.verdict, "UNANCHORED");
    assert.equal(v.internallyConsistent, true);
    const pinned = bothVerdicts(d, { identity: log.identityPubkey });
    assert.equal(pinned.identityPinned, true);
    assert.equal(bothVerdicts(d, { identity: "ab".repeat(32) }).verdict, "DIVERGED");
    log.close();
    assert.equal(log.closed, true);
    assert.throws(() => log.appendIntent("x"), (e: unknown) => e instanceof WitnessLogError && e.code === "closed");
  });

  it("tampering is DIVERGED for both verifiers", () => {
    const log = openLog(tempJournalPath());
    for (let k = 0; k < 5; k++) log.appendIntent(`step ${k}`);
    const d = log.exportDossier();
    log.close();

    const edited = structuredClone(d);
    edited.leaves[2].payload_hash = "00".repeat(32);
    assert.equal(bothVerdicts(edited).verdict, "DIVERGED");

    const dropped = structuredClone(d);
    dropped.leaves.pop();
    assert.equal(bothVerdicts(dropped).verdict, "DIVERGED");

    const reordered = structuredClone(d);
    [reordered.leaves[0], reordered.leaves[1]] = [reordered.leaves[1], reordered.leaves[0]];
    assert.equal(bothVerdicts(reordered).verdict, "DIVERGED");

    const resigned = structuredClone(d);
    resigned.checkpoint.timestamp_ms += 1;
    assert.equal(bothVerdicts(resigned).verdict, "DIVERGED");

    const otherIdentity = structuredClone(d);
    otherIdentity.identity_pubkey = "cd".repeat(32);
    assert.equal(bothVerdicts(otherIdentity).verdict, "DIVERGED");

    const noBindings = structuredClone(d);
    noBindings.key_bindings = [];
    assert.equal(bothVerdicts(noBindings).verdict, "UNANCHORED"); // "not asserted", not a failure

    const wrongBinding = structuredClone(d);
    wrongBinding.key_bindings![0].session_number += 1;
    assert.equal(bothVerdicts(wrongBinding).verdict, "DIVERGED");
  });

  it("resumes the same identity and session bindings carry across restarts", () => {
    const path = tempJournalPath();
    const a = openLog(path);
    const identity = a.identityPubkey;
    a.appendIntent("first session");
    a.close();

    const b = openLog(path);
    assert.equal(b.identityPubkey, identity);
    assert.equal(b.treeSize, 1);
    b.appendIntent("second session");
    const d = b.exportDossier();
    assert.equal(d.key_bindings?.length, 2);
    assert.equal(bothVerdicts(d, { identity }).verdict, "UNANCHORED");
    b.close();
    if (process.platform !== "win32") assert.equal(statSync(path).mode & 0o777, 0o600);
  });

  it("sealed: the seed never lands in the journal and is required to reopen", () => {
    const path = tempJournalPath();
    const seed = randomBytes(32);
    assert.throws(() => openLog(path, { seal: true }), (e: unknown) => e instanceof WitnessLogError && e.code === "invalid");
    const a = openLog(path, { identitySeed: seed, seal: true });
    const identity = a.identityPubkey;
    a.appendIntent("sealed");
    assert.deepEqual(a.identityBytes(), new Uint8Array(seed));
    a.close();
    assert.equal(readFileSync(path, "utf8").includes(seed.toString("hex")), false);

    assert.throws(() => openLog(path), (e: unknown) => e instanceof WitnessLogError && e.code === "sealed");
    assert.throws(() => openLog(path, { identitySeed: randomBytes(32) }), WitnessLogError);
    const b = openLog(path, { identitySeed: seed });
    assert.equal(b.identityPubkey, identity);
    assert.equal(b.treeSize, 1);
    b.appendIntent("still sealed");
    assert.equal(bothVerdicts(b.exportDossier(), { identity }).verdict, "UNANCHORED");
    b.close();
  });

  it("the same seed reproduces the identity in an unsealed journal", () => {
    const seed = randomBytes(32);
    const a = openLog(tempJournalPath(), { identitySeed: seed });
    const b = openLog(tempJournalPath(), { identitySeed: seed });
    assert.equal(a.identityPubkey, b.identityPubkey);
    a.close();
    b.close();
  });

  it("forget erases the salt and the stored payload; proofs stay valid", () => {
    const path = tempJournalPath();
    const log = openLog(path, { storePayloads: true });
    log.appendIntent("name: Ada");
    log.appendResult({ ok: true });
    const before = log.disclose(0)!;
    assert.equal(before.verified, true);
    assert.equal(new TextDecoder().decode(before.payload!), "name: Ada");
    assert.ok(before.salt);
    assert.equal(verifyDisclosure(log.leaves()[0], before.payload!, before.salt!), true);
    assert.equal(verifyDisclosure(log.leaves()[0], new TextEncoder().encode("name: Bob"), before.salt!), false);

    assert.equal(log.canForget(0), true);
    assert.equal(log.forget(0), true);
    assert.equal(log.forget(0), false);
    assert.equal(log.treeSize, 3); // a 0x03 tombstone was appended
    const after = log.disclose(0)!;
    assert.equal(after.salt, null);
    assert.equal(after.payload, null);
    assert.equal(after.verified, false);
    assert.equal(after.payloadHash, before.payloadHash);
    assert.equal(readFileSync(`${path}.payloads`, "utf8").includes("Ada"), false);
    assert.equal(readFileSync(`${path}.salts`, "utf8").includes(Buffer.from(before.salt!).toString("hex")), false);
    assert.equal(log.disclose(1)!.verified, true);
    assert.equal(log.disclose(99), null);

    const d = log.exportDossier();
    assert.equal(d.leaves[2].leaf_type, 3);
    assert.equal(d.leaves[2].redacted_index, 0);
    assert.equal(bothVerdicts(d).verdict, "UNANCHORED");

    const proof = log.inclusionProof(1)!;
    assert.equal(verifyInclusion(hexToBytes(proof.leafHash), 1, proof.treeSize, proof.proof.map(hexToBytes), hexToBytes(proof.rootHash)), true);
    log.close();

    // Payloads survive a restart; the forgotten one stays gone.
    const again = openLog(path, { storePayloads: true });
    assert.equal(again.disclose(0)!.payload, null);
    assert.deepEqual(again.disclose(1)!.payload, canonicalJson({ ok: true }));
    again.close();
  });

  it("without storePayloads disclose returns the salt only", () => {
    const log = openLog(tempJournalPath());
    log.appendIntent("x");
    const d = log.disclose(0)!;
    assert.ok(d.salt);
    assert.equal(d.payload, null);
    assert.equal(verifyDisclosure(log.leaves()[0], new TextEncoder().encode("x"), d.salt!), true);
    assert.equal(existsSync(`${log.path}.payloads`), false);
    log.close();
  });

  it("handoff and authorization leaves bind across two logs", () => {
    const a = openLog(tempJournalPath());
    const b = openLog(tempJournalPath());
    const state = canonicalJson({ task: "reconcile", amount: 250 });
    a.appendHandoff("sent", b.identityPubkey.toUpperCase(), state);
    b.appendHandoff("received", a.identityPubkey, state);
    assert.equal(verifyHandoffBinding(a.identityPubkey, a.leaves()[0], b.identityPubkey, b.leaves()[0]), null);
    const mismatch = verifyHandoffBinding(a.identityPubkey, a.leaves()[0], a.identityPubkey, b.leaves()[0]);
    assert.match(String(mismatch), /counterparty/);

    const scope = "pay up to 250 USD to merchant X";
    a.appendAuthorizationEvent("granted_by_me", b.identityPubkey, scope);
    b.appendAuthorizationEvent("granted_to_me", a.identityPubkey, scope);
    assert.equal(verifyAuthorizationBinding(a.identityPubkey, a.leaves()[1], b.identityPubkey, b.leaves()[1]), null);
    assert.throws(
      () => a.appendAuthorizationEvent("granted" as never, b.identityPubkey, scope),
      (e: unknown) => e instanceof WitnessLogError && e.code === "invalid",
    );
    assert.throws(() => a.appendHandoff("sent", "zz", state), WitnessLogError);

    a.appendExternalAnchor("https://rekor.sigstore.dev/api/v1/log/entries/abc", { logIndex: 1 });
    assert.throws(() => a.appendExternalAnchor("file:///etc/passwd", "{}"), WitnessLogError);
    for (const log of [a, b]) {
      assert.equal(bothVerdicts(log.exportDossier()).verdict, "UNANCHORED");
      log.close();
    }
  });

  it("step records intent and result, and rethrows", async () => {
    const log = openLog(tempJournalPath(), { storePayloads: true });
    const out = await log.step("transfer", async () => ({ tx: "t1" }), { args: { amount: 5 } });
    assert.deepEqual(out, { tx: "t1" });
    await assert.rejects(
      log.step("boom", () => {
        throw new RangeError("nope");
      }),
      RangeError,
    );
    const leaves = log.leaves();
    assert.deepEqual(
      leaves.map((l) => l.leaf_type),
      [1, 2, 1, 2],
    );
    const result = JSON.parse(new TextDecoder().decode(log.disclose(3)!.payload!));
    assert.equal(result.outcome, "error");
    assert.equal(result.intent_index, 2);
    assert.match(result.value, /RangeError: nope/);
    log.close();
  });

  it("a second process cannot open the same journal", () => {
    const path = tempJournalPath();
    const a = openLog(path);
    assert.throws(() => openLog(path), WitnessLogError);
    a.close();
    const b = openLog(path);
    b.close();
    assert.equal(existsSync(join(dirname(path), "journal.jsonl.lock")), false);
  });

  it("the 32-byte seed is checked", () => {
    assert.throws(() => openLog(tempJournalPath(), { identitySeed: new Uint8Array(31) }), (e: unknown) => e instanceof WitnessLogError && e.code === "invalid");
  });
});
