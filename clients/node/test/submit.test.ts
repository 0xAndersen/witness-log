import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

import { openLog, verifyDossier, verifyDossierNative, loadWitnessState, saveWitnessState, tempJournalPath, selectWitnesses, type WitnessEntry } from "../src/index.js";
import { MockWitness } from "./mock-witness.js";

describe("submit to witnesses (mock tlog-witness servers)", () => {
  const w1 = new MockWitness("w1", "Org One");
  const w2 = new MockWitness("w2", "Org Two");
  const w3 = new MockWitness("w3", "Org Three", "busy-once");
  const refuser = new MockWitness("w4", "Org Four", "refuse");
  const garbage = new MockWitness("w5", "Org Five", "garbage");
  const wrongKey = new MockWitness("w6", "Org Six", "wrong-key");
  const stale = new MockWitness("w7", "Org Seven", "stale-size");
  const all = [w1, w2, w3, refuser, garbage, wrongKey, stale];
  let directory: { witnesses: WitnessEntry[] };

  before(async () => {
    await Promise.all(all.map((w) => w.start()));
    directory = { witnesses: all.map((w) => w.entry()) };
  });
  after(async () => {
    await Promise.all(all.map((w) => w.stop()));
  });

  it("reaches WITNESSED with two honest witnesses and records state", async () => {
    const path = tempJournalPath();
    const log = openLog(path);
    log.appendIntent("a");
    log.appendResult("b");
    const good = { witnesses: [w1.entry(), w2.entry()] };
    const r = await log.submit(good, { min: 2 });
    assert.equal(r.refused, undefined);
    assert.equal(r.ok, true, JSON.stringify(r.outcomes));
    assert.equal(r.cosignatures, 2);
    assert.equal(r.contacted, 2);
    assert.equal(r.treeSize, 2);
    assert.ok(r.dossier);
    assert.equal(r.dossier.witness_receipts?.length, 2);
    assert.equal(r.dossier.witness_receipts?.[0].c2sp_origin, log.origin);
    assert.deepEqual(r.dossier.witness_directory, good);

    const ts = verifyDossier(r.dossier, { directory: good, identity: log.identityPubkey, minWitnesses: 2 });
    const rs = verifyDossierNative(r.dossier, { directory: good, identity: log.identityPubkey, minWitnesses: 2 });
    assert.equal(ts.verdict, "WITNESSED", JSON.stringify(ts.report.quorum));
    assert.equal(rs.verdict, "WITNESSED");
    assert.equal(ts.report.quorum?.distinct_independent_operators, 2);
    // The dossier's own directory is never a trust input.
    assert.equal(verifyDossier(r.dossier).verdict, "UNANCHORED");
    // Receipts from keys outside the trusted directory do not count.
    assert.equal(verifyDossier(r.dossier, { directory: [w1.entry()], minWitnesses: 1 }).verdict, "CONSISTENT-UNWITNESSED");

    const state = loadWitnessState(`${path}.witnesses.json`);
    assert.equal(state.cosigned_size, 2);
    assert.equal(state.cosigned_root, log.rootHash);
    assert.deepEqual(state.sizes, { [w1.pubkeyHex]: 2, [w2.pubkeyHex]: 2 });

    // Second round: the witnesses remember size 2, the client sends old=2 (no 409 needed).
    log.appendIntent("c");
    const before = w1.requests.length;
    const r2 = await log.submit(good, { min: 2 });
    assert.equal(r2.ok, true);
    assert.equal(w1.requests.length, before + 1);
    assert.match(w1.requests[before], /^old 2\n/);
    log.close();
  });

  it("resyncs on 409 when the client state is lost", async () => {
    const path = tempJournalPath();
    const log = openLog(path);
    log.appendIntent("a");
    const good = { witnesses: [w1.entry(), w2.entry()] };
    assert.equal((await log.submit(good)).ok, true);
    log.appendIntent("b");
    // Lose the state: the next round sends old=0, gets 409 with the witness's size, retries once.
    saveWitnessState(`${path}.witnesses.json`, { sizes: {}, cosigned_size: 0, cosigned_root: "" });
    const n1 = w1.requests.length;
    const r = await log.submit(good);
    assert.equal(r.ok, true, JSON.stringify(r.outcomes));
    assert.equal(w1.requests.length, n1 + 2);
    assert.match(w1.requests[n1], /^old 0\n/);
    assert.match(w1.requests[n1 + 1], /^old 1\n/);
    log.close();
  });

  it("honours Retry-After, reports refusals, and drops cosignatures that do not verify", async () => {
    const log = openLog(tempJournalPath());
    log.appendIntent("a");
    const started = Date.now();
    const r = await log.submit(directory, { want: 7, min: 3, timeoutMs: 5000 });
    const by = Object.fromEntries(r.outcomes.map((o) => [o.witness, o]));
    assert.equal(by.w1.status, 200);
    assert.equal(by.w2.status, 200);
    assert.equal(by.w3.status, 200, "busy-once should succeed after Retry-After");
    assert.ok(Date.now() - started >= 900, "waited for Retry-After: 1");
    assert.equal(by.w4.status, 422);
    assert.match(String(by.w4.error), /REFUSED \(422\)/);
    assert.equal(by.w5.status, 0);
    assert.match(String(by.w5.error), /no valid cosignature/);
    assert.equal(by.w6.status, 0, "a cosignature under a key other than the directory's must not count");
    assert.equal(by.w7.status, 409);
    assert.match(String(by.w7.error), /fork/);
    assert.equal(r.cosignatures, 3);
    assert.equal(r.ok, true);
    const v = verifyDossier(r.dossier!, { directory, minWitnesses: 3 });
    assert.equal(v.verdict, "WITNESSED");
    assert.equal(v.report.quorum?.valid_receipts, 3);
    assert.equal(verifyDossierNative(r.dossier!, { directory, minWitnesses: 3 }).verdict, "WITNESSED");
    assert.equal(verifyDossier(r.dossier!, { directory, minWitnesses: 4 }).verdict, "CONSISTENT-UNWITNESSED");
    log.close();
  });

  it("ok is false below min, and transport failures are outcomes, not exceptions", async () => {
    const log = openLog(tempJournalPath());
    log.appendIntent("a");
    const dead: WitnessEntry = { ...w1.entry(), name: "dead", pubkey: "ef".repeat(32), url: "http://127.0.0.1:9", operator_org: "Org Dead" };
    const r = await log.submit({ witnesses: [w1.entry(), dead] }, { min: 2, timeoutMs: 2000 });
    assert.equal(r.ok, false);
    assert.equal(r.cosignatures, 1);
    const d = r.outcomes.find((o) => o.witness === "dead")!;
    assert.equal(d.status, 0);
    assert.ok(d.error);
    assert.equal(verifyDossier(r.dossier!, { directory: [w1.entry(), dead] }).verdict, "CONSISTENT-UNWITNESSED");
    log.close();
  });

  it("refuses to submit a journal that does not extend what witnesses cosigned", async () => {
    const path = tempJournalPath();
    const log = openLog(path);
    log.appendIntent("a");
    saveWitnessState(`${path}.witnesses.json`, { sizes: {}, cosigned_size: 1, cosigned_root: "00".repeat(32) });
    const r = await log.submit([w1.entry(), w2.entry()]);
    assert.equal(r.ok, false);
    assert.match(String(r.refused), /refusing to submit/);
    assert.equal(r.contacted, 0);
    assert.equal(r.dossier, null);
    log.close();
  });

  it("rejects bad directories and non-http urls up front", async () => {
    const log = openLog(tempJournalPath());
    log.appendIntent("a");
    await assert.rejects(log.submit({ nope: 1 } as never), /directory must be/);
    await assert.rejects(log.submit([w1.entry()], { min: 0 }), /at least 1/);
    const r = await log.submit([{ ...w1.entry(), url: "file:///etc/passwd" }]);
    assert.equal(r.outcomes[0].status, 0);
    assert.match(String(r.outcomes[0].error), /http:\/\/ or https:\/\//);
    assert.equal(existsSync(`${log.path}.witnesses.json`), true);
    assert.equal(JSON.parse(readFileSync(`${log.path}.witnesses.json`, "utf8")).cosigned_size, 0);
    log.close();
  });

  it("selectWitnesses spreads across operators", () => {
    const picks = selectWitnesses(directory, "ab".repeat(32), 3);
    assert.equal(picks.length, 3);
    assert.equal(new Set(picks.map((p) => p.operator_org)).size, 3);
  });
});
