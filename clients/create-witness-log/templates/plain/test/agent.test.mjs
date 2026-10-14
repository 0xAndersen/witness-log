import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openLog, verifyDossier, verifyDossierNative } from "@witness-log/node";

test("append -> export -> verify, and tampering is caught", async () => {
  const path = join(mkdtempSync(join(tmpdir(), "wl-")), "agent.jsonl");
  const log = openLog(path, { storePayloads: true });
  await log.step("search", async () => ["result"], { args: { query: "q" } });
  await assert.rejects(
    log.step("pay", () => {
      throw new RangeError("too much");
    }),
    RangeError,
  );
  assert.equal(log.treeSize, 4);

  const dossier = log.exportDossier();
  assert.equal(verifyDossier(dossier, { identity: log.identityPubkey }).verdict, "UNANCHORED");
  assert.equal(verifyDossierNative(dossier, { identity: log.identityPubkey }).verdict, "UNANCHORED");

  const tampered = structuredClone(dossier);
  tampered.leaves[1].payload_hash = "00".repeat(32);
  assert.equal(verifyDossier(tampered).verdict, "INVALID");
  assert.equal(verifyDossierNative(tampered).verdict, "INVALID");

  // Prove what leaf 0 said, then forget it; the dossier still verifies.
  const d = log.disclose(0);
  assert.equal(d.verified, true);
  assert.equal(log.forget(0), true);
  assert.equal(verifyDossier(log.exportDossier()).verdict, "UNANCHORED");
  log.close();
});
