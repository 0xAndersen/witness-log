// A minimal agent loop with a witness-log audit trail.
//
// Every tool call is two leaves: an intent before it runs and a result
// after. The log holds salted commitments only; with `storePayloads` the
// plaintext is kept next to the journal so you can later prove what a leaf
// said (`log.disclose(i)`). Run with `npm start`.
import { writeFileSync } from "node:fs";
import { openLog, verifyDossier, verifyDossierNative } from "@witness-log/node";

const JOURNAL = process.env.WITNESS_LOG_JOURNAL ?? "agent.jsonl";

// The identity key lives in the journal header (0600). For a key you
// manage elsewhere pass `identitySeed` (32 bytes); add `seal: true` to keep
// it out of the file entirely.
const log = openLog(JOURNAL, { storePayloads: true });
console.log(`log ${log.identityPubkey} at ${log.path}, ${log.treeSize} leaves so far`);

// Pretend tools.
const tools = {
  async search(query) {
    return [{ title: "Oslo weather", snippet: "21C and clear" }];
  },
  async pay({ amountUsd, to }) {
    if (amountUsd > 100) throw new RangeError(`refusing to pay ${amountUsd} USD without approval`);
    return { tx: "t-1", amountUsd, to };
  },
};

// `step` appends the intent, runs the function, appends the result (or the
// error, which is rethrown).
const results = await log.step("search", () => tools.search("weather in Oslo"), { args: { query: "weather in Oslo" } });
console.log("search ->", results[0].snippet);

const payment = await log.step("pay", () => tools.pay({ amountUsd: 25, to: "merchant-7" }), { args: { amountUsd: 25, to: "merchant-7" } });
console.log("pay ->", payment.tx);

try {
  await log.step("pay", () => tools.pay({ amountUsd: 500, to: "merchant-7" }), { args: { amountUsd: 500, to: "merchant-7" } });
} catch (e) {
  console.log("pay (500) ->", e.message, "(recorded as an error result)");
}

// Hand the dossier to anyone. It verifies offline.
const dossier = log.exportDossier();
writeFileSync("dossier.json", JSON.stringify(dossier, null, 2));
console.log(`wrote dossier.json: ${dossier.leaves.length} leaves, root ${dossier.checkpoint.root_hash.slice(0, 16)}...`);

// Two independent verifiers: pure TypeScript, and the Rust reference verifier.
const ts = verifyDossier(dossier, { identity: log.identityPubkey });
const rs = verifyDossierNative(dossier, { identity: log.identityPubkey });
console.log(`verdict: ${ts.verdict} (TypeScript) / ${rs.verdict} (Rust)`);
console.log("UNANCHORED means internally consistent but not yet cosigned by witnesses you trust.");
console.log("Next: get the head cosigned, see README.md.");

log.close();
