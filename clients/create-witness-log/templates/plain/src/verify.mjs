// Verify a dossier offline: `node src/verify.mjs dossier.json [--identity <hex>] [--directory trusted.json] [--min 2]`
// Exit code is the verdict: 0 WITNESSED, 10 CONSISTENT-UNWITNESSED, 20 UNANCHORED, 30 DIVERGED.
import { readFileSync } from "node:fs";
import { verifyDossier, verifyDossierNative } from "@witness-log/node";

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith("--")) ?? "dossier.json";
const flag = (name) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};
const opts = {};
if (flag("identity")) opts.identity = flag("identity");
if (flag("directory")) opts.directory = JSON.parse(readFileSync(flag("directory"), "utf8"));
if (flag("min")) opts.minWitnesses = Number(flag("min"));

const dossier = JSON.parse(readFileSync(file, "utf8"));
const ts = verifyDossier(dossier, opts);
const rs = verifyDossierNative(dossier, opts);
console.log(`${ts.verdict} (TypeScript verifier), ${rs.verdict} (Rust verifier)`);
if (ts.failures.length) console.log("failures:", ts.failures.join("; "));
if (ts.report.quorum) {
  const q = ts.report.quorum;
  console.log(`receipts: ${q.valid_receipts} valid, ${q.distinct_independent_operators} independent operators (${q.independent_operators_represented.join(", ")})`);
}
if (!opts.directory) console.log("no --directory given: the verdict is capped at UNANCHORED (nothing you trust was consulted).");
process.exit(ts.verdict === rs.verdict ? ts.exitCode : 30);
