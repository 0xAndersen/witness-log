// The page's rendering of the known-heads check, without a browser or an
// engine: web/verify.js runs in a vm with a stub DOM and is handed reports
// shaped like the engines' (Rust wasm, Go wasm). Security review of 0.5.0,
// F9: the page ticked "consistent with your known heads" for an INVALID
// dossier (whose heads are never compared) and for heads larger than the
// dossier (which cannot be compared). Run: node --test web/test/*.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const here = dirname(fileURLToPath(import.meta.url));

function page() {
  const els = {};
  const el = (id) =>
    (els[id] ??= {
      id, value: "", checked: false, textContent: "", innerHTML: "", hidden: false, disabled: false, files: [],
      classList: { add() {}, remove() {}, toggle() {} }, addEventListener() {},
    });
  const ctx = vm.createContext({
    document: { getElementById: el }, location: { search: "?engine=none" }, URLSearchParams, console,
    FileReader: class {}, setTimeout, TextEncoder,
  });
  vm.runInContext(readFileSync(join(here, "..", "verify.js"), "utf8"), ctx);
  const render = vm.runInContext("render", ctx);
  return {
    // Renders `report` with these known heads typed in; returns the check rows.
    checks(report, heads) {
      el("known-heads").value = heads.join(" ");
      render({
        verdict: report.verdict.toUpperCase().replace("CONSISTENT_UNWITNESSED", "CONSISTENT-UNWITNESSED"),
        exit_code: 0, identity_pinned: false, directory_pinned: false, report,
        summary: {
          checkpoint: { tree_size: report.claimed_tree_size, root_hash: "", signer_pubkey: "", timestamp_ms: 0, sig_alg: "ed25519", signature: "" },
          canonical_origin: null, receipts: [], leaves: [], key_bindings: [], claimed_directory_size: 0,
        },
      });
      return el("checks").innerHTML.split("</li>").filter((l) => l.includes("<li")).map((l) => {
        const mark = /<span class="mark">([^<]*)<\/span>/.exec(l)[1];
        const name = /<\/span><span>([^<]*)<small>/.exec(l)[1];
        return { mark, name, text: l.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim() };
      });
    },
  };
}

const report = (over) => ({
  checkpoint_signature_valid: true, identity_bound: true, leaves_structurally_valid: true, bindings_valid: true,
  bindings_asserted: false, leaf_count: 4, claimed_tree_size: 4, merkle_continuity_valid: true, externally_anchored: false,
  identity_pinned: false, internally_consistent: true, quorum: null, split_view_unsafe: false, failures: [],
  contradictions: [], known_heads_unchecked: [], verdict: "unanchored", ...over,
});
const root = "ab".repeat(32);
const headRows = (rows) => rows.filter((r) => r.name.includes("known heads"));

test("an INVALID dossier never shows a known-heads tick: its heads are not compared", () => {
  const p = page();
  const rows = p.checks(report({
    merkle_continuity_valid: false, internally_consistent: false, verdict: "invalid",
    failures: ["the leaves do not reproduce the signed root"],
  }), [`2:${root}`]);
  assert.deepEqual(headRows(rows), [], JSON.stringify(rows));
  assert.ok(rows.some((r) => r.name === "failed" && r.mark === "✗"));
});

test("a head larger than the dossier is shown as not checked, never ticked", () => {
  const p = page();
  const rows = headRows(p.checks(report({ known_heads_unchecked: [`9:${root}`] }), [`9:${root}`]));
  assert.equal(rows.length, 1, JSON.stringify(rows));
  assert.equal(rows[0].mark, "–");
  assert.match(rows[0].text, /larger than this dossier: 9:ab/);
});

test("a reproduced head is ticked; an unchecked one beside it is not", () => {
  const p = page();
  assert.deepEqual(headRows(p.checks(report({}), [`2:${root}`])).map((r) => r.mark), ["✓"]);
  const both = headRows(p.checks(report({ known_heads_unchecked: [`9:${root}`] }), [`2:${root}`, `9:${root}`]));
  assert.deepEqual(both.map((r) => [r.name, r.mark]), [["consistent with your known heads", "✓"], ["known heads not checked", "–"]]);
});

test("a contradicted head is a cross", () => {
  const p = page();
  const rows = headRows(p.checks(report({ verdict: "diverged", contradictions: [`known head 2:${root} is not what this dossier's first 2 leaves produce`] }), [`2:${root}`]));
  assert.deepEqual(rows.map((r) => r.mark), ["✗"]);
});
