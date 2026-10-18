// witness-log browser verifier. Loads the wasm engine, reads the files the
// reader drops, calls verify_dossier_with_options / verify_disclosure /
// bind, and renders the result. No network after load; nothing is sent.

const $ = (id) => document.getElementById(id);

const MEANING = {
  WITNESSED:
    "Every cryptographic and structural check passes, and witnesses from at least two independent operators in your trusted directory cosigned this exact checkpoint. The log cannot have shown a different history to those witnesses.",
  "CONSISTENT-UNWITNESSED":
    "The cryptography is sound and you supplied a trusted directory, but witness coverage is absent, below the gate, or from fewer than two independent operators. A single-operator log can still show different histories to different readers.",
  UNANCHORED:
    "The dossier does not contradict itself, and that is all: no trusted directory was supplied, so nothing ties it to a party you did not already trust. A fabricated dossier reaches this verdict too.",
  DIVERGED:
    "The dossier is valid on its own and contradicts other evidence about the same identity (a head you already trusted, or a witness's equivocation proof): this identity has shown two different histories.",
  INVALID:
    "A check failed. The file was altered after signing, was fabricated, or is not the log named by the expected identity; it establishes nothing. The failing check is marked below.",
};

const state = { engine: null, dossier: null, directory: null, other: null, lastResult: null };

async function loadEngine() {
  // The Rust build (wasm-bindgen) is the primary engine. The Go build is
  // the same API from the second implementation; web/build-go.sh produces
  // it, and the Playwright test uses it where the Rust toolchain cannot
  // target wasm32.
  const want = new URLSearchParams(location.search).get("engine"); // ?engine=rust|go pins one
  const candidates = [
    { name: "rust", url: "./pkg/witness_log_wasm.js" },
    { name: "go", url: "./pkg-go/witness_log_go.js" },
  ].filter((c) => !want || c.name === want);
  const errors = [];
  for (const c of candidates) {
    try {
      const mod = await import(c.url);
      await mod.default();
      state.engine = { name: c.name, mod };
      $("engine").textContent = `engine: ${c.name} wasm, witness-log ${mod.version()}`;
      return;
    } catch (e) {
      errors.push(`${c.url}: ${e && e.message ? e.message : e}`);
    }
  }
  setStatus(
    "The verifier module is not built. Run web/build.sh (Rust) or web/build-go.sh (Go) and reload. " + errors.join(" | "),
    true,
  );
}

function setStatus(text, isError = false) {
  const el = $("status");
  el.textContent = text;
  el.classList.toggle("error", isError);
}

function readFile(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result);
    r.onerror = () => reject(r.error);
    r.readAsText(file);
  });
}

function wireDrop(zoneId, inputId, fileLabelId, onText) {
  const zone = $(zoneId);
  const input = $(inputId);
  const take = async (file) => {
    if (!file) return;
    try {
      const text = await readFile(file);
      JSON.parse(text); // fail early with a clear message
      $(fileLabelId).textContent = `${file.name} (${file.size.toLocaleString()} bytes)`;
      zone.classList.add("loaded");
      onText(text, file.name);
    } catch (e) {
      $(fileLabelId).textContent = "";
      zone.classList.remove("loaded");
      setStatus(`${file.name} is not JSON: ${e.message}`, true);
    }
  };
  input.addEventListener("change", () => take(input.files[0]));
  zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("over"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("over"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("over");
    take(e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]);
  });
  zone.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); } });
}

function updateVerifyButton() {
  $("verify").disabled = !(state.engine && state.dossier);
  if (state.engine && state.dossier) setStatus("Ready. Click Verify.");
}

function options() {
  const o = {};
  const id = $("identity").value.trim();
  if (id) o.expected_identity_pubkey = id;
  const th = parseFloat($("threshold").value);
  if (!Number.isNaN(th)) o.threshold = th;
  const min = $("min-receipts").value.trim();
  if (min !== "") o.min_receipts = parseInt(min, 10);
  const heads = $("known-heads").value.split(/[\s,]+/).filter((h) => h !== "");
  if (heads.length) o.known_heads = heads;
  if ($("allow-sub-majority").checked) o.allow_sub_majority = true;
  return o;
}

function verify() {
  if (!state.engine || !state.dossier) return;
  let result;
  try {
    result = state.engine.mod.verify_dossier_with_options(state.dossier, state.directory ?? undefined, JSON.stringify(options()));
  } catch (e) {
    setStatus(`Cannot verify: ${e && e.message ? e.message : e}`, true);
    $("result").hidden = true;
    return;
  }
  state.lastResult = result;
  render(result);
  setStatus(`Verified ${result.summary.leaves.length} leaves in your browser.`);
}

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const short = (hex, n = 12) => (hex && hex.length > n * 2 ? `${hex.slice(0, n)}…${hex.slice(-6)}` : hex ?? "");
const when = (ms) => (ms === null || ms === undefined ? "" : new Date(Number(ms)).toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z"));
const mark = (ok) => (ok ? '<span class="ok">✓</span>' : '<span class="bad">✗</span>');

function render(r) {
  const rep = r.report;
  const s = r.summary;
  $("result").hidden = false;

  const v = $("verdict");
  v.className = `verdict ${r.verdict.toLowerCase()}`;
  $("verdict-word").textContent = r.verdict;
  $("verdict-meaning").textContent = MEANING[r.verdict] || "";
  $("verdict-exit").textContent =
    `witness-log verify would exit ${r.exit_code}` +
    (r.exit_code === 11 ? " — WITNESSED, but by fewer than a strict majority of your directory, so a conflicting history could have been cosigned by the rest" : "") +
    (r.identity_pinned ? "" : " — no expected identity was supplied, so this says what the log's history is, not whose log it is");

  const checks = [
    ["checkpoint signature", rep.checkpoint_signature_valid, `Ed25519 over "witness-log-sth-v2" with the algorithm and signer key inside the signed message.`],
    ["identity bound", rep.identity_bound, r.identity_pinned ? "dossier identity equals the checkpoint signer, and equals the key you expected." : "dossier identity equals the checkpoint signer (self-consistency only; pin an expected identity to authenticate)."],
    ["leaves structurally valid", rep.leaves_structurally_valid, `${rep.leaf_count} leaves: recognised types, well-formed fields, indices matching position, anchor proofs matching their committed hash.`],
    rep.bindings_asserted
      ? ["session key bindings", rep.bindings_valid, "every leaf's session key traces to a binding signed by this identity, within its validity window, before any revocation."]
      : ["session key bindings", null, "not asserted by this dossier."],
    ["Merkle continuity", rep.merkle_continuity_valid, `root rebuilt from the leaves equals the signed root at tree size ${rep.claimed_tree_size}.`],
    rep.externally_anchored
      ? rep.quorum
        ? ["witness quorum", rep.quorum.meets_count_threshold && rep.quorum.distinct_independent_operators >= 2,
          `${rep.quorum.valid_receipts} valid receipt(s) from ${rep.quorum.total_directory_witnesses} trusted witness(es); gate ${rep.quorum.count_gate}; ${rep.quorum.distinct_independent_operators} independent operator(s) (need 2): ${rep.quorum.independent_operators_represented.join(", ") || "none"}; project-operated receipts ${rep.quorum.project_operated_receipts}; split-view resistant: ${rep.quorum.split_view_resistant ? "yes" : "no"}.`]
        : ["witness quorum", false, "the dossier carries no receipts to score against your directory."]
      : ["witness quorum", null, "not scored: no trusted directory supplied."],
  ];
  const failures = rep.failures || [];
  for (const f of failures) checks.push(["failed", false, f]);
  const contradictions = rep.contradictions || [];
  const heads = options().known_heads || [];
  // Known heads are compared only with a dossier that passed every check
  // (an INVALID one never is), and a head larger than the dossier cannot
  // be compared at all: neither may show a tick (security review of 0.5.0, F9).
  if (heads.length && failures.length === 0) {
    const unchecked = rep.known_heads_unchecked || [];
    if (contradictions.length) {
      checks.push(["consistent with your known heads", false, contradictions.join("; ")]);
    } else if (heads.length > unchecked.length) {
      checks.push(["consistent with your known heads", true,
        unchecked.length ? "this dossier's leaves reproduce every head you supplied that it is long enough to check." : "this dossier's leaves reproduce every head you supplied."]);
    }
    if (unchecked.length) checks.push(["known heads not checked", null, `larger than this dossier: ${unchecked.join(", ")}`]);
  } else if (heads.length === 0) {
    for (const c of contradictions) checks.push(["contradiction", false, c]);
  }
  $("checks").innerHTML = checks
    .map(([name, ok, note]) => `<li class="${ok === null ? "skip" : ok ? "ok" : "bad"}"><span class="mark">${ok === null ? "–" : ok ? "✓" : "✗"}</span><span>${esc(name)}<small>${esc(note)}</small></span></li>`)
    .join("");

  const cp = s.checkpoint;
  $("checkpoint").innerHTML = [
    ["tree size", cp.tree_size],
    ["root hash", cp.root_hash],
    ["signer (identity key)", cp.signer_pubkey],
    ["signed at (self-asserted)", `${cp.timestamp_ms} = ${when(cp.timestamp_ms)}`],
    ["algorithm", cp.sig_alg],
    ["signature", cp.signature],
    ["C2SP origin", s.canonical_origin ?? "—"],
  ].map(([k, val]) => `<dt>${esc(k)}</dt><dd>${esc(val)}</dd>`).join("");

  $("receipts-note").textContent = s.receipts.length
    ? `${s.receipts.length} in the dossier; ${r.directory_pinned ? "scored against your directory" : "not scored (no directory)"}; the dossier's own directory lists ${s.claimed_directory_size}`
    : "";
  $("receipts").innerHTML = s.receipts.length
    ? `<table><thead><tr><th>witness key</th><th>kind</th><th>witnessed at</th><th>signature</th><th>in your directory</th><th>operator</th></tr></thead><tbody>${s.receipts
        .map((w) => `<tr><td title="${esc(w.witness_pubkey)}">${esc(short(w.witness_pubkey))}</td><td>${esc(w.kind)}</td><td>${esc(when(w.witnessed_at_ms))}</td><td>${mark(w.signature_valid)}${w.signature_error ? ` <span class="dim">${esc(w.signature_error)}</span>` : ""}</td><td>${r.directory_pinned ? (w.in_trusted_directory ? mark(true) : '<span class="dim">no</span>') : '<span class="dim">—</span>'}</td><td class="wrap">${w.in_trusted_directory ? esc(w.trusted_operator_org) + (w.trusted_is_project_operated ? ' <span class="amber">project-operated</span>' : "") : w.claimed_operator_org ? `<span class="dim">claims ${esc(w.claimed_operator_org)}</span>` : ""}</td></tr>`)
        .join("")}</tbody></table>`
    : `<p class="empty">No witness receipts. The log has not been cosigned by anyone.</p>`;

  $("leaves-note").textContent = `${s.leaves.length} leaves`;
  $("leaves").innerHTML = s.leaves.length
    ? `<table><thead><tr><th>#</th><th>type</th><th>time</th><th>session key</th><th>payload hash</th><th>details</th></tr></thead><tbody>${s.leaves
        .map((l) => `<tr class="${l.structurally_valid ? "" : "invalid"}"><td>${l.index}</td><td>${esc(l.leaf_type_name)}</td><td>${esc(when(l.timestamp_ms))}</td><td title="${esc(l.session_pubkey)}">${esc(short(l.session_pubkey, 8))}</td><td title="${esc(l.payload_hash)}">${esc(short(l.payload_hash, 8))}</td><td class="wrap">${esc(leafDetails(l))}</td></tr>`)
        .join("")}</tbody></table>`
    : `<p class="empty">No leaves.</p>`;

  $("bindings-note").textContent = s.key_bindings.length ? `${s.key_bindings.length}; custody is self-asserted and never changes the verdict` : "none in this dossier";
  $("bindings").innerHTML = s.key_bindings.length
    ? `<table><thead><tr><th>session key</th><th>session</th><th>issued</th><th>expires</th><th>custody</th><th>signature</th></tr></thead><tbody>${s.key_bindings
        .map((b) => `<tr><td title="${esc(b.session_pubkey)}">${esc(short(b.session_pubkey, 8))}</td><td>${b.session_number}</td><td>${esc(when(b.timestamp_ms))}</td><td>${b.not_after_ms ? esc(when(b.not_after_ms)) : "never"}</td><td>${esc(custody(b.custody))}</td><td>${mark(b.signature_valid && b.names_this_identity)}</td></tr>`)
        .join("")}</tbody></table>`
    : "";

  $("report-json").textContent = JSON.stringify(rep, null, 2);

  const sel = $("disclose-leaf");
  sel.innerHTML = s.leaves.map((l) => `<option value="${l.index}">${l.index} ${esc(l.leaf_type_name)}</option>`).join("");
  $("disclose-out").textContent = "";
  if (state.other) bind();
}

function custody(c) {
  if (c && typeof c === "object" && c.threshold) return `threshold ${c.threshold.k}-of-${c.threshold.n}`;
  return c || "undisclosed";
}

function leafDetails(l) {
  const parts = [];
  if (l.redacted_index !== null && l.redacted_index !== undefined) parts.push(`forgets leaf ${l.redacted_index}`);
  if (l.revoked_identity) parts.push(`revokes ${short(l.revoked_identity, 8)}`);
  if (l.handoff_direction) parts.push(`${l.handoff_direction.toLowerCase()} ⇄ ${short(l.counterparty_pubkey, 8)}, state ${short(l.handoff_state_hash, 8)}`);
  if (l.authorization_event_kind) parts.push(`${l.authorization_event_kind} ⇄ ${short(l.counterparty_pubkey, 8)}, scope ${short(l.authorization_scope_hash, 8)}`);
  if (l.anchor_url) parts.push(`${l.anchor_url}${l.has_anchor_proof_json ? "" : " (proof not carried)"}`);
  if (!l.structurally_valid) parts.push(l.structural_error || "invalid");
  return parts.join("; ");
}

function disclose() {
  if (!state.lastResult) return;
  const idx = parseInt($("disclose-leaf").value, 10);
  const dossier = JSON.parse(state.dossier);
  const leaf = dossier.leaves[idx];
  const out = $("disclose-out");
  const run = (bytes) => {
    try {
      const res = state.engine.mod.verify_disclosure(JSON.stringify(leaf), bytes, $("disclose-salt").value.trim());
      out.innerHTML = res.matches
        ? `${mark(true)} leaf ${res.leaf_index} commits to exactly this payload (${bytes.length} bytes).`
        : `${mark(false)} this payload and salt do not reproduce leaf ${res.leaf_index}'s payload_hash.<br><span class="dim">committed ${esc(res.committed)}<br>recomputed ${esc(res.recomputed)}</span>`;
    } catch (e) {
      out.innerHTML = `${mark(false)} ${esc(e && e.message ? e.message : e)}`;
    }
  };
  const f = $("disclose-file").files[0];
  if (f) {
    f.arrayBuffer().then((buf) => run(new Uint8Array(buf)));
  } else {
    run(new TextEncoder().encode($("disclose-payload").value));
  }
}

function bind() {
  if (!state.dossier || !state.other) return;
  const out = $("bind-out");
  try {
    const res = state.engine.mod.bind(state.dossier, state.other);
    const lines = [];
    for (const p of res.bound) {
      lines.push(p.kind === "handoff"
        ? `${mark(true)} handoff: ${esc(short(p.sender, 8))} leaf ${p.sender_leaf} → ${esc(short(p.receiver, 8))} leaf ${p.receiver_leaf}, state ${esc(short(p.state_hash, 8))}`
        : `${mark(true)} authorization: leaf ${p.a_leaf} ${esc(p.a_event)} ↔ leaf ${p.b_leaf} ${esc(p.b_event)}, scope ${esc(short(p.scope_hash, 8))}`);
    }
    for (const f of res.failed) lines.push(`${mark(false)} ${esc(f.kind)} not bound: ${esc(f.reason)}`);
    const verdict = res.exit === 0 ? "BOUND: both logs committed to the same bytes between the same two identities."
      : res.exit === 30 ? "MISMATCH: the two logs disagree about what was handed over, or to whom."
      : "NO CROSS-LOG LEAVES: neither dossier names the other identity.";
    lines.push(`<strong>${esc(verdict)}</strong> <span class="dim">(witness-log bind would exit ${res.exit}; verify each dossier on its own first)</span>`);
    out.innerHTML = lines.join("<br>");
  } catch (e) {
    out.innerHTML = `${mark(false)} ${esc(e && e.message ? e.message : e)}`;
  }
}

wireDrop("drop-dossier", "input-dossier", "file-dossier", (text) => { state.dossier = text; state.lastResult = null; $("result").hidden = true; updateVerifyButton(); });
wireDrop("drop-directory", "input-directory", "file-directory", (text) => { state.directory = text; $("clear-directory").hidden = false; updateVerifyButton(); });
wireDrop("drop-other", "input-other", "file-other", (text) => { state.other = text; bind(); });
$("clear-directory").addEventListener("click", () => {
  state.directory = null;
  $("file-directory").textContent = "";
  $("drop-directory").classList.remove("loaded");
  $("clear-directory").hidden = true;
});
$("verify").addEventListener("click", verify);
$("disclose").addEventListener("click", disclose);

loadEngine().then(() => { if (state.engine) { setStatus(state.dossier ? "Ready. Click Verify." : "Drop a dossier to begin."); updateVerifyButton(); } });
