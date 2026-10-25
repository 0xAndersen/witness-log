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
import * as native from "@witness-log/node/native";

/** The two verifiers must agree; returns the TypeScript verdict. */
function bothVerdicts(d: Dossier, opts: Parameters<typeof verifyDossier>[1] = {}) {
  const ts = verifyDossier(d, opts);
  const rs = verifyDossierNative(d, opts);
  assert.equal(ts.verdict, rs.verdict, `TS ${ts.verdict} vs Rust ${rs.verdict}: ${ts.failures.join("; ")}`);
  assert.equal(ts.exitCode, rs.exitCode);
  assert.equal(ts.failures.length > 0, rs.failures.length > 0);
  assert.equal(ts.contradictions.length, rs.contradictions.length);
  assert.equal(ts.splitViewUnsafe, rs.splitViewUnsafe);
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
    assert.equal(bothVerdicts(d, { identity: "ab".repeat(32) }).verdict, "INVALID");
    log.close();
    assert.equal(log.closed, true);
    assert.throws(() => log.appendIntent("x"), (e: unknown) => e instanceof WitnessLogError && e.code === "closed");
  });

  it("tampering is INVALID for both verifiers", () => {
    const log = openLog(tempJournalPath());
    for (let k = 0; k < 5; k++) log.appendIntent(`step ${k}`);
    const d = log.exportDossier();
    log.close();

    const edited = structuredClone(d);
    edited.leaves[2].payload_hash = "00".repeat(32);
    assert.equal(bothVerdicts(edited).verdict, "INVALID");

    const dropped = structuredClone(d);
    dropped.leaves.pop();
    assert.equal(bothVerdicts(dropped).verdict, "INVALID");

    const reordered = structuredClone(d);
    [reordered.leaves[0], reordered.leaves[1]] = [reordered.leaves[1], reordered.leaves[0]];
    assert.equal(bothVerdicts(reordered).verdict, "INVALID");

    const resigned = structuredClone(d);
    resigned.checkpoint.timestamp_ms = Number(resigned.checkpoint.timestamp_ms) + 1;
    assert.equal(bothVerdicts(resigned).verdict, "INVALID");

    const otherIdentity = structuredClone(d);
    otherIdentity.identity_pubkey = "cd".repeat(32);
    assert.equal(bothVerdicts(otherIdentity).verdict, "INVALID");

    const noBindings = structuredClone(d);
    noBindings.key_bindings = [];
    assert.equal(bothVerdicts(noBindings).verdict, "UNANCHORED"); // "not asserted", not a failure

    const wrongBinding = structuredClone(d);
    wrongBinding.key_bindings![0].session_number = Number(wrongBinding.key_bindings![0].session_number) + 1;
    assert.equal(bothVerdicts(wrongBinding).verdict, "INVALID");
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

describe("canonicalJson is RFC 8785, byte-identical to the Python package", () => {
  // Expected strings were produced by `witness_log.canonical_json` in Python.
  const dec = (b: Uint8Array) => new TextDecoder().decode(b);
  it("UTF-16 key order, literal UTF-8, ES6 number formatting", () => {
    assert.equal(
      dec(canonicalJson({ "é": 1, z: 2, "😀": 3, A: [1.5, "\u0007", 1e21, 1e-7, 10.0, -0] })),
      '{"A":[1.5,"\\u0007",1e+21,1e-7,10,0],"z":2,"é":1,"😀":3}',
    );
  });
  it("only quote, backslash and control characters are escaped", () => {
    assert.equal(
      dec(canonicalJson({ k: 'quote " backslash \\ nl \n tab \t del \x7f' })),
      '{"k":"quote \\" backslash \\\\ nl \\n tab \\t del \x7f"}',
    );
  });
  it("literals and safe integers", () => {
    assert.equal(dec(canonicalJson({ b: [null, true, false, 0, -1, 2 ** 53 - 1] })), '{"b":[null,true,false,0,-1,9007199254740991]}');
  });
  it("non-finite numbers become the same strings as in Python", () => {
    assert.equal(dec(canonicalJson({ nan: NaN, inf: Infinity })), '{"inf":"inf","nan":"nan"}');
  });
});

describe("corpus 15: both verifiers read evidence, known heads and labels alike", () => {
  const corpusFile = join(dirname(new URL(import.meta.url).pathname), "..", "..", "..", "..", "corpus", "15_evidence_and_args.json");
  it("refused (exit 2) or the same verdict, exit code and report fields", { skip: !existsSync(corpusFile) }, () => {
    const v = JSON.parse(readFileSync(corpusFile, "utf8"));
    for (const c of v.cases) {
      const opts = {
        directory: c.directory === null ? undefined : v.directories[c.directory],
        identity: c.expected_identity ?? undefined,
        threshold: c.threshold,
        minWitnesses: c.min_witnesses ?? undefined,
        knownHeads: c.known_heads,
        evidence: c.evidence.map((k: string) => v.evidence[k]),
        allowSubMajority: c.allow_sub_majority,
        subjectOrg: c.subject_org ?? undefined,
      };
      const e = c.expect;
      if (e.exit_code === 2) {
        assert.throws(() => verifyDossier(v.dossiers[c.dossier], opts), TypeError, `TS: ${c.name}`);
        assert.throws(() => verifyDossierNative(v.dossiers[c.dossier], opts), Error, `Rust: ${c.name}`);
        continue;
      }
      for (const r of [verifyDossier(v.dossiers[c.dossier], opts), verifyDossierNative(v.dossiers[c.dossier], opts)]) {
        assert.equal(r.report.verdict, e.verdict, c.name);
        assert.equal(r.exitCode, e.exit_code, c.name);
        assert.equal(r.report.contradictions.length, e.contradictions, c.name);
        assert.equal(r.report.known_heads_unchecked.length, e.known_heads_unchecked, c.name);
        assert.equal(r.report.quorum?.distinct_independent_operators ?? null, e.independent_operators, c.name);
      }
    }
  });

  it("F1: the evidence file witness serve writes is DIVERGED for both", { skip: !existsSync(corpusFile) }, () => {
    const v = JSON.parse(readFileSync(corpusFile, "utf8"));
    const ts = bothVerdicts(v.dossiers.full, { directory: v.directories.corpus, evidence: [v.evidence.wrapped] });
    assert.equal(ts.verdict, "DIVERGED");
  });
});

describe("corpus 13: both verifiers agree on every verdict case", () => {
  const corpusFile = join(dirname(new URL(import.meta.url).pathname), "..", "..", "..", "..", "corpus", "13_verdicts.json");
  it("verdict, exit code and report fields", { skip: !existsSync(corpusFile) }, () => {
    const v = JSON.parse(readFileSync(corpusFile, "utf8"));
    for (const c of v.cases) {
      const opts = {
        directory: c.trusted_directory ? v.trusted_directory : undefined,
        identity: c.expected_identity ?? undefined,
        threshold: c.threshold,
        minWitnesses: c.min_witnesses ?? undefined,
        knownHeads: c.known_heads,
        evidence: c.evidence.map((k: string) => v.evidence[k]),
        allowSubMajority: c.allow_sub_majority,
        subjectOrg: c.subject_org ?? undefined,
      };
      const ts = bothVerdicts(v.dossiers[c.dossier], opts);
      const rs = verifyDossierNative(v.dossiers[c.dossier], opts);
      for (const r of [ts, rs]) {
        assert.equal(r.report.verdict, c.expect.verdict, c.name);
        assert.equal(r.exitCode, c.expect.exit_code, c.name);
        assert.equal(r.report.contradictions.length, c.expect.contradictions, c.name);
        assert.equal(r.report.known_heads_unchecked.length, c.expect.known_heads_unchecked, c.name);
      }
    }
  });
});

describe("corpus 14: both verifiers agree on every fleet anchor case (RFC-0001, experimental)", () => {
  const corpusFile = join(dirname(new URL(import.meta.url).pathname), "..", "..", "..", "..", "corpus", "14_fleet_anchor.json");
  it("verdict, exit code, quorum, fleet status and path fields", { skip: !existsSync(corpusFile) }, () => {
    const v = JSON.parse(readFileSync(corpusFile, "utf8"));
    for (const c of v.cases) {
      const opts = {
        directory: c.trusted_directory ? v.trusted_directory : undefined,
        threshold: c.threshold,
        minWitnesses: c.min_witnesses ?? undefined,
        allowSubMajority: c.allow_sub_majority,
        subjectOrg: c.subject_org ?? undefined,
        acceptFleetAnchor: c.accept_fleet_anchor,
      };
      const ts = bothVerdicts(v.dossiers[c.dossier], opts);
      const rs = verifyDossierNative(v.dossiers[c.dossier], opts);
      const e = c.expect;
      for (const r of [ts, rs]) {
        assert.equal(r.report.verdict, e.verdict, c.name);
        assert.equal(r.exitCode, e.exit_code, c.name);
        assert.equal(r.report.quorum?.distinct_independent_operators ?? null, e.independent_operators, c.name);
        assert.equal(r.report.fleet_anchor?.status ?? null, e.fleet_anchor_status, c.name);
        assert.equal(r.report.fleet_anchor?.fleet_tree_size ?? null, e.fleet_tree_size, c.name);
        if (c.accept_fleet_anchor) {
          assert.deepEqual(r.report.witnessed_via, e.witnessed_via, c.name);
          assert.deepEqual(r.report.witness_paths, e.witness_paths, c.name);
        } else {
          assert.equal("witnessed_via" in r.report, false, c.name);
        }
      }
    }
  });
});

describe("corpus 16 and 17: strict Ed25519 and reading a dossier, both verifiers (outside review III)", () => {
  const dir = join(dirname(new URL(import.meta.url).pathname), "..", "..", "..", "..", "corpus");
  const optsOf = (v: any, c: any) => ({
    directory: c.directory === null ? undefined : v.directories[c.directory],
    identity: c.expected_identity ?? undefined,
    threshold: c.threshold,
    minWitnesses: c.min_witnesses ?? undefined,
    knownHeads: c.known_heads,
    evidence: c.evidence.map((k: string) => v.evidence[k]),
    allowSubMajority: c.allow_sub_majority,
    subjectOrg: c.subject_org ?? undefined,
  });
  const same = (r: ReturnType<typeof verifyDossier>, e: any, name: string) => {
    assert.equal(r.report.verdict, e.verdict, name);
    assert.equal(r.exitCode, e.exit_code, name);
    assert.equal(r.report.internally_consistent, e.internally_consistent, name);
    assert.equal(r.report.contradictions.length, e.contradictions, name);
    assert.equal(r.report.quorum?.valid_receipts ?? null, e.valid_receipts, name);
  };

  it("16: degenerate signatures in dossiers, the same verdict from both", { skip: !existsSync(join(dir, "16_ed25519_strict.json")) }, () => {
    const v = JSON.parse(readFileSync(join(dir, "16_ed25519_strict.json"), "utf8"));
    for (const c of v.cases) {
      const d = v.dossiers[c.dossier];
      for (const r of [verifyDossier(d, optsOf(v, c)), verifyDossierNative(d, optsOf(v, c))]) same(r, c.expect, c.name);
    }
  });

  it("17: a text that is not a dossier is INVALID in TypeScript and refused natively; others the same verdict", { skip: !existsSync(join(dir, "17_dossier_parsing.json")) }, () => {
    const v = JSON.parse(readFileSync(join(dir, "17_dossier_parsing.json"), "utf8"));
    for (const c of v.cases) {
      const opts = optsOf({ ...v, evidence: {} }, c);
      if (c.expect.not_a_dossier) {
        const ts = verifyDossier(c.dossier_json, opts);
        assert.equal(ts.exitCode, 40, c.name);
        assert.match(ts.failures[0], /^not a dossier: /, c.name);
        assert.throws(() => verifyDossierNative(c.dossier_json, opts), WitnessLogError, c.name);
        continue;
      }
      for (const r of [verifyDossier(c.dossier_json, opts), verifyDossierNative(c.dossier_json, opts)]) same(r, c.expect, c.name);
    }
  });

  it("17 inputs: a directory, revocations or evidence item nested deeper than 1000 is refused by both, as a malformed one", { skip: !existsSync(join(dir, "17_dossier_parsing.json")) }, () => {
    // Before, both read a directory or revocations of any depth, and the
    // native evidence list stopped at serde_json's 128 levels.
    const v = JSON.parse(readFileSync(join(dir, "17_dossier_parsing.json"), "utf8"));
    const valid: string = v.cases.find((c: { name: string }) => c.name === "valid").dossier_json;
    for (const c of v.inputs) {
      const value = JSON.parse(c.text);
      const opts =
        c.input === "directory"
          ? { directory: value, minWitnesses: c.min_witnesses }
          : c.input === "revocations"
            ? { revocations: value }
            : { evidence: [value] };
      // The native call takes the text itself: V8's JSON.stringify cannot
      // write a value 100,000 deep, which verifyDossierNative would do.
      const nativeOpts =
        c.input === "directory"
          ? { directoryJson: c.text, minWitnesses: c.min_witnesses }
          : c.input === "revocations"
            ? { revocationsJson: c.text }
            : { evidenceJson: `[${c.text}]` };
      const viaWrapper = c.text.length < 100_000;
      if (c.expect.refused) {
        assert.throws(() => verifyDossier(valid, opts), (e: Error) => e instanceof TypeError && /nested deeper than 1000/.test(e.message), c.name);
        assert.throws(() => native.verifyDossierJson(valid, nativeOpts), /nested deeper than 1000/, c.name);
        if (viaWrapper) assert.throws(() => verifyDossierNative(valid, opts), WitnessLogError, c.name);
        continue;
      }
      const rs = JSON.parse(native.verifyDossierJson(valid, nativeOpts));
      assert.equal(rs.verdict, c.expect.verdict, c.name);
      assert.equal(rs.failures.length > 0, c.expect.has_failures, c.name);
      assert.equal(rs.quorum?.valid_receipts ?? null, c.expect.valid_receipts, c.name);
      for (const r of [verifyDossier(valid, opts), verifyDossierNative(valid, opts)]) {
        assert.equal(r.report.verdict, c.expect.verdict, c.name);
        assert.equal(r.exitCode, c.expect.exit_code, c.name);
        assert.equal(r.report.contradictions.length, c.expect.contradictions, c.name);
      }
    }
  });

  it("a text nested deeper than 1000, refused by both at once; a huge input quoted in part", { skip: !existsSync(join(dir, "17_dossier_parsing.json")) }, () => {
    // Outside audit of 0.6.1: an ignored key of any depth was read by both,
    // and refusals quoted the whole input.
    const v = JSON.parse(readFileSync(join(dir, "17_dossier_parsing.json"), "utf8"));
    const min: string = v.cases.find((c: { name: string }) => c.name === "whitespace around the object").dossier_json.trim();
    const deep = `${min.slice(0, -1)},"zz":${"[".repeat(5_000_000)}${"]".repeat(5_000_000)}}`;
    const t0 = performance.now();
    assert.match(verifyDossier(deep).failures[0], /^not a dossier: nested deeper than 1000/);
    assert.throws(() => verifyDossierNative(deep), (e: Error) => e instanceof WitnessLogError && /nested deeper than 1000/.test(e.message));
    assert.ok(performance.now() - t0 < 3000, `${Math.round(performance.now() - t0)} ms`);
    const huge = min.replace('"tree_size":0', `"tree_size":"${"a".repeat(10_000_000)}"`);
    assert.ok(verifyDossier(huge).failures[0].length < 300);
    assert.throws(() => verifyDossierNative(huge), (e: Error) => e instanceof WitnessLogError && e.message.length < 1000);
  });
});
