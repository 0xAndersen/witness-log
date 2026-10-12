/**
 * End to end against the locally built CLI and the MCP server:
 *   WITNESS_LOG_BIN     the witness-log binary (default: ../../target/release/witness-log)
 *   WITNESS_LOG_PYTHON  a Python with witness_log and mcp>=2 installed (default: python3)
 * Two witnesses are started from the CLI on free ports.
 */
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { WitnessLogCLI, WitnessLogCLIError, WitnessLogMCP, WitnessLogMCPError } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url)); // clients/typescript/dist/test
const repo = resolve(here, "..", "..", "..", "..");
const exe = process.platform === "win32" ? "witness-log.exe" : "witness-log";
const BIN = process.env.WITNESS_LOG_BIN ?? join(repo, "target", "release", exe);
const SERVER = join(repo, "integrations", "mcp", "witness_mcp_server.py");

function freePort(): Promise<number> {
  return new Promise((res, rej) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const a = s.address();
      s.close(() => (typeof a === "object" && a ? res(a.port) : rej(new Error("no port"))));
    });
  });
}

async function waitHealthy(url: string): Promise<void> {
  for (let i = 0; i < 200; i++) {
    try {
      if ((await fetch(url + "/health")).ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`witness at ${url} did not start`);
}

describe("@witness-log/client", { skip: existsSync(BIN) ? false : `no CLI at ${BIN}` }, () => {
  const cli = new WitnessLogCLI({ bin: BIN });
  const procs: ChildProcess[] = [];
  let tmp = "";
  let directory: { witnesses: Array<Record<string, unknown>> } = { witnesses: [] };
  let wl: WitnessLogMCP;

  before(async () => {
    tmp = await mkdtemp(join(tmpdir(), "wl-ts-"));
    for (const [name, org] of [
      ["w1", "Org One"],
      ["w2", "Org Two"],
    ]) {
      const port = await freePort();
      const url = `http://127.0.0.1:${port}`;
      const init = await cli.run(["witness", "init", join(tmp, name), "--name", `${name}.test/w`, "--org", org, "--url", url]);
      assert.equal(init.code, 0, init.stderr);
      directory.witnesses.push(JSON.parse(init.stdout));
      const p = spawn(BIN, ["witness", "serve", join(tmp, name), "--listen", `127.0.0.1:${port}`, "--open-enrollment"], {
        stdio: "ignore",
      });
      procs.push(p);
      await waitHealthy(url);
    }
    wl = await WitnessLogMCP.start({ sessionId: "agent-1", serverPath: SERVER, home: join(tmp, "home"), metadata: { model: "test" } });
  });

  after(async () => {
    await wl?.close();
    for (const p of procs) p.kill();
    await rm(tmp, { recursive: true, force: true });
  });

  it("starts a chain over MCP", () => {
    assert.equal(wl.resumed, false);
    assert.match(wl.head.identityPubkey, /^[0-9a-f]{64}$/);
    assert.equal(wl.head.origin, `witness-log/${wl.head.identityPubkey}`);
    assert.equal(wl.head.treeSize, 1);
  });

  it("step records intent before and result after, and rethrows errors", async () => {
    const v = await wl.step("transfer", async () => ({ ok: true, tx: "t1" }), { args: { amount: 5 } });
    assert.deepEqual(v, { ok: true, tx: "t1" });
    await assert.rejects(
      wl.step("fail", () => {
        throw new RangeError("nope");
      }),
      RangeError,
    );
    const d = await wl.exportDossier();
    const types = (d.leaves as Array<{ leaf_type: number }>).map((l) => l.leaf_type);
    assert.deepEqual(types, [0, 1, 2, 1, 2]);
  });

  it("forget erases a payload and keeps every proof", async () => {
    assert.equal(await wl.forget(1), true);
    assert.equal(await wl.forget(1), false);
    const r = await wl.verify();
    assert.equal(r.verdict, "unanchored");
    assert.deepEqual(r.tamperAlerts, []);
  });

  it("CLI verify returns typed verdicts", async () => {
    const d = await wl.exportDossier();
    const plain = await cli.verify(d);
    assert.equal(plain.verdict, "UNANCHORED");
    assert.equal(plain.exitCode, 20);
    assert.equal(plain.ok, false);
    const pinned = await cli.verify(d, { identity: wl.head.identityPubkey, directory });
    assert.equal(pinned.verdict, "CONSISTENT-UNWITNESSED");
    assert.equal(pinned.exitCode, 10);
    assert.equal(pinned.identityPinned, true);
  });

  it("gets WITNESSED through the MCP server and the CLI agrees", async () => {
    const s = await wl.submit(directory);
    assert.equal(s.cosignatures, 2);
    assert.equal(s.verdict, "witnessed");
    const r = await wl.verify({ trustedDirectory: directory });
    assert.equal(r.verdict, "witnessed");
    const v = await cli.verify(await wl.exportDossier(), { identity: wl.head.identityPubkey, directory, minWitnesses: 2 });
    assert.equal(v.verdict, "WITNESSED");
    assert.equal(v.exitCode, 0);
    assert.equal(v.ok, true);
  });

  it("CLI submit takes over the same journal and state", async () => {
    await wl.step("later", () => 1);
    const journal = join(tmp, "home", "agent-1", "journal.jsonl");
    const s = await cli.submit(journal, { directory, min: 2 });
    assert.equal(s.exitCode, 0, s.stderr);
    assert.equal(s.cosigned, 2);
    assert.ok(s.dossier);
    const v = await cli.verify(s.dossier, { identity: wl.head.identityPubkey, directory });
    assert.equal(v.verdict, "WITNESSED");
  });

  it("tampering is DIVERGED and diff reports it", async () => {
    const d = await wl.exportDossier();
    const t = structuredClone(d) as { leaves: Array<{ payload_hash: string }> };
    t.leaves[2].payload_hash = "00".repeat(32);
    const v = await cli.verify(t, { identity: wl.head.identityPubkey });
    assert.equal(v.verdict, "DIVERGED");
    assert.equal(v.exitCode, 30);
    const same = await cli.diff(d, d);
    assert.equal(same.consistent, true);
    const diff = await cli.diff(d, t);
    assert.equal(diff.exitCode, 30);
  });

  it("bind matches a handoff between two agents", async () => {
    const other = await WitnessLogMCP.start({ sessionId: "agent-2", serverPath: SERVER, home: join(tmp, "home2") });
    try {
      await wl.tool("record_handoff", {
        direction: "sent",
        counterparty_identity_pubkey: other.head.identityPubkey.toUpperCase(),
        state: { task: "reconcile" },
      });
      await other.tool("record_handoff", {
        direction: "received",
        counterparty_identity_pubkey: wl.head.identityPubkey,
        state: { task: "reconcile" },
      });
      const b = await cli.bind(await wl.exportDossier(), await other.exportDossier());
      assert.equal(b.exitCode, 0);
      assert.equal(b.bound.length, 1);
      assert.equal(b.failed.length, 0);
    } finally {
      await other.close();
    }
  });

  it("errors carry the reason", async () => {
    await assert.rejects(cli.verify(join(tmp, "missing.json")), (e: unknown) => {
      assert.ok(e instanceof WitnessLogCLIError);
      assert.equal(e.exitCode, 2);
      return true;
    });
    await assert.rejects(new WitnessLogCLI({ bin: join(tmp, "no-such-binary") }).version(), WitnessLogCLIError);
    await assert.rejects(wl.tool("get_inclusion_proof", { entry_index: 10_000 }), (e: unknown) => {
      assert.ok(e instanceof WitnessLogMCPError);
      assert.match(e.message, /no leaf at index 10000/);
      return true;
    });
    await assert.rejects(
      wl.tool("record_handoff", { direction: "sent", counterparty_identity_pubkey: "zz", state: {} }),
      /64 hex/,
    );
  });

  it("reports the CLI version", async () => {
    assert.match(await cli.version(), /^\d+\.\d+\.\d+/);
  });
});
