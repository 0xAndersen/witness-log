/**
 * A small `c2sp.org/tlog-witness` lookalike for tests: it parses the
 * add-checkpoint body, remembers the size it last cosigned per origin,
 * answers 409 with its size when `old` is wrong, and otherwise signs a
 * `cosignature/v1` line under a fresh Ed25519 key. Scenarios (`mode`)
 * make it misbehave on purpose. It verifies nothing: the point of the
 * tests is the client, and the client must only count cosignatures that
 * verify under the directory's key over its own head.
 */
import { createServer, type Server } from "node:http";
import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import type { WitnessEntry } from "../src/index.js";

export type Mode = "ok" | "busy-once" | "refuse" | "garbage" | "wrong-key" | "stale-size";

export class MockWitness {
  readonly key: KeyObject;
  readonly pubkeyHex: string;
  readonly keyName: string;
  sizes = new Map<string, number>();
  requests: string[] = [];
  private busySent = false;
  private server: Server | null = null;
  url = "";

  constructor(
    readonly name: string,
    readonly org: string,
    public mode: Mode = "ok",
  ) {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    this.key = privateKey;
    const jwk = publicKey.export({ format: "jwk" }) as { x: string };
    this.pubkeyHex = Buffer.from(jwk.x, "base64url").toString("hex");
    this.keyName = `${name}.test/w`;
  }

  entry(): WitnessEntry {
    return {
      name: this.name,
      operator_org: this.org,
      url: this.url,
      pubkey: this.mode === "wrong-key" ? "ab".repeat(32) : this.pubkeyHex,
      runtime: "agent",
      compute_provider: null,
      is_project_operated: false,
    };
  }

  async start(): Promise<void> {
    this.server = createServer((req, res) => {
      let body = "";
      req.setEncoding("utf8");
      req.on("data", (c: string) => (body += c));
      req.on("end", () => {
        const [status, headers, text] = this.handle(req.url ?? "", body);
        res.writeHead(status, headers);
        res.end(text);
      });
    });
    await new Promise<void>((r) => this.server!.listen(0, "127.0.0.1", r));
    const a = this.server.address();
    if (typeof a !== "object" || a === null) throw new Error("no address");
    this.url = `http://127.0.0.1:${a.port}`;
  }

  stop(): Promise<void> {
    return new Promise((r) => (this.server ? this.server.close(() => r()) : r()));
  }

  handle(url: string, body: string): [number, Record<string, string>, string] {
    if (url !== "/add-checkpoint") return [404, {}, "not found\n"];
    this.requests.push(body);
    const text = { "content-type": "text/plain; charset=utf-8" };
    const sep = body.indexOf("\n\n");
    if (!body.startsWith("old ") || sep < 0) return [400, text, "malformed\n"];
    const old = Number.parseInt(body.slice(4, body.indexOf("\n")), 10);
    const note = body.slice(sep + 2);
    const noteEnd = note.indexOf("\n\n");
    if (noteEnd < 0) return [400, text, "malformed note\n"];
    const noteText = note.slice(0, noteEnd + 1);
    const [origin, sizeLine] = noteText.split("\n");
    const size = Number.parseInt(sizeLine, 10);

    if (this.mode === "busy-once" && !this.busySent) {
      this.busySent = true;
      return [429, { ...text, "retry-after": "1" }, "slow down\n"];
    }
    if (this.mode === "refuse") return [422, text, "consistency proof does not verify\n"];
    if (this.mode === "stale-size") return [409, { "content-type": "text/x.tlog.size" }, `${size + 5}\n`];

    const known = this.sizes.get(origin) ?? 0;
    if (old !== known) return [409, { "content-type": "text/x.tlog.size" }, `${known}\n`];
    if (size < known) return [400, text, "old checkpoint\n"];
    this.sizes.set(origin, size);

    if (this.mode === "garbage") return [200, text, "— nobody/w AAAAAAAAAAAA\n"];
    const timestamp = Math.floor(Date.now() / 1000);
    return [200, text, this.cosign(noteText, timestamp) + "\n"];
  }

  cosign(noteText: string, timestamp: number): string {
    const msg = `cosignature/v1\ntime ${timestamp}\n${noteText}`;
    const sig = sign(null, Buffer.from(msg), this.key);
    const pub = Buffer.from(this.pubkeyHex, "hex");
    const keyId = createHash("sha256")
      .update(Buffer.concat([Buffer.from(this.keyName), Buffer.from([0x0a, 0x04]), pub]))
      .digest()
      .subarray(0, 4);
    const ts = Buffer.alloc(8);
    ts.writeBigUInt64BE(BigInt(timestamp));
    return `— ${this.keyName} ${Buffer.concat([keyId, ts, sig]).toString("base64")}`;
  }
}
