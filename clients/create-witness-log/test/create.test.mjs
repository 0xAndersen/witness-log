/**
 * Generates each template into a temp dir with `--local` (file: links to
 * this checkout's packages, which must be built: `npm run build` in
 * clients/node and clients/ai-sdk), installs it, runs its tests and `npm
 * start`, and checks the dossier it wrote verifies.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const bin = join(here, "..", "bin", "create-witness-log.js");
const clients = resolve(here, "..", "..");
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const nativeBuilt = existsSync(join(clients, "node", "native", "index.js")) && existsSync(join(clients, "node", "dist", "src", "index.js"));

function run(cmd, args, cwd) {
  // Drop the test-runner context, or the generated project's `node --test` thinks it is nested and runs nothing.
  const env = { ...process.env, npm_config_fund: "false", npm_config_audit: "false" };
  delete env.NODE_TEST_CONTEXT;
  const r = spawnSync(cmd, args, { cwd, encoding: "utf8", env });
  return { code: r.status, out: `${r.stdout}\n${r.stderr}` };
}

describe("create-witness-log", () => {
  it("prints usage and refuses unknown templates", () => {
    const help = run(process.execPath, [bin, "--help"]);
    assert.equal(help.code, 0);
    assert.match(help.out, /--template <name>/);
    const bad = run(process.execPath, [bin, join(mkdtempSync(join(tmpdir(), "cwl-")), "x"), "--template", "nope"]);
    assert.equal(bad.code, 1);
    assert.match(bad.out, /unknown template/);
  });

  for (const template of ["plain", "ai-sdk"]) {
    it(`generates a working ${template} project`, { skip: nativeBuilt ? false : "build clients/node first (npm run build)", timeout: 600_000 }, () => {
      const parent = mkdtempSync(join(tmpdir(), "cwl-"));
      const dir = join(parent, `my-${template}-agent`);
      try {
        const gen = run(process.execPath, [bin, dir, "--template", template, "--local", clients]);
        assert.equal(gen.code, 0, gen.out);
        assert.match(gen.out, /Created .* from the/);
        const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
        assert.equal(pkg.name, `my-${template}-agent`);
        assert.match(pkg.dependencies["@witness-log/node"], /^file:/);
        assert.equal(existsSync(join(dir, ".gitignore")), true);

        const install = run(npm, ["install", "--no-package-lock"], dir);
        assert.equal(install.code, 0, install.out);

        const test = run(npm, ["test"], dir);
        assert.equal(test.code, 0, test.out);
        assert.match(test.out, /# pass 1/);

        const start = run(npm, ["start"], dir);
        assert.equal(start.code, 0, start.out);
        assert.match(start.out, /verdict: UNANCHORED \(TypeScript\) \/ UNANCHORED \(Rust\)/);
        assert.equal(existsSync(join(dir, "dossier.json")), true);

        const verify = run(npm, ["run", "verify"], dir);
        assert.equal(verify.code, 20, verify.out); // UNANCHORED is exit 20
        assert.match(verify.out, /UNANCHORED \(TypeScript verifier\), UNANCHORED \(Rust verifier\)/);

        // Running again resumes the same journal and identity.
        const again = run(npm, ["start"], dir);
        assert.equal(again.code, 0, again.out);
        assert.match(again.out, /leaves so far/);
        assert.doesNotMatch(again.out, /, 0 leaves so far/);
      } finally {
        rmSync(parent, { recursive: true, force: true });
      }
    });
  }
});
