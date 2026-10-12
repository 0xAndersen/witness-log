#!/usr/bin/env node
/**
 * `npm create witness-log [dir] [-- --template plain|ai-sdk]`
 *
 * Copies one of the templates in ../templates into `dir`, fills in the
 * project name, and prints what to run next. No dependencies, no network:
 * installing the generated project's dependencies is left to you (or to
 * `--install`).
 */
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join, resolve, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const here = dirname(fileURLToPath(import.meta.url));
const templatesDir = join(here, "..", "templates");

function usage(code) {
  const out = `Usage: npm create witness-log [dir] [-- options]

Options:
  --template <name>   plain (default) or ai-sdk
  --install           run npm install in the new project
  --local <dir>       use the packages from a local checkout of clients/ (development)
  -h, --help          this text

Templates:
  plain    an agent loop that appends intent/result leaves with @witness-log/node,
           exports a dossier and verifies it offline (pure TypeScript verifier + Rust verifier)
  ai-sdk   the same with the Vercel AI SDK: witnessTools() around a tool, run against
           a mock model so it works without an API key
`;
  (code === 0 ? process.stdout : process.stderr).write(out);
  process.exit(code);
}

function parseArgs(argv) {
  const opts = { dir: null, template: "plain", install: false, local: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") usage(0);
    else if (a === "--template") opts.template = argv[++i];
    else if (a.startsWith("--template=")) opts.template = a.slice("--template=".length);
    else if (a === "--install") opts.install = true;
    else if (a === "--local") opts.local = argv[++i];
    else if (a.startsWith("--local=")) opts.local = a.slice("--local=".length);
    else if (a.startsWith("-")) {
      process.stderr.write(`unknown option ${a}\n`);
      usage(2);
    } else if (opts.dir === null) opts.dir = a;
    else {
      process.stderr.write(`unexpected argument ${a}\n`);
      usage(2);
    }
  }
  return opts;
}

export function create(opts) {
  const templates = readdirSync(templatesDir);
  if (!templates.includes(opts.template)) {
    throw new Error(`unknown template ${JSON.stringify(opts.template)}; available: ${templates.join(", ")}`);
  }
  const dir = resolve(opts.dir ?? `witness-log-${opts.template}`);
  if (existsSync(dir) && readdirSync(dir).length > 0) {
    throw new Error(`${dir} exists and is not empty`);
  }
  mkdirSync(dir, { recursive: true });
  cpSync(join(templatesDir, opts.template), dir, { recursive: true });
  // npm drops .gitignore from published packages; templates ship it as "gitignore".
  if (existsSync(join(dir, "gitignore"))) renameSync(join(dir, "gitignore"), join(dir, ".gitignore"));

  const pkgPath = join(dir, "package.json");
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
  pkg.name = basename(dir)
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^[._-]+/, "") || "witness-log-agent";
  if (opts.local) {
    const local = resolve(opts.local);
    const map = {
      "@witness-log/client": join(local, "typescript"),
      "@witness-log/node": join(local, "node"),
      "@witness-log/ai-sdk": join(local, "ai-sdk"),
    };
    for (const section of ["dependencies", "devDependencies"]) {
      for (const name of Object.keys(pkg[section] ?? {})) {
        if (map[name]) pkg[section][name] = `file:${map[name]}`;
      }
    }
  }
  writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");

  if (opts.install) {
    const r = spawnSync(process.platform === "win32" ? "npm.cmd" : "npm", ["install"], { cwd: dir, stdio: "inherit" });
    if (r.status !== 0) throw new Error(`npm install failed with ${r.status}`);
  }
  return dir;
}

const invokedDirectly = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  try {
    const opts = parseArgs(process.argv.slice(2));
    const dir = create(opts);
    const rel = basename(dir);
    process.stdout.write(`
Created ${dir} from the ${opts.template} template.

Next:
  cd ${rel}${opts.install ? "" : "\n  npm install"}
  npm start        # append, export dossier.json, verify
  npm test

Then get the head cosigned by witnesses you trust (see README.md).
`);
  } catch (e) {
    process.stderr.write(`create-witness-log: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exit(1);
  }
}
