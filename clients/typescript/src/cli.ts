/**
 * The `witness-log` CLI as typed functions. Every verdict comes from the
 * Rust verifier in the binary; this module only spawns it, writes inputs
 * to temp files when given objects, and parses `--json`.
 */
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** The four verdicts, as the CLI prints them. */
export type Verdict = "WITNESSED" | "CONSISTENT-UNWITNESSED" | "UNANCHORED" | "DIVERGED";

/** Exit code for each verdict (the CLI's contract). */
export const EXIT_CODES: Readonly<Record<Verdict, number>> = Object.freeze({
  WITNESSED: 0,
  "CONSISTENT-UNWITNESSED": 10,
  UNANCHORED: 20,
  DIVERGED: 30,
});

/** A dossier: a path to its JSON file, or the parsed object. */
export type DossierInput = string | Record<string, unknown>;
/** A witness directory: a path, `{witnesses: [...]}`, or a bare array of entries. */
export type DirectoryInput = string | Record<string, unknown> | unknown[];

export interface CLIOptions {
  /** Path to the binary. Default: `$WITNESS_LOG_BIN`, else `witness-log` on PATH. */
  bin?: string;
  /** Per-command timeout in milliseconds. Default 120000. */
  timeoutMs?: number;
}

export interface VerifyOptions {
  /** The identity public key you expect (64 hex), obtained out of band. */
  identity?: string;
  /** A witness directory YOU trust. */
  directory?: DirectoryInput;
  /** Quorum as a fraction of the directory (0..1). */
  threshold?: number;
  /** Quorum as an absolute count of cosigning witnesses. */
  minWitnesses?: number;
}

export interface VerifyResult {
  verdict: Verdict;
  exitCode: number;
  /** True only for WITNESSED. */
  ok: boolean;
  identityPubkey: string;
  identityPinned: boolean;
  directoryPinned: boolean;
  /** The verifier's full report (`DossierReport`, see spec/SPEC.md). */
  report: Record<string, unknown>;
  /** Warnings the CLI printed on stderr (e.g. split-view gates). */
  warnings: string[];
}

export interface DiffResult {
  /** 0: same history or one a prefix of the other; 30: equivocation or tampering. */
  exitCode: number;
  consistent: boolean;
  output: string;
}

export interface BindResult {
  /** 0 bound, 30 mismatch, 10 nothing to bind. */
  exitCode: number;
  bound: Array<Record<string, unknown>>;
  failed: Array<Record<string, unknown>>;
}

export interface SubmitOptions {
  directory: DirectoryInput;
  /** Where to write the dossier. Default: a temp file, read back and returned. */
  out?: string;
  /** Client state file. Default `<journal>.witnesses.json` (shared with Python). */
  state?: string;
  /** Exit non-zero unless at least this many witnesses cosigned. */
  min?: number;
}

export interface SubmitResult {
  exitCode: number;
  /** Witnesses that cosigned, from the CLI's report. */
  cosigned: number;
  dossier: Record<string, unknown> | null;
  stderr: string;
}

/** A non-verdict failure: usage error (exit 2), missing binary, timeout. */
export class WitnessLogCLIError extends Error {
  constructor(
    message: string,
    readonly exitCode: number | null,
    readonly stderr: string,
  ) {
    super(message);
    this.name = "WitnessLogCLIError";
  }
}

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

export class WitnessLogCLI {
  readonly bin: string;
  readonly timeoutMs: number;

  constructor(opts: CLIOptions = {}) {
    this.bin = opts.bin ?? process.env.WITNESS_LOG_BIN ?? "witness-log";
    this.timeoutMs = opts.timeoutMs ?? 120_000;
  }

  /** Run the binary with `args`. Resolves with any exit code; rejects only if it could not run. */
  run(args: string[]): Promise<RunResult> {
    return new Promise((resolve, reject) => {
      const child = spawn(this.bin, args, { stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "";
      let stderr = "";
      child.stdout.setEncoding("utf8").on("data", (d: string) => (stdout += d));
      child.stderr.setEncoding("utf8").on("data", (d: string) => (stderr += d));
      const timer = setTimeout(() => child.kill("SIGKILL"), this.timeoutMs);
      child.on("error", (e) => {
        clearTimeout(timer);
        reject(new WitnessLogCLIError(`could not run ${this.bin}: ${e.message}`, null, ""));
      });
      child.on("close", (code, signal) => {
        clearTimeout(timer);
        if (code === null) {
          reject(new WitnessLogCLIError(`${this.bin} ${args[0]} was killed (${signal})`, null, stderr));
        } else {
          resolve({ code, stdout, stderr });
        }
      });
    });
  }

  /** Offline verification. Resolves with the verdict for exit 0/10/20/30; rejects on exit 2. */
  async verify(dossier: DossierInput, opts: VerifyOptions = {}): Promise<VerifyResult> {
    return withTemp(async (tmp) => {
      const args = ["verify", await asFile(tmp, "dossier.json", dossier), "--json"];
      if (opts.identity !== undefined) args.push("--identity", opts.identity);
      if (opts.directory !== undefined) args.push("--directory", await asFile(tmp, "directory.json", opts.directory));
      if (opts.threshold !== undefined) args.push("--threshold", String(opts.threshold));
      if (opts.minWitnesses !== undefined) args.push("--min-witnesses", String(opts.minWitnesses));
      const r = await this.run(args);
      if (![0, 10, 20, 30].includes(r.code)) throw usage("verify", r);
      const out = JSON.parse(r.stdout) as Record<string, unknown>;
      const verdict = out.verdict as Verdict;
      if (EXIT_CODES[verdict] !== r.code) {
        throw new WitnessLogCLIError(`verdict ${verdict} does not match exit code ${r.code}`, r.code, r.stderr);
      }
      return {
        verdict,
        exitCode: r.code,
        ok: verdict === "WITNESSED",
        identityPubkey: String(out.identity_pubkey ?? ""),
        identityPinned: Boolean(out.identity_pinned),
        directoryPinned: Boolean(out.directory_pinned),
        report: (out.report ?? {}) as Record<string, unknown>,
        warnings: r.stderr.split("\n").filter((l) => l.trim() !== ""),
      };
    });
  }

  /** Two copies of one log: honest growth (exit 0) or equivocation / tampering (exit 30). */
  async diff(a: DossierInput, b: DossierInput): Promise<DiffResult> {
    return withTemp(async (tmp) => {
      const r = await this.run(["diff", await asFile(tmp, "a.json", a), await asFile(tmp, "b.json", b)]);
      if (r.code !== 0 && r.code !== 30) throw usage("diff", r);
      return { exitCode: r.code, consistent: r.code === 0, output: r.stdout };
    });
  }

  /** Two different agents' logs: do their handoff / authorization leaves bind? */
  async bind(a: DossierInput, b: DossierInput): Promise<BindResult> {
    return withTemp(async (tmp) => {
      const r = await this.run(["bind", await asFile(tmp, "a.json", a), await asFile(tmp, "b.json", b), "--json"]);
      if (![0, 10, 30].includes(r.code)) throw usage("bind", r);
      const out = JSON.parse(r.stdout) as { bound?: unknown[]; failed?: unknown[] };
      return {
        exitCode: r.code,
        bound: (out.bound ?? []) as Array<Record<string, unknown>>,
        failed: (out.failed ?? []) as Array<Record<string, unknown>>,
      };
    });
  }

  /** `witness submit`: get a journal's head cosigned by the witnesses in a directory. */
  async submit(journal: string, opts: SubmitOptions): Promise<SubmitResult> {
    return withTemp(async (tmp) => {
      const out = opts.out ?? join(tmp, "dossier.json");
      const args = ["witness", "submit", journal, "--directory", await asFile(tmp, "directory.json", opts.directory), "--out", out];
      if (opts.state !== undefined) args.push("--state", opts.state);
      if (opts.min !== undefined) args.push("--min", String(opts.min));
      const r = await this.run(args);
      if (r.code === 2) throw usage("witness submit", r);
      const m = /^(\d+)\/\d+ witnesses cosigned/m.exec(r.stderr);
      let dossier: Record<string, unknown> | null = null;
      try {
        dossier = JSON.parse(await readFile(out, "utf8")) as Record<string, unknown>;
      } catch {
        dossier = null;
      }
      return { exitCode: r.code, cosigned: m ? Number(m[1]) : 0, dossier, stderr: r.stderr };
    });
  }

  /** `witness-log --version`, e.g. "0.3.5". */
  async version(): Promise<string> {
    const r = await this.run(["--version"]);
    return r.stdout.trim().replace(/^witness-log\s+/, "");
  }
}

function usage(cmd: string, r: RunResult): WitnessLogCLIError {
  const msg = r.stderr.trim() || r.stdout.trim() || `exit ${r.code}`;
  return new WitnessLogCLIError(`witness-log ${cmd}: ${msg}`, r.code, r.stderr);
}

async function withTemp<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), "witness-log-"));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function asFile(dir: string, name: string, v: string | object): Promise<string> {
  if (typeof v === "string") return v;
  const p = join(dir, name);
  await writeFile(p, JSON.stringify(v), { mode: 0o600 });
  return p;
}
