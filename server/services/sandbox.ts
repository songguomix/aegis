import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawn } from "node:child_process";

export interface SandboxRunResult {
  ok: boolean;
  degraded: boolean;
  mode: "seatbelt" | "fallback";
  sandboxRoot: string;
  argv: string[];
  exitCode: number | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
  durationMs: number;
  error?: string;
}

export interface SandboxExtractResult {
  ok: boolean;
  degraded: boolean;
  mode: "seatbelt" | "fallback";
  sandboxRoot: string;
  members: string[];
  riskyMembers: string[];
  extractedCount: number;
  error?: string;
}

const MAX_OUTPUT = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 5000;

function hasSandboxExec(): boolean {
  try {
    return fs.existsSync("/usr/bin/sandbox-exec");
  } catch {
    return false;
  }
}

function makeSandboxRoot(): string {
  const base = path.join(os.tmpdir(), `aegis-sandbox-${crypto.randomUUID().slice(0, 8)}`);
  fs.mkdirSync(base, { recursive: true, mode: 0o700 });
  return base;
}

/** Strict Seatbelt profile: deny default; write only sandbox root; no network. */
export function buildSeatbeltProfile(sandboxRoot: string): string {
  const home = os.homedir();
  const abs = sandboxRoot.replace(/\\/g, "/");
  return `
(version 1)
(deny default)
(import "system.sb")

; allow reading system binaries/libs
(allow file-read*
  (subpath "/usr")
  (subpath "/bin")
  (subpath "/sbin")
  (subpath "/lib")
  (subpath "/System")
  (subpath "/Library")
  (subpath "/private/var/db")
  (subpath "/private/var/tmp")
  (subpath "/dev")
  (literal "/dev/null")
  (literal "/dev/urandom")
  (literal "/dev/random")
)

; explicit deny for secrets
(deny file-read*
  (subpath "${home}/.ssh")
  (subpath "${home}/.aws")
  (subpath "${home}/.gnupg")
  (subpath "${home}/.config")
  (subpath "${home}/.kube")
  (regex #"${home}/Library/Keychains")
)

; sandbox workspace: read/write only here
(allow file-write*
  (subpath "${abs}")
  (subpath "/tmp/aegis-sandbox")
)
(allow file-read*
  (subpath "${abs}")
  (subpath "/tmp/aegis-sandbox")
  (literal "${abs}")
)
(allow process-exec*)
(allow process-fork)
(allow process-info*)
(deny network*)
(deny network-outbound)
(deny network-inbound)
(deny ipc*)
(allow sysctl-read)
`.trim();
}

function sanitizeEnv(extra?: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {
    PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
    HOME: os.homedir(),
    TMPDIR: os.tmpdir(),
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
  };
  const deny = /TOKEN|KEY|SECRET|PASSWORD|PASSPHRASE|CREDENTIAL|APIKEY|AUTH/i;
  for (const [k, v] of Object.entries(extra ?? process.env)) {
    if (v == null) continue;
    if (deny.test(k)) continue;
    if (k === "NODE_OPTIONS" || k === "PYTHONSTARTUP") continue;
    out[k] = v;
  }
  return out;
}

function truncate(s: string): { text: string; truncated: boolean } {
  if (s.length <= MAX_OUTPUT) return { text: s, truncated: false };
  return { text: s.slice(0, MAX_OUTPUT) + "\n…[truncated]", truncated: true };
}

export async function runInSandbox(
  argv: string[],
  opts: {
    cwd?: string;
    timeoutMs?: number;
    stdin?: string;
    keepRoot?: boolean;
  } = {},
): Promise<SandboxRunResult> {
  const sandboxRoot = opts.cwd ?? makeSandboxRoot();
  fs.mkdirSync(sandboxRoot, { recursive: true, mode: 0o700 });
  const timeoutMs = Math.min(Math.max(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS, 500), 60_000);
  const started = Date.now();

  if (!Array.isArray(argv) || !argv.length || argv.some((a) => typeof a !== "string")) {
    return {
      ok: false,
      degraded: true,
      mode: "fallback",
      sandboxRoot,
      argv: [],
      exitCode: null,
      stdout: "",
      stderr: "",
      truncated: false,
      durationMs: 0,
      error: "invalid_argv",
    };
  }

  const seatbelt = hasSandboxExec();
  const profilePath = path.join(sandboxRoot, ".aegis.sb");
  if (seatbelt) {
    fs.writeFileSync(profilePath, buildSeatbeltProfile(sandboxRoot), "utf8");
  }

  const cmd = seatbelt ? "/usr/bin/sandbox-exec" : argv[0];
  const args = seatbelt ? ["-f", profilePath, ...argv] : argv.slice(1);

  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      cwd: sandboxRoot,
      env: sanitizeEnv(),
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let truncated = false;
    const timer = setTimeout(() => {
      truncated = true;
      child.kill("SIGKILL");
    }, timeoutMs);

    child.stdout.on("data", (d) => {
      stdout += d.toString();
      if (stdout.length > MAX_OUTPUT * 2) {
        truncated = true;
        child.kill("SIGKILL");
      }
    });
    child.stderr.on("data", (d) => {
      stderr += d.toString();
      if (stderr.length > MAX_OUTPUT * 2) {
        truncated = true;
        child.kill("SIGKILL");
      }
    });
    if (opts.stdin) child.stdin.write(opts.stdin);
    child.stdin.end();

    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({
        ok: false,
        degraded: !seatbelt,
        mode: seatbelt ? "seatbelt" : "fallback",
        sandboxRoot,
        argv,
        exitCode: null,
        stdout: "",
        stderr: err.message,
        truncated: false,
        durationMs: Date.now() - started,
        error: "spawn_failed",
      });
    });

    child.on("close", (code) => {
      clearTimeout(timer);
      const o = truncate(stdout);
      const e = truncate(stderr);
      resolve({
        ok: code === 0,
        degraded: !seatbelt,
        mode: seatbelt ? "seatbelt" : "fallback",
        sandboxRoot,
        argv,
        exitCode: code,
        stdout: o.text,
        stderr: e.text,
        truncated: truncated || o.truncated || e.truncated,
        durationMs: Date.now() - started,
      });
    });
  });
}

/** Zip extract with path-traversal guard; uses Python zipfile inside sandbox when available. */
export async function extractInSandbox(
  archivePath: string,
  opts: { timeoutMs?: number } = {},
): Promise<SandboxExtractResult> {
  const abs = path.resolve(archivePath);
  if (!fs.existsSync(abs)) {
    return {
      ok: false,
      degraded: true,
      mode: "fallback",
      sandboxRoot: "",
      members: [],
      riskyMembers: [],
      extractedCount: 0,
      error: "archive_not_found",
    };
  }
  const sandboxRoot = makeSandboxRoot();
  const dest = path.join(sandboxRoot, "extract");
  fs.mkdirSync(dest, { recursive: true, mode: 0o700 });

  // Path traversal check on names first (defensive)
  const members: string[] = [];
  const risky: string[] = [];
  try {
    const buf = fs.readFileSync(abs);
    let i = 0;
    while (i + 30 < buf.length && members.length < 200) {
      if (buf[i] === 0x50 && buf[i + 1] === 0x4b && buf[i + 2] === 0x03 && buf[i + 3] === 0x04) {
        const nameLen = buf.readUInt16LE(i + 26);
        const name = buf.slice(i + 30, i + 30 + nameLen).toString("utf8");
        if (name) {
          if (name.includes("..") || name.startsWith("/") || name.includes("\\")) {
            return {
              ok: false,
              degraded: false,
              mode: "fallback",
              sandboxRoot,
              members,
              riskyMembers: risky,
              extractedCount: 0,
              error: "path_traversal",
            };
          }
          members.push(name);
          if (/\.(exe|dll|bat|cmd|ps1|vbs|js|jar|sh|msi|scr)$/i.test(name)) {
            risky.push(name);
          }
        }
        i += 30 + nameLen;
      } else {
        i++;
      }
    }
  } catch {
    /* non-zip */
  }

  const script = `
import zipfile, sys, os
src, dest = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(src) as z:
    for n in z.namelist():
        if n.startswith('/') or '..' in n.split('/'):
            raise SystemExit('path_traversal')
        z.extract(n, dest)
print(len(z.namelist()))
`;
  const result = await runInSandbox(
    ["/usr/bin/python3", "-c", script, abs, dest],
    { timeoutMs: opts.timeoutMs ?? 8000 },
  );

  return {
    ok: result.ok,
    degraded: result.degraded,
    mode: result.mode,
    sandboxRoot: dest,
    members: members.length ? members : result.stdout.trim().split("\n").filter(Boolean),
    riskyMembers: risky,
    extractedCount: Number(result.stdout.trim().split("\n").filter(Boolean).length) || members.length,
    error: result.error ?? (result.ok ? undefined : result.stderr.slice(0, 200) || "extract_failed"),
  };
}

export function cleanupSandbox(root: string): void {
  try {
    if (root && root.includes("aegis-sandbox")) {
      fs.rmSync(root, { recursive: true, force: true });
    }
  } catch {
    /* ignore */
  }
}
