import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { extractZipWithNode } from "./zipExtract.js";

export type SandboxMode = "seatbelt" | "bwrap" | "restricted";

/** Human/agent readable explanation when no OS-level isolation is available. */
export const RESTRICTED_MODE_WARNING =
  "No OS-level sandbox on this platform (mode=restricted): the command ran with the " +
  "current user's full privileges. Network access, reads of ~/.ssh, ~/.aws, keychains " +
  "and writes outside the sandbox root are NOT blocked. Only run trusted inspection " +
  "tools here (file, ls, strings) — never an untrusted binary.";

/**
 * Why execution was refused and what to do instead.
 * Written for the agent: it must be able to reason about the next step on its
 * own instead of retrying the same command.
 */
export const SANDBOX_REFUSAL_REASON =
  "Refused to execute: this platform has no OS-level sandbox (mode=restricted — " +
  "Windows, or Linux without bubblewrap). Without kernel isolation the command would " +
  "run with the user's full privileges: network access, reads of ~/.ssh, ~/.aws and " +
  "keychains, and writes outside the sandbox root would NOT be blocked, so an " +
  "untrusted payload could compromise the machine. Do not retry with a weaker or " +
  "equivalent command. Use these instead — none of them execute the artifact: " +
  "(1) analyze_installer(path): static analysis — hashes, file type, entropy, embedded " +
  "URLs/strings, archive members, risk flags; " +
  "(2) extract_in_sandbox(path): unpack a zip with Node into a temp dir, traversal-safe, " +
  "no execution; " +
  "(3) check_file_hash(hash) or upload_scan_file(path): VirusTotal verdict for the file; " +
  "(4) ask the user to inspect the artifact manually and report back. " +
  "Real isolation can be enabled on Linux by installing bubblewrap (bwrap); on macOS " +
  "sandbox-exec is used automatically.";

export interface SandboxRunResult {
  ok: boolean;
  degraded: boolean;
  /** True only when the OS actually enforces isolation (seatbelt / bwrap). */
  isolated: boolean;
  /** Present when isolated=false — explains what is not being enforced. */
  warning?: string;
  /** Present when the command was refused — explains why and what to do instead. */
  reason?: string;
  mode: SandboxMode;
  platform: NodeJS.Platform;
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
  /** True only when the OS actually enforces isolation (seatbelt / bwrap). */
  isolated: boolean;
  warning?: string;
  mode: SandboxMode;
  platform: NodeJS.Platform;
  sandboxRoot: string;
  members: string[];
  riskyMembers: string[];
  /** Entries that were refused during extraction (traversal, symlink, limits). */
  refusedMembers?: string[];
  extractedCount: number;
  error?: string;
}

const MAX_OUTPUT = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 5000;

export function detectSandboxBackend(): SandboxMode {
  if (process.platform === "darwin" && fs.existsSync("/usr/bin/sandbox-exec")) {
    return "seatbelt";
  }
  for (const p of ["/usr/bin/bwrap", "/bin/bwrap"]) {
    if (fs.existsSync(p)) return "bwrap";
  }
  return "restricted";
}

function hasSandboxExec(): boolean {
  return detectSandboxBackend() === "seatbelt";
}

function findBwrap(): string | null {
  for (const p of ["/usr/bin/bwrap", "/bin/bwrap"]) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

function makeSandboxRoot(): string {
  const base = path.join(os.tmpdir(), `aegis-sandbox-${crypto.randomUUID().slice(0, 8)}`);
  fs.mkdirSync(base, { recursive: true, mode: 0o700 });
  return base;
}

/**
 * Resolve the sandbox root to its real path.
 * On macOS os.tmpdir() is /var/folders/... while the real path is
 * /private/var/folders/... — Seatbelt matches on resolved paths, so a profile
 * built from the symlinked path would not allow the sandbox's own directory.
 */
function realSandboxRoot(root: string): string {
  try {
    return fs.realpathSync(root);
  } catch {
    return root;
  }
}

/** Strict Seatbelt profile: deny default; write only sandbox root; no network. */
export function buildSeatbeltProfile(sandboxRoot: string): string {
  const home = os.homedir();
  const abs = realSandboxRoot(sandboxRoot).replace(/\\/g, "/");
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
  (subpath "/private/var/select")
  (subpath "/var/select")
  (subpath "/Library/Developer")
  (subpath "/Applications/Xcode.app")
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

/**
 * Trusted read-only inspection tools.
 *
 * Used only in restricted mode (no kernel isolation) when the caller
 * explicitly opts in: these binaries cannot execute the inspected artifact,
 * cannot write files and have no network capability. Everything that could
 * run arbitrary code (sh, python, node, perl, env, xargs, …) is excluded on
 * purpose.
 */
export const TRUSTED_INSPECT_TOOLS = new Set([
  "file",
  "ls",
  "stat",
  "strings",
  "xxd",
  "hexdump",
  "od",
  "wc",
  "head",
  "tail",
  "shasum",
  "sha256sum",
  "sha1sum",
  "md5",
  "md5sum",
  "cksum",
  "cmp",
  "diff",
  "grep",
  "egrep",
  "fgrep",
  "codesign",
  "otool",
  "plutil",
  "nm",
  "objdump",
  "readelf",
  "pdfinfo",
  "findstr",
]);

/** Directories the trusted tools may be resolved from (fixed PATH). */
const TOOL_DIRS = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

export interface SandboxRunOptions {
  cwd?: string;
  timeoutMs?: number;
  stdin?: string;
  keepRoot?: boolean;
  /**
   * Artifact to inspect. It is copied into the sandbox root and every argv
   * reference to it is rewritten to the copy, so a trusted tool can read it
   * without gaining access to the rest of the filesystem.
   */
  targetPath?: string;
  /**
   * Opt-in for platforms without kernel isolation: allow running a trusted
   * read-only inspection tool without OS sandboxing. Without this flag the
   * call is refused (see SANDBOX_REFUSAL_REASON).
   */
  allowUnisolated?: boolean;
}

/**
 * Validate an argv for the unisolated (restricted) opt-in mode.
 *
 * Rules:
 *  - the executable must be a trusted read-only inspection tool, resolved from
 *    a fixed set of system directories (never from the caller's PATH)
 *  - no argument may point outside the sandbox: absolute paths, `~` and `..`
 *    are rejected, so relative paths resolve inside the sandbox root
 */
export function checkUnisolatedArgv(
  argv: string[],
  sandboxRoot?: string,
): {
  ok: boolean;
  reason?: string;
  resolvedPath?: string;
} {
  const exe = argv[0] ?? "";
  const base = path.basename(exe);
  if (!TRUSTED_INSPECT_TOOLS.has(base)) {
    return {
      ok: false,
      reason:
        `Refused: "${base}" is not in the trusted read-only inspection allowlist ` +
        `(${Array.from(TRUSTED_INSPECT_TOOLS).join(", ")}). ` +
        "Without kernel isolation only these tools may run — they cannot execute the " +
        "artifact, write files or reach the network. Use analyze_installer, " +
        "extract_in_sandbox or check_file_hash instead of running the artifact.",
    };
  }
  const resolved = TOOL_DIRS.map((d) => path.join(d, base)).find((p) => fs.existsSync(p));
  if (!resolved) {
    return {
      ok: false,
      reason: `Refused: "${base}" was not found in ${TOOL_DIRS.join(", ")}.`,
    };
  }

  const root = sandboxRoot ? path.resolve(sandboxRoot) : null;
  const insideSandbox = (p: string): boolean => {
    if (!root) return false;
    const abs = path.resolve(p);
    return abs === root || abs.startsWith(root + path.sep);
  };

  for (const arg of argv.slice(1)) {
    if (arg.startsWith("-")) continue; // flags are fine
    if (arg.startsWith("~")) {
      return {
        ok: false,
        reason:
          `Refused: argument "${arg}" points outside the sandbox (home expansion). ` +
          "Without kernel isolation only paths inside the sandbox root may be read. " +
          "Pass the artifact via the `target` option — Aegis copies it into the " +
          "sandbox and rewrites the argument for you.",
      };
    }
    if (arg.split(/[/\\]/).includes("..")) {
      return {
        ok: false,
        reason:
          `Refused: argument "${arg}" contains a parent-directory hop. ` +
          "Without kernel isolation only paths inside the sandbox root may be read. " +
          "Pass the artifact via the `target` option — Aegis copies it into the " +
          "sandbox and rewrites the argument for you.",
      };
    }
    if (path.isAbsolute(arg) && !insideSandbox(arg)) {
      return {
        ok: false,
        reason:
          `Refused: argument "${arg}" points outside the sandbox. ` +
          "Without kernel isolation only paths inside the sandbox root may be read. " +
          "Pass the artifact via the `target` option — Aegis copies it into the " +
          "sandbox and rewrites the argument for you.",
      };
    }
  }
  return { ok: true, resolvedPath: resolved };
}

export async function runInSandbox(
  argv: string[],
  opts: SandboxRunOptions = {},
): Promise<SandboxRunResult> {
  const sandboxRoot = realSandboxRoot(opts.cwd ?? makeSandboxRoot());
  fs.mkdirSync(sandboxRoot, { recursive: true, mode: 0o700 });
  const timeoutMs = Math.min(Math.max(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS, 500), 60_000);
  const started = Date.now();

  if (!Array.isArray(argv) || !argv.length || argv.some((a) => typeof a !== "string")) {
    return {
      ok: false,
      degraded: true,
      isolated: false,
      warning: RESTRICTED_MODE_WARNING,
      mode: "restricted",
      platform: process.platform,
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

  // Stage the artifact: copy it into the sandbox root and rewrite argv so the
  // tool reads the copy. Without this the sandbox cannot even see the file
  // under inspection (it lives outside the allowed paths by design).
  let stagedTarget: string | null = null;
  if (opts.targetPath) {
    const src = path.resolve(opts.targetPath);
    if (!fs.existsSync(src) || !fs.statSync(src).isFile()) {
      return {
        ok: false,
        degraded: true,
        isolated: false,
        warning: RESTRICTED_MODE_WARNING,
        mode: "restricted",
        platform: process.platform,
        sandboxRoot,
        argv,
        exitCode: null,
        stdout: "",
        stderr: "",
        truncated: false,
        durationMs: 0,
        error: "target_not_found",
      };
    }
    const dest = path.join(sandboxRoot, path.basename(src));
    try {
      fs.copyFileSync(src, dest);
      fs.chmodSync(dest, 0o600);
      stagedTarget = dest;
    } catch {
      return {
        ok: false,
        degraded: true,
        isolated: false,
        warning: RESTRICTED_MODE_WARNING,
        mode: "restricted",
        platform: process.platform,
        sandboxRoot,
        argv,
        exitCode: null,
        stdout: "",
        stderr: "",
        truncated: false,
        durationMs: 0,
        error: "target_copy_failed",
      };
    }
  }

  const effectiveArgv = stagedTarget
    ? argv.map((a) => (a === opts.targetPath || a === path.resolve(opts.targetPath!) ? stagedTarget! : a))
    : argv;

  const backend = detectSandboxBackend();
  let unisolatedTool: string | null = null;
  if (backend === "restricted") {
    if (!opts.allowUnisolated) {
      // No kernel isolation available: refuse instead of pretending. The
      // reason is handed to the caller (agent) so it can pick a non-executing
      // route.
      return {
        ok: false,
        degraded: true,
        isolated: false,
        warning: RESTRICTED_MODE_WARNING,
        reason: SANDBOX_REFUSAL_REASON,
        mode: backend,
        platform: process.platform,
        sandboxRoot,
        argv: effectiveArgv,
        exitCode: null,
        stdout: "",
        stderr: "",
        truncated: false,
        durationMs: 0,
        error: "no_os_sandbox",
      };
    }

    // Opt-in path: only trusted read-only inspection tools, and only
    // arguments that stay inside the sandbox root.
    const verdict = checkUnisolatedArgv(effectiveArgv, sandboxRoot);
    if (!verdict.ok) {
      return {
        ok: false,
        degraded: true,
        isolated: false,
        warning: RESTRICTED_MODE_WARNING,
        reason: verdict.reason,
        mode: backend,
        platform: process.platform,
        sandboxRoot,
        argv: effectiveArgv,
        exitCode: null,
        stdout: "",
        stderr: "",
        truncated: false,
        durationMs: 0,
        error: "unisolated_not_allowed",
      };
    }
    unisolatedTool = verdict.resolvedPath ?? null;
  }

  const profilePath = path.join(sandboxRoot, ".aegis.sb");
  if (backend === "seatbelt") {
    fs.writeFileSync(profilePath, buildSeatbeltProfile(sandboxRoot), "utf8");
  }

  let cmd: string;
  let args: string[];
  if (backend === "seatbelt") {
    cmd = "/usr/bin/sandbox-exec";
    args = ["-f", profilePath, ...effectiveArgv];
  } else if (backend === "bwrap") {
    const bwrap = findBwrap()!;
    cmd = bwrap;
    args = [
      "--unshare-all",
      "--unshare-net",
      "--die-with-parent",
      "--ro-bind",
      "/usr",
      "/usr",
      "--ro-bind",
      "/bin",
      "/bin",
      "--ro-bind",
      "/lib",
      "/lib",
      "--ro-bind",
      "/lib64",
      "/lib64",
      "--proc",
      "/proc",
      "--dev",
      "/dev",
      "--bind",
      sandboxRoot,
      sandboxRoot,
      ...effectiveArgv,
    ];
  } else {
    // Restricted (opted in): run the trusted tool directly — no isolation,
    // but the tool list and the argument rules keep it read-only and local.
    cmd = unisolatedTool ?? effectiveArgv[0];
    args = effectiveArgv.slice(1);
  }

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
        degraded: backend === "restricted",
        isolated: backend !== "restricted",
        warning: backend === "restricted" ? RESTRICTED_MODE_WARNING : undefined,
        mode: backend,
        platform: process.platform,
        sandboxRoot,
        argv: effectiveArgv,
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
        degraded: backend === "restricted",
        isolated: backend !== "restricted",
        warning: backend === "restricted" ? RESTRICTED_MODE_WARNING : undefined,
        mode: backend,
        platform: process.platform,
        sandboxRoot,
        argv: effectiveArgv,
        exitCode: code,
        stdout: o.text,
        stderr: e.text,
        truncated: truncated || o.truncated || e.truncated,
        durationMs: Date.now() - started,
      });
    });
  });
}

/**
 * List every member name of a zip archive by parsing its central directory.
 * Memory stays bounded (only the directory is read), unlike scanning the whole
 * archive. Returns null when the archive is not a readable zip.
 */
export function readZipEntryNames(filePath: string): string[] | null {
  let fd: number | null = null;
  try {
    const st = fs.statSync(filePath);
    if (!st.isFile() || st.size < 22) return null;
    fd = fs.openSync(filePath, "r");

    // Locate the End Of Central Directory record (last 64KB + 22 bytes).
    const tailLen = Math.min(st.size, 65_557 + 22);
    const tail = Buffer.alloc(tailLen);
    fs.readSync(fd, tail, 0, tailLen, st.size - tailLen);
    let eocd = -1;
    for (let i = tail.length - 22; i >= 0; i--) {
      if (tail.readUInt32LE(i) === 0x06054b50) {
        eocd = i;
        break;
      }
    }
    if (eocd < 0) return null;

    const entryCount = tail.readUInt16LE(eocd + 10);
    const cdSize = tail.readUInt32LE(eocd + 12);
    const cdOffset = tail.readUInt32LE(eocd + 16);
    // zip64 sentinel — fall back to the naive scanner.
    if (cdOffset === 0xffffffff || cdSize === 0xffffffff) return null;
    if (cdOffset > st.size || cdSize > st.size) return null;

    const cd = Buffer.alloc(cdSize);
    fs.readSync(fd, cd, 0, cdSize, cdOffset);

    const names: string[] = [];
    let p = 0;
    for (let n = 0; n < entryCount && p + 46 <= cd.length; n++) {
      if (cd.readUInt32LE(p) !== 0x02014b50) break;
      const nameLen = cd.readUInt16LE(p + 28);
      const extraLen = cd.readUInt16LE(p + 30);
      const commentLen = cd.readUInt16LE(p + 32);
      const name = cd.subarray(p + 46, p + 46 + nameLen).toString("utf8");
      if (name) names.push(name);
      p += 46 + nameLen + extraLen + commentLen;
    }
    return names.length ? names : null;
  } catch {
    return null;
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {
        /* ignore */
      }
    }
  }
}

/** Naive local-header scan, used when the central directory cannot be read. */
function scanZipLocalHeaders(abs: string, limit: number): string[] {
  const names: string[] = [];
  try {
    const fd = fs.openSync(abs, "r");
    try {
      const chunkSize = 1024 * 1024;
      let pos = 0;
      let carry = Buffer.alloc(0);
      const seen = new Set<string>();
      while (names.length < limit) {
        const chunk = Buffer.alloc(chunkSize);
        const read = fs.readSync(fd, chunk, 0, chunkSize, pos);
        if (read <= 0) break;
        const buf = carry.length
          ? Buffer.concat([carry, chunk.subarray(0, read)])
          : chunk.subarray(0, read);
        let i = 0;
        while (i + 30 < buf.length && names.length < limit) {
          if (
            buf[i] === 0x50 &&
            buf[i + 1] === 0x4b &&
            buf[i + 2] === 0x03 &&
            buf[i + 3] === 0x04
          ) {
            const nameLen = buf.readUInt16LE(i + 26);
            const name = buf.subarray(i + 30, i + 30 + nameLen).toString("utf8");
            if (name && !seen.has(name)) {
              seen.add(name);
              names.push(name);
            }
            i += 30 + nameLen;
          } else {
            i++;
          }
        }
        carry = buf.subarray(Math.max(0, buf.length - 70_000));
        pos += read;
      }
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    /* non-zip */
  }
  return names;
}

/** Zip extract with path-traversal guard; Node extraction first, system unzip as fallback. */
export async function extractInSandbox(
  archivePath: string,
  opts: { timeoutMs?: number } = {},
): Promise<SandboxExtractResult> {
  const abs = path.resolve(archivePath);
  if (!fs.existsSync(abs)) {
    return {
      ok: false,
      degraded: true,
      isolated: false,
      warning: RESTRICTED_MODE_WARNING,
      mode: "restricted",
      platform: process.platform,
      sandboxRoot: "",
      members: [],
      riskyMembers: [],
      extractedCount: 0,
      error: "archive_not_found",
    };
  }
  // Path traversal check on names first (defensive)
  const members: string[] = [];
  const risky: string[] = [];
  const allNames = readZipEntryNames(abs) ?? scanZipLocalHeaders(abs, 200);
  for (const name of allNames.slice(0, 200)) {
    if (name.includes("..") || name.startsWith("/") || name.includes("\\")) {
      return {
        ok: false,
        degraded: false,
        isolated: false,
        mode: "restricted" as const,
        platform: process.platform,
        sandboxRoot: "",
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

  const sandboxRoot = makeSandboxRoot();
  const dest = path.join(sandboxRoot, "extract");
  fs.mkdirSync(dest, { recursive: true, mode: 0o700 });

  // Primary path: pure Node extraction. Works on Windows and on Linux hosts
  // without the `unzip` binary, and never shells out.
  const nodeExtract = extractZipWithNode(abs, dest);
  let extractedCount = nodeExtract.extracted;
  let mode: SandboxMode = "restricted";
  let degraded = true;
  let isolated = false;
  let ok = false;
  let error: string | undefined;

  if (nodeExtract.parsed) {
    // The archive was understood: never fall back to the system `unzip` here,
    // otherwise entries we refused (traversal, symlinks) would come back.
    ok = nodeExtract.ok;
    mode = detectSandboxBackend();
    degraded = mode === "restricted";
    isolated = mode !== "restricted";
  } else {
    // Fallback for archives the Node parser could not read (e.g. zip64):
    // system `unzip` *inside* the sandbox. Never on the host — that would
    // extract without isolation and could recreate refused symlinks.
    const localZip = path.join(sandboxRoot, "input.bin");
    fs.copyFileSync(abs, localZip);
    const result = await runInSandbox(
      ["/usr/bin/unzip", "-qq", "-o", localZip, "-d", dest],
      { timeoutMs: opts.timeoutMs ?? 8000, cwd: sandboxRoot },
    );
    try {
      extractedCount = fs.readdirSync(dest, { recursive: true }).length;
    } catch {
      extractedCount = 0;
    }
    mode = result.mode;
    degraded = result.degraded;
    isolated = result.isolated;
    if (!extractedCount) {
      ok = false;
      error =
        result.error === "no_os_sandbox"
          ? `unzip_fallback_unavailable: ${result.reason ?? "no OS sandbox"}`
          : result.stderr.slice(0, 200) || "extract_failed";
    } else {
      ok = true;
    }
  }

  return {
    ok,
    degraded,
    isolated,
    warning: isolated ? undefined : RESTRICTED_MODE_WARNING,
    mode,
    platform: process.platform,
    sandboxRoot: dest,
    members,
    riskyMembers: risky,
    extractedCount,
    refusedMembers: nodeExtract.refused.length ? nodeExtract.refused.slice(0, 20) : undefined,
    error,
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
