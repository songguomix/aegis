import { describe, it, expect, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  buildSeatbeltProfile,
  runInSandbox,
  extractInSandbox,
  cleanupSandbox,
  readZipEntryNames,
} from "../services/sandbox.js";

const roots: string[] = [];

afterAll(() => {
  for (const r of roots) cleanupSandbox(r);
});

describe("security sandbox", () => {
  it("profile denies network and secrets paths", () => {
    const p = buildSeatbeltProfile("/tmp/aegis-sandbox-test");
    expect(p).toContain("(deny default)");
    expect(p).toContain("(deny network*)");
    expect(p).toContain("/.ssh");
    expect(p).toContain("aegis-sandbox-test");
  });

  it("runs argv in sandbox and captures stdout", async () => {
    const r = await runInSandbox(["/bin/echo", "aegis-ok"]);
    roots.push(r.sandboxRoot);
    if (r.mode === "restricted") {
      // No kernel isolation here: execution must be refused, not faked.
      expect(r.ok).toBe(false);
      expect(r.error).toBe("no_os_sandbox");
      expect(r.isolated).toBe(false);
      return;
    }
    expect(r.stdout).toContain("aegis-ok");
    expect(r.exitCode).toBe(0);
    expect(["seatbelt", "bwrap", "restricted"]).toContain(r.mode);
    // env should not leak secrets even if present
    const r2 = await runInSandbox(["/usr/bin/env"]);
    roots.push(r2.sandboxRoot);
    expect(r2.stdout.toLowerCase()).not.toContain("aegis_secret_token");
  });

  it("refuses to execute without OS isolation and explains why", async () => {
    const realPlatform = process.platform;
    const realExists = fs.existsSync;
    try {
      // Simulate a platform without seatbelt/bwrap (Windows).
      Object.defineProperty(process, "platform", { value: "win32", configurable: true });
      (fs as unknown as { existsSync: (p: string) => boolean }).existsSync = (p: string) =>
        realExists(p) && !p.includes("sandbox-exec") && !p.includes("bwrap");
      const r = await runInSandbox(["/bin/sh", "-c", "echo should-not-run"]);
      expect(r.ok).toBe(false);
      expect(r.error).toBe("no_os_sandbox");
      expect(r.isolated).toBe(false);
      expect(r.degraded).toBe(true);
      expect(r.stdout).toBe("");
      // The reason must tell the model what to do instead.
      expect(r.reason).toContain("analyze_installer");
      expect(r.reason).toContain("extract_in_sandbox");
      expect(r.reason).toContain("Do not retry");
    } finally {
      (fs as unknown as { existsSync: (p: string) => boolean }).existsSync = realExists;
      Object.defineProperty(process, "platform", { value: realPlatform, configurable: true });
    }
  });

  it("unisolated opt-in only allows trusted read-only tools inside the sandbox", async () => {
    const realPlatform = process.platform;
    const realExists = fs.existsSync;
    const artifact = path.join(os.tmpdir(), `aegis-target-${Date.now()}.bin`);
    fs.writeFileSync(artifact, "AEGIS-MARKER-PAYLOAD\n");
    try {
      Object.defineProperty(process, "platform", { value: "win32", configurable: true });
      (fs as unknown as { existsSync: (p: string) => boolean }).existsSync = (p: string) =>
        realExists(p) && !p.includes("sandbox-exec") && !p.includes("bwrap");

      // Not in the allowlist → refused with a reason.
      const shell = await runInSandbox(["/bin/sh", "-c", "echo hi"], { allowUnisolated: true });
      expect(shell.ok).toBe(false);
      expect(shell.error).toBe("unisolated_not_allowed");
      expect(shell.reason).toContain("allowlist");

      // Reading outside the sandbox → refused.
      const escape = await runInSandbox(["/usr/bin/strings", "/etc/passwd"], {
        allowUnisolated: true,
      });
      expect(escape.ok).toBe(false);
      expect(escape.reason).toContain("outside the sandbox");

      const home = await runInSandbox(["/usr/bin/strings", "~/.ssh/id_rsa"], {
        allowUnisolated: true,
      });
      expect(home.ok).toBe(false);

      // Trusted tool on a staged target → allowed, and the artifact is readable.
      const ok = await runInSandbox(["/usr/bin/strings", artifact], {
        targetPath: artifact,
        allowUnisolated: true,
      });
      if (ok.mode === "restricted" && ok.error === "unisolated_not_allowed") {
        // The tool is not installed on this host — the allowlist decision is
        // what matters here.
        expect(ok.reason).toBeTruthy();
      } else {
        expect(ok.ok).toBe(true);
        expect(ok.stdout).toContain("AEGIS-MARKER-PAYLOAD");
        expect(ok.isolated).toBe(false);
      }
      if (ok.sandboxRoot) cleanupSandbox(ok.sandboxRoot);
    } finally {
      (fs as unknown as { existsSync: (p: string) => boolean }).existsSync = realExists;
      Object.defineProperty(process, "platform", { value: realPlatform, configurable: true });
      fs.rmSync(artifact, { force: true });
    }
  });

  it("stages the target file into the sandbox so it can be inspected", async () => {
    const artifact = path.join(os.tmpdir(), `aegis-stage-${Date.now()}.bin`);
    fs.writeFileSync(artifact, "STAGED-MARKER\n");
    const r = await runInSandbox(["/usr/bin/strings", artifact], { targetPath: artifact });
    roots.push(r.sandboxRoot);
    if (r.mode !== "restricted") {
      expect(r.ok).toBe(true);
      expect(r.stdout).toContain("STAGED-MARKER");
      // The sandbox root must be the resolved path, otherwise Seatbelt
      // cannot match it and the sandbox cannot read its own files.
      expect(r.sandboxRoot).toBe(fs.realpathSync(r.sandboxRoot));
    }
    fs.rmSync(artifact, { force: true });
  });

  it("rejects invalid argv", async () => {
    const r = await runInSandbox([]);
    expect(r.ok).toBe(false);
    expect(r.error).toBe("invalid_argv");
  });

  it("blocks path traversal extract", async () => {
    const zip = path.join(os.tmpdir(), `aegis-trav-${Date.now()}.zip`);
    const name = Buffer.from("../evil.txt");
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0);
    header.writeUInt16LE(name.length, 26);
    fs.writeFileSync(zip, Buffer.concat([header, name, Buffer.from("x")]));
    const r = await extractInSandbox(zip);
    expect(r.ok).toBe(false);
    expect(r.error).toBe("path_traversal");
    if (r.sandboxRoot) cleanupSandbox(path.dirname(r.sandboxRoot));
    fs.unlinkSync(zip);
  });

  it("extracts clean zip members", async () => {
    const zip = path.join(os.tmpdir(), `aegis-ok-${Date.now()}.zip`);
    const { execFileSync } = await import("node:child_process");
    const srcFile = path.join(os.tmpdir(), `aegis-zsrc-${Date.now()}.txt`);
    fs.writeFileSync(srcFile, "hello");
    execFileSync("/usr/bin/python3", [
      "-c",
      "import sys,zipfile; z=zipfile.ZipFile(sys.argv[1],'w'); z.write(sys.argv[2],'readme.txt'); z.close()",
      zip,
      srcFile,
    ]);
    expect(fs.existsSync(zip)).toBe(true);
    const r = await extractInSandbox(zip);
    expect(r.ok).toBe(true);
    expect(r.members.some((m) => m.includes("readme"))).toBe(true);
    if (r.sandboxRoot) cleanupSandbox(path.dirname(r.sandboxRoot));
    fs.unlinkSync(zip);
    fs.unlinkSync(srcFile);
  });

  it("reads zip member names from the central directory", async () => {
    const zip = path.join(os.tmpdir(), `aegis-cd-${Date.now()}.zip`);
    const { execFileSync } = await import("node:child_process");
    const srcFile = path.join(os.tmpdir(), `aegis-cdsrc-${Date.now()}.txt`);
    fs.writeFileSync(srcFile, "hello");
    execFileSync("/usr/bin/python3", [
      "-c",
      "import sys,zipfile; z=zipfile.ZipFile(sys.argv[1],'w'); z.write(sys.argv[2],'a/b.txt'); z.write(sys.argv[2],'c.exe'); z.close()",
      zip,
      srcFile,
    ]);
    const names = readZipEntryNames(zip);
    expect(names).not.toBeNull();
    expect(names).toContain("a/b.txt");
    expect(names).toContain("c.exe");
    fs.unlinkSync(zip);
    fs.unlinkSync(srcFile);
  });

  it("returns null for non-zip files", () => {
    const p = path.join(os.tmpdir(), `aegis-notzip-${Date.now()}.bin`);
    fs.writeFileSync(p, Buffer.alloc(1024, 7));
    expect(readZipEntryNames(p)).toBeNull();
    fs.unlinkSync(p);
  });
});
