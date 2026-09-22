import { describe, it, expect, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  buildSeatbeltProfile,
  runInSandbox,
  extractInSandbox,
  cleanupSandbox,
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
    expect(r.stdout).toContain("aegis-ok");
    expect(r.exitCode).toBe(0);
    expect(["seatbelt", "fallback"]).toContain(r.mode);
    // env should not leak secrets even if present
    const r2 = await runInSandbox(["/usr/bin/env"]);
    roots.push(r2.sandboxRoot);
    expect(r2.stdout.toLowerCase()).not.toContain("aegis_secret_token");
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
});
