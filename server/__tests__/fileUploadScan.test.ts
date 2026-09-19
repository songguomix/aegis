import { describe, it, expect } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanDownloadedFile } from "../services/fileUploadScan.js";
import { DEFAULT_CONFIG, type EngineConfig } from "../types.js";
import { primeVtCache, clearVtCache } from "../services/virustotal.js";

const cfg: EngineConfig = {
  ...DEFAULT_CONFIG,
  vtApiKey: null,
  enableRdap: false,
  maxUploadBytes: 32 * 1024 * 1024,
};

describe("scanDownloadedFile (upload scan wrapper)", () => {
  it("rejects missing path", async () => {
    const r = await scanDownloadedFile("/tmp/aegis-does-not-exist-xyz", cfg);
    expect(r.decision).toBe("block");
    expect(r.reasons[0].code).toBe("file_not_found");
  });

  it("flags oversized file without upload", async () => {
    const p = path.join(os.tmpdir(), `aegis-big-${Date.now()}.bin`);
    fs.writeFileSync(p, Buffer.alloc(2048));
    const r = await scanDownloadedFile(p, { ...cfg, maxUploadBytes: 10 });
    expect(r.reasons.some((x) => x.code === "file_too_large")).toBe(true);
    expect(r.scan.size).toBe(2048);
    fs.unlinkSync(p);
  });

  it("degrades without API key (hash path via upload scan)", async () => {
    const p = path.join(os.tmpdir(), `aegis-small-${Date.now()}.txt`);
    fs.writeFileSync(p, "hello aegis");
    const r = await scanDownloadedFile(p, cfg);
    expect(["review", "block"]).toContain(r.decision);
    expect(r.scan.vtApiKeyConfigured).toBe(false);
    fs.unlinkSync(p);
  });

  it("allow when VT hash already clean", async () => {
    clearVtCache();
    const p = path.join(os.tmpdir(), `aegis-clean-${Date.now()}.txt`);
    fs.writeFileSync(p, "clean-file-content-for-hash");
    const { sha256File } = await import("../services/fileUploadScan.js");
    const hash = await sha256File(p);
    primeVtCache(`file:${hash}`, {
      status: "clean",
      malicious: 0,
      suspicious: 0,
      harmless: 40,
      undetected: 5,
      reputation: 0,
      categories: [],
      cached: true,
      permalink: null,
    });
    primeVtCache(hash, {
      status: "clean",
      malicious: 0,
      suspicious: 0,
      harmless: 40,
      undetected: 5,
      reputation: 0,
      categories: [],
      cached: true,
      permalink: null,
    });
    const r = await scanDownloadedFile(p, { ...cfg, vtApiKey: "test" });
    expect(r.decision).toBe("allow");
    fs.unlinkSync(p);
  });
});
