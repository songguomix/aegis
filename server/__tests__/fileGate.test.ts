import { describe, it, expect } from "vitest";
import { detectHashType, runFileGate } from "../services/fileGate.js";
import { DEFAULT_CONFIG, type EngineConfig } from "../types.js";
import { primeVtCache, clearVtCache } from "../services/virustotal.js";

const cfg: EngineConfig = { ...DEFAULT_CONFIG, vtApiKey: "k", enableRdap: false };

describe("detectHashType", () => {
  it("detects sha256", () => {
    expect(detectHashType("a".repeat(64))).toBe("sha256");
  });
  it("detects sha1", () => {
    expect(detectHashType("b".repeat(40))).toBe("sha1");
  });
  it("detects md5", () => {
    expect(detectHashType("c".repeat(32))).toBe("md5");
  });
  it("rejects garbage", () => {
    expect(detectHashType("not-a-hash")).toBeNull();
  });
});

describe("runFileGate", () => {
  it("blocks invalid hash", async () => {
    const r = await runFileGate("xyz", cfg);
    expect(r.decision).toBe("block");
    expect(r.reasons[0].code).toBe("invalid_hash");
  });

  it("blocks malicious file", async () => {
    clearVtCache();
    primeVtCache("file:" + "d".repeat(64), {
      status: "malicious",
      malicious: 12,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      reputation: -10,
      categories: [],
      cached: false,
      permalink: null,
    });
    const r = await runFileGate("d".repeat(64), cfg, { fileName: "evil.exe" });
    expect(r.decision).toBe("block");
    expect(r.hashType).toBe("sha256");
  });

  it("reviews unknown hash", async () => {
    clearVtCache();
    const r = await runFileGate("e".repeat(64), { ...cfg, vtApiKey: null });
    expect(r.decision).toBe("review");
  });
});
