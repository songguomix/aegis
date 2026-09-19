import { describe, it, expect, vi, beforeEach } from "vitest";
import { DEFAULT_CONFIG } from "../types.js";

const uploadFileVt = vi.fn();

vi.mock("../services/virustotal.js", () => ({
  uploadFileVt: (...args: unknown[]) => uploadFileVt(...args),
}));

import { runUploadScan } from "../services/uploadScan.js";

const cfg = { ...DEFAULT_CONFIG, vtApiKey: "k", maxUploadBytes: 1024 };

beforeEach(() => {
  uploadFileVt.mockReset();
});

describe("upload_scan", () => {
  it("rejects empty / invalid input", async () => {
    const r = await runUploadScan({}, cfg);
    expect(r.ok).toBe(false);
  });

  it("rejects oversized file", async () => {
    const big = Buffer.alloc(2048, 1);
    const r = await runUploadScan({ base64: big.toString("base64"), filename: "big.bin" }, cfg);
    expect(r.ok && r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe("file_too_large");
  });

  it("requires vt key", async () => {
    const r = await runUploadScan(
      { base64: Buffer.from("hi").toString("base64") },
      { ...cfg, vtApiKey: null },
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe("vt_key_required");
  });

  it("returns malicious block from VT report", async () => {
    uploadFileVt.mockResolvedValue({
      ok: true,
      value: {
        analysisId: "abc",
        sha256: "e3b0c442",
        uploaded: true,
        report: {
          status: "malicious",
          malicious: 10,
          suspicious: 0,
          harmless: 0,
          undetected: 0,
          reputation: -5,
          categories: [],
          cached: false,
          permalink: "https://www.virustotal.com/gui/file/e3b0c442",
        },
      },
    });
    const r = await runUploadScan(
      { base64: Buffer.from("evil").toString("base64"), filename: "evil.exe" },
      cfg,
    );
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.result.decision).toBe("block");
      expect(r.result.uploaded).toBe(true);
      expect(r.result.sha256).toBeTruthy();
    }
  });

  it("returns allow for clean upload", async () => {
    uploadFileVt.mockResolvedValue({
      ok: true,
      value: {
        analysisId: "x",
        sha256: "aa",
        uploaded: true,
        report: {
          status: "clean",
          malicious: 0,
          suspicious: 0,
          harmless: 50,
          undetected: 10,
          reputation: 0,
          categories: [],
          cached: false,
          permalink: null,
        },
      },
    });
    const r = await runUploadScan({ base64: Buffer.from("ok").toString("base64") }, cfg);
    expect(r.ok && r.result.decision).toBe("allow");
  });
});
