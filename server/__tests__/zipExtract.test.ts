import { describe, it, expect } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import {
  extractZipWithNode,
  readZipEntries,
  safeMemberPath,
} from "../services/zipExtract.js";
import { extractInSandbox, cleanupSandbox } from "../services/sandbox.js";

interface Entry {
  name: string;
  data?: string;
  method?: 0 | 8;
  externalAttrs?: number;
}

/** Minimal zip writer so the test controls compression and attributes. */
function buildZip(entries: Entry[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const method = e.method ?? 0;
    const nameBuf = Buffer.from(e.name, "utf8");
    const raw = Buffer.from(e.data ?? "", "utf8");
    const payload = method === 8 ? zlib.deflateRawSync(raw) : raw;
    const crc = zlib.crc32 ? zlib.crc32(raw) : 0;

    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(0x04034b50, 0);
    lfh.writeUInt16LE(20, 4);
    lfh.writeUInt16LE(method, 8);
    lfh.writeUInt32LE(crc, 14);
    lfh.writeUInt32LE(payload.length, 18);
    lfh.writeUInt32LE(raw.length, 22);
    lfh.writeUInt16LE(nameBuf.length, 26);
    locals.push(lfh, nameBuf, payload);

    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0);
    cen.writeUInt16LE(20, 4);
    cen.writeUInt16LE(20, 6);
    cen.writeUInt16LE(method, 10);
    cen.writeUInt32LE(crc, 16);
    cen.writeUInt32LE(payload.length, 20);
    cen.writeUInt32LE(raw.length, 24);
    cen.writeUInt16LE(nameBuf.length, 28);
    cen.writeUInt32LE(e.externalAttrs ?? 0, 38);
    cen.writeUInt32LE(offset, 42);
    centrals.push(cen, nameBuf);
    offset += lfh.length + nameBuf.length + payload.length;
  }
  const centralBuf = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBuf.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, centralBuf, end]);
}

let tmp: string;
beforeAllTmp();
function beforeAllTmp() {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-zip-test-"));
}

describe("zip extraction (node only, no unzip binary)", () => {
  it("extracts stored and deflated members with intact content", () => {
    const zip = path.join(tmp, "mixed.zip");
    fs.writeFileSync(
      zip,
      buildZip([
        { name: "readme.txt", data: "hello world", method: 0 },
        { name: "dir/nested.txt", data: "x".repeat(5000), method: 8 },
      ]),
    );
    const entries = readZipEntries(zip);
    expect(entries?.map((e) => e.name)).toEqual(["readme.txt", "dir/nested.txt"]);

    const dest = path.join(tmp, "out-ok");
    const r = extractZipWithNode(zip, dest);
    expect(r.parsed).toBe(true);
    expect(r.ok).toBe(true);
    expect(r.extracted).toBe(2);
    expect(fs.readFileSync(path.join(dest, "readme.txt"), "utf8")).toBe("hello world");
    expect(fs.readFileSync(path.join(dest, "dir", "nested.txt"), "utf8")).toHaveLength(5000);
  });

  it("refuses path traversal, absolute and windows paths", () => {
    const zip = path.join(tmp, "evil.zip");
    fs.writeFileSync(
      zip,
      buildZip([
        { name: "../../../../tmp/aegis-test-pwned.txt", data: "pwned", method: 0 },
        { name: "/etc/passwd", data: "root", method: 0 },
        { name: "C:\\Windows\\evil.dll", data: "dll", method: 0 },
      ]),
    );
    const dest = path.join(tmp, "out-evil");
    const r = extractZipWithNode(zip, dest);
    expect(r.extracted).toBe(0);
    expect(r.refused.length).toBe(3);
    expect(r.ok).toBe(false);
    expect(fs.existsSync("/tmp/aegis-test-pwned.txt")).toBe(false);
    expect(safeMemberPath("../x")).toBeNull();
    expect(safeMemberPath("/abs")).toBeNull();
    expect(safeMemberPath("a/../b")).toBeNull();
    expect(safeMemberPath("ok/name.txt")).toBe("ok/name.txt");
  });

  it("refuses symlink members", () => {
    const zip = path.join(tmp, "link.zip");
    fs.writeFileSync(
      zip,
      buildZip([
        { name: "evil-link", data: "/etc/passwd", method: 0, externalAttrs: (0xa1ff << 16) >>> 0 },
      ]),
    );
    const r = extractZipWithNode(zip, path.join(tmp, "out-link"));
    expect(r.extracted).toBe(0);
    expect(r.refused).toContain("evil-link");
  });

  it("reports parsed=false for non-zip input", () => {
    const p = path.join(tmp, "not.zip");
    fs.writeFileSync(p, Buffer.alloc(512, 9));
    const r = extractZipWithNode(p, path.join(tmp, "out-nz"));
    expect(r.parsed).toBe(false);
    expect(r.error).toBe("not_a_zip");
  });

  it("caps the total uncompressed size (zip bomb guard)", () => {
    const zip = path.join(tmp, "bomb.zip");
    fs.writeFileSync(
      zip,
      buildZip([{ name: "big.txt", data: "y".repeat(100_000), method: 8 }]),
    );
    const r = extractZipWithNode(zip, path.join(tmp, "out-bomb"), {
      maxTotalBytes: 1000,
    });
    expect(r.extracted).toBe(0);
    expect(r.refused.length).toBe(1);
  });
});

describe("extractInSandbox", () => {
  it("extracts via the node extractor and reports refused members", async () => {
    const zip = path.join(tmp, "sandbox.zip");
    fs.writeFileSync(
      zip,
      buildZip([
        { name: "readme.txt", data: "hello", method: 0 },
        { name: "../escape.txt", data: "nope", method: 0 },
      ]),
    );
    // The path-traversal pre-check rejects the archive before extraction.
    const r = await extractInSandbox(zip);
    expect(r.ok).toBe(false);
    expect(r.error).toBe("path_traversal");
    if (r.sandboxRoot) cleanupSandbox(path.dirname(r.sandboxRoot));
  });

  it("extracts a clean archive without the system unzip binary", async () => {
    const zip = path.join(tmp, "clean.zip");
    fs.writeFileSync(
      zip,
      buildZip([{ name: "readme.txt", data: "hello", method: 0 }]),
    );
    const r = await extractInSandbox(zip);
    expect(r.ok).toBe(true);
    expect(r.extractedCount).toBeGreaterThan(0);
    expect(r.members).toContain("readme.txt");
    expect(r.isolated).toBe(r.mode !== "restricted");
    if (r.sandboxRoot) cleanupSandbox(path.dirname(r.sandboxRoot));
  });
});
