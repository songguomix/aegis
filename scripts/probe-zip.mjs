/**
 * Manual probe for the Node-based zip extractor: store/deflate content,
 * path-traversal refusal and symlink refusal.
 *
 *   npm run build:server && node scripts/probe-zip.mjs
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { extractZipWithNode, readZipEntries, safeMemberPath } from "../dist-server/services/zipExtract.js";
import { extractInSandbox, cleanupSandbox } from "../dist-server/services/sandbox.js";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-zip-probe-"));

/** Build a zip by hand so we control method, names and attributes. */
function buildZip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const e of entries) {
    const nameBuf = Buffer.from(e.name, "utf8");
    const raw = Buffer.from(e.data ?? "", "utf8");
    const deflated = e.method === 8 ? zlib.deflateRawSync(raw) : raw;
    const crc = zlib.crc32 ? zlib.crc32(raw) : 0;

    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(0x04034b50, 0);
    lfh.writeUInt16LE(20, 4);
    lfh.writeUInt16LE(e.method, 8);
    lfh.writeUInt32LE(crc, 14);
    lfh.writeUInt32LE(deflated.length, 18);
    lfh.writeUInt32LE(raw.length, 22);
    lfh.writeUInt16LE(nameBuf.length, 26);
    locals.push(lfh, nameBuf, deflated);

    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0);
    cen.writeUInt16LE(20, 4);
    cen.writeUInt16LE(20, 6);
    cen.writeUInt16LE(e.method, 10);
    cen.writeUInt32LE(crc, 16);
    cen.writeUInt32LE(deflated.length, 20);
    cen.writeUInt32LE(raw.length, 24);
    cen.writeUInt16LE(nameBuf.length, 28);
    cen.writeUInt32LE(e.externalAttrs ?? 0, 38);
    cen.writeUInt32LE(offset, 42);
    centrals.push(cen, nameBuf);
    offset += lfh.length + nameBuf.length + deflated.length;
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

// 1) store + deflate entries
const zip1 = path.join(tmp, "mixed.zip");
fs.writeFileSync(
  zip1,
  buildZip([
    { name: "readme.txt", data: "hello world", method: 0 },
    { name: "dir/nested.txt", data: "x".repeat(5000), method: 8 },
    { name: "setup.exe", data: "MZ fake", method: 0 },
  ]),
);
const entries = readZipEntries(zip1);
console.log("1) central dir entries:", entries?.map((e) => `${e.name}(m=${e.method})`).join(", "));

const dest1 = path.join(tmp, "out1");
const r1 = extractZipWithNode(zip1, dest1);
console.log("   extract ok:", r1.ok, "extracted:", r1.extracted, "refused:", r1.refused.length);
console.log(
  "   readme.txt content:",
  JSON.stringify(fs.readFileSync(path.join(dest1, "readme.txt"), "utf8")),
);
console.log(
  "   nested.txt length:",
  fs.readFileSync(path.join(dest1, "dir", "nested.txt"), "utf8").length,
  "(expect 5000)",
);

// 2) path traversal attempt
const zip2 = path.join(tmp, "evil.zip");
fs.writeFileSync(
  zip2,
  buildZip([
    { name: "../../../../tmp/aegis-pwned.txt", data: "pwned", method: 0 },
    { name: "/etc/passwd", data: "root", method: 0 },
    { name: "C:\\Windows\\evil.dll", data: "dll", method: 0 },
  ]),
);
const r2 = extractZipWithNode(zip2, path.join(tmp, "out2"));
console.log("2) traversal zip → ok:", r2.ok, "extracted:", r2.extracted, "refused:", r2.refused.length, r2.refused);
console.log("   escaped file exists:", fs.existsSync("/tmp/aegis-pwned.txt"));
console.log("   safeMemberPath('../x') =", safeMemberPath("../x"));

// 3) symlink entry must be refused
const zip3 = path.join(tmp, "link.zip");
fs.writeFileSync(
  zip3,
  buildZip([{ name: "evil-link", data: "/etc/passwd", method: 0, externalAttrs: (0xa1ff << 16) >>> 0 }]),
);
const r3 = extractZipWithNode(zip3, path.join(tmp, "out3"));
console.log("3) symlink zip → extracted:", r3.extracted, "refused:", r3.refused);

// 4) full extractInSandbox path (uses the Node extractor now)
const r4 = await extractInSandbox(zip1);
console.log(
  "4) extractInSandbox ok:",
  r4.ok,
  "count:",
  r4.extractedCount,
  "members:",
  r4.members.length,
  "isolated:",
  r4.isolated,
);
if (r4.sandboxRoot) cleanupSandbox(path.dirname(r4.sandboxRoot));

fs.rmSync(tmp, { recursive: true, force: true });
process.exit(0);
