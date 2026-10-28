import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";

export interface ZipEntry {
  name: string;
  method: number;
  compressedSize: number;
  uncompressedSize: number;
  localOffset: number;
  externalAttrs: number;
}

export interface ZipExtractResult {
  /** True when the archive was parsed (even if every entry was refused). */
  parsed: boolean;
  ok: boolean;
  extracted: number;
  skipped: number;
  /** Entries that were refused (path traversal, symlink, limits). */
  refused: string[];
  error?: string;
}

const EOCD_SIG = 0x06054b50;
const CD_SIG = 0x02014b50;
const LFH_SIG = 0x04034b50;

/** Unix mode bits live in the high 16 bits of the external attributes. */
function unixMode(externalAttrs: number): number {
  return (externalAttrs >>> 16) & 0xffff;
}

function isSymlink(externalAttrs: number): boolean {
  return (unixMode(externalAttrs) & 0xf000) === 0xa000;
}

function isDirectoryEntry(entry: ZipEntry): boolean {
  return entry.name.endsWith("/") || (unixMode(entry.externalAttrs) & 0xf000) === 0x4000;
}

/**
 * Normalise a zip member name and refuse anything that could escape the
 * destination directory. Returns null when the name is unsafe.
 */
export function safeMemberPath(name: string): string | null {
  if (!name) return null;
  if (name.includes("\\")) return null; // windows separators / traversal
  if (name.startsWith("/")) return null; // absolute
  if (/^[a-zA-Z]:/.test(name)) return null; // drive letter
  const parts = name.split("/").filter((p) => p !== "" && p !== ".");
  if (parts.some((p) => p === "..")) return null;
  if (!parts.length) return null;
  return parts.join("/");
}

/**
 * Parse the central directory of a zip archive.
 * Returns null when the file is not a readable (non-zip64-sentinel) archive.
 */
export function readZipEntries(filePath: string): ZipEntry[] | null {
  let fd: number | null = null;
  try {
    const st = fs.statSync(filePath);
    if (!st.isFile() || st.size < 22) return null;
    fd = fs.openSync(filePath, "r");

    const tailLen = Math.min(st.size, 65_557 + 22);
    const tail = Buffer.alloc(tailLen);
    fs.readSync(fd, tail, 0, tailLen, st.size - tailLen);
    let eocd = -1;
    for (let i = tail.length - 22; i >= 0; i--) {
      if (tail.readUInt32LE(i) === EOCD_SIG) {
        eocd = i;
        break;
      }
    }
    if (eocd < 0) return null;

    let entryCount = tail.readUInt16LE(eocd + 10);
    let cdSize = tail.readUInt32LE(eocd + 12);
    let cdOffset = tail.readUInt32LE(eocd + 16);
    if (cdSize === 0xffffffff || cdOffset === 0xffffffff) {
      // zip64: locate the zip64 EOCD locator right before the classic one.
      if (eocd < 20) return null;
      const locOffset = tail.readBigUInt64LE(eocd - 20 + 8);
      if (locOffset >= BigInt(st.size)) return null;
      const loc = Buffer.alloc(20);
      fs.readSync(fd, loc, 0, 20, Number(locOffset));
      if (loc.readUInt32LE(0) !== 0x07064b50) return null;
      const z64 = Buffer.alloc(56);
      fs.readSync(fd, z64, 0, 56, Number(loc.readBigUInt64LE(4)));
      if (z64.readUInt32LE(0) !== 0x06064b50) return null;
      entryCount = Number(z64.readBigUInt64LE(32));
      cdSize = Number(z64.readBigUInt64LE(40));
      cdOffset = Number(z64.readBigUInt64LE(48));
    }
    if (cdOffset > st.size || cdSize > st.size) return null;

    const cd = Buffer.alloc(cdSize);
    fs.readSync(fd, cd, 0, cdSize, cdOffset);

    const entries: ZipEntry[] = [];
    let p = 0;
    for (let n = 0; n < entryCount && p + 46 <= cd.length; n++) {
      if (cd.readUInt32LE(p) !== CD_SIG) break;
      const method = cd.readUInt16LE(p + 10);
      let compressedSize = cd.readUInt32LE(p + 20);
      let uncompressedSize = cd.readUInt32LE(p + 24);
      const nameLen = cd.readUInt16LE(p + 28);
      const extraLen = cd.readUInt16LE(p + 30);
      const commentLen = cd.readUInt16LE(p + 32);
      const externalAttrs = cd.readUInt32LE(p + 38);
      let localOffset = cd.readUInt32LE(p + 42);
      const name = cd.subarray(p + 46, p + 46 + nameLen).toString("utf8");

      // zip64 extra field (0x0001) carries the real sizes/offset.
      if (
        compressedSize === 0xffffffff ||
        uncompressedSize === 0xffffffff ||
        localOffset === 0xffffffff
      ) {
        let e = p + 46 + nameLen;
        const extraEnd = e + extraLen;
        while (e + 4 <= extraEnd) {
          const headerId = cd.readUInt16LE(e);
          const dataSize = cd.readUInt16LE(e + 2);
          let q = e + 4;
          if (headerId === 0x0001) {
            if (uncompressedSize === 0xffffffff && q + 8 <= extraEnd) {
              uncompressedSize = Number(cd.readBigUInt64LE(q));
              q += 8;
            }
            if (compressedSize === 0xffffffff && q + 8 <= extraEnd) {
              compressedSize = Number(cd.readBigUInt64LE(q));
              q += 8;
            }
            if (localOffset === 0xffffffff && q + 8 <= extraEnd) {
              localOffset = Number(cd.readBigUInt64LE(q));
              q += 8;
            }
            break;
          }
          e += 4 + dataSize;
        }
      }

      entries.push({
        name,
        method,
        compressedSize,
        uncompressedSize,
        localOffset,
        externalAttrs,
      });
      p += 46 + nameLen + extraLen + commentLen;
    }
    return entries.length ? entries : null;
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

/**
 * Extract a zip archive with Node only (no external `unzip` binary), so the
 * feature also works on Windows and on Linux without unzip installed.
 *
 * Safety: path traversal is refused, symlinks are skipped, and both the entry
 * count and the total uncompressed size are capped (zip-bomb guard).
 */
export function extractZipWithNode(
  filePath: string,
  destDir: string,
  opts: { maxEntries?: number; maxTotalBytes?: number } = {},
): ZipExtractResult {
  const maxEntries = opts.maxEntries ?? 2000;
  const maxTotalBytes = opts.maxTotalBytes ?? 512 * 1024 * 1024;

  const entries = readZipEntries(filePath);
  if (!entries) {
    return {
      parsed: false,
      ok: false,
      extracted: 0,
      skipped: 0,
      refused: [],
      error: "not_a_zip",
    };
  }

  const refused: string[] = [];
  let extracted = 0;
  let skipped = 0;
  let total = 0;

  let fd: number | null = null;
  try {
    const st = fs.statSync(filePath);
    fd = fs.openSync(filePath, "r");
    fs.mkdirSync(destDir, { recursive: true, mode: 0o700 });
    const root = path.resolve(destDir);

    for (const entry of entries) {
      if (extracted + skipped >= maxEntries) {
        skipped++;
        continue;
      }
      const rel = safeMemberPath(entry.name);
      if (!rel) {
        refused.push(entry.name);
        continue;
      }
      if (isSymlink(entry.externalAttrs)) {
        refused.push(entry.name);
        continue;
      }
      if (isDirectoryEntry(entry)) {
        try {
          fs.mkdirSync(path.join(root, rel), { recursive: true, mode: 0o700 });
        } catch {
          /* ignore */
        }
        skipped++;
        continue;
      }
      if (entry.method !== 0 && entry.method !== 8) {
        refused.push(entry.name);
        continue;
      }
      if (total + entry.uncompressedSize > maxTotalBytes) {
        refused.push(entry.name);
        continue;
      }

      // Local header: the payload starts after the (possibly different) name.
      const lfh = Buffer.alloc(30);
      fs.readSync(fd, lfh, 0, 30, entry.localOffset);
      if (lfh.readUInt32LE(0) !== LFH_SIG) {
        refused.push(entry.name);
        continue;
      }
      const lfhNameLen = lfh.readUInt16LE(26);
      const lfhExtraLen = lfh.readUInt16LE(28);
      const dataStart = entry.localOffset + 30 + lfhNameLen + lfhExtraLen;
      if (dataStart + entry.compressedSize > st.size) {
        refused.push(entry.name);
        continue;
      }

      const compressed = Buffer.alloc(entry.compressedSize);
      fs.readSync(fd, compressed, 0, entry.compressedSize, dataStart);

      let data: Buffer;
      try {
        data =
          entry.method === 0
            ? compressed
            : zlib.inflateRawSync(compressed, { maxOutputLength: maxTotalBytes });
      } catch {
        refused.push(entry.name);
        continue;
      }

      const target = path.join(root, rel);
      // Defence in depth: the normalised path must stay inside the root.
      if (!target.startsWith(root + path.sep)) {
        refused.push(entry.name);
        continue;
      }
      try {
        fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
        fs.writeFileSync(target, data, { mode: 0o600 });
        total += data.length;
        extracted++;
      } catch {
        refused.push(entry.name);
      }
    }

    // Refused entries mean the archive was understood but not fully trusted:
    // report success only when something usable was extracted (an empty
    // archive is fine too).
    return {
      parsed: true,
      ok: extracted > 0 || refused.length === 0,
      extracted,
      skipped,
      refused,
    };
  } catch (err) {
    return {
      parsed: true,
      ok: false,
      extracted,
      skipped,
      refused,
      error: err instanceof Error ? err.message : "extract_failed",
    };
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
