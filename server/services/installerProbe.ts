import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

export interface InstallerAnalysis {
  ok: boolean;
  error?: string;
  path: string;
  fileName: string;
  size: number;
  hashes: { sha256: string; sha1: string; md5: string };
  kind: string;
  mimeGuess: string;
  entropy: number;
  urls: string[];
  ips: string[];
  suspiciousStrings: string[];
  archiveMembers: string[];
  riskFlags: string[];
  aiBrief: string;
  checkedAt: string;
}

const MAX_SAMPLE = 8 * 1024 * 1024; // sample first 8MB for strings/entropy
const MAGIC: Array<{ bytes: number[]; kind: string; mime: string }> = [
  { bytes: [0x50, 0x4b, 0x03, 0x04], kind: "zip/jar/apk", mime: "application/zip" },
  { bytes: [0x4d, 0x5a], kind: "pe-exe", mime: "application/vnd.microsoft.portable-executable" },
  { bytes: [0x7f, 0x45, 0x4c, 0x46], kind: "elf", mime: "application/x-elf" },
  { bytes: [0xca, 0xfe, 0xba, 0xbe], kind: "java-class", mime: "application/java-vm" },
  { bytes: [0x21, 0x3c, 0x61, 0x72, 0x63, 0x68, 0x3e], kind: "deb-ar", mime: "application/vnd.debian.binary-package" },
];

const SUSPICIOUS = [
  /curl\s+https?:\/\//i,
  /wget\s+https?:\/\//i,
  /powershell/i,
  /Invoke-Expression|IEX\s*\(/i,
  /\/bin\/bash\s+-c/i,
  /LaunchAgent|LaunchDaemon/i,
  /password|credential|keychain/i,
  /ransom|decrypt_your|bitcoin|wallet\.dat/i,
  /\/\.ssh\//i,
  /sudo\s+chmod\s+\+x/i,
  /rm\s+-rf\s+\//i,
];

function shannon(buf: Buffer): number {
  if (!buf.length) return 0;
  const freq = new Array<number>(256).fill(0);
  for (let i = 0; i < buf.length; i++) freq[buf[i]]++;
  let h = 0;
  for (let i = 0; i < 256; i++) {
    if (!freq[i]) continue;
    const p = freq[i] / buf.length;
    h -= p * Math.log2(p);
  }
  return Math.round(h * 100) / 100;
}

function detectKind(buf: Buffer, name: string): { kind: string; mime: string } {
  const ext = path.extname(name).toLowerCase().replace(/^\./, "");
  for (const m of MAGIC) {
    if (m.bytes.every((b, i) => buf[i] === b)) {
      return { kind: m.kind, mime: m.mime };
    }
  }
  if (ext === "dmg") return { kind: "dmg", mime: "application/x-apple-diskimage" };
  if (ext === "pkg" || ext === "mpkg") return { kind: "pkg", mime: "application/vnd.apple.installer-package" };
  if (ext === "msi") return { kind: "msi", mime: "application/x-msi" };
  if (ext === "appimage") return { kind: "appimage", mime: "application/octet-stream" };
  return { kind: ext || "unknown", mime: "application/octet-stream" };
}

function extractStrings(sample: Buffer, minLen = 6): string[] {
  const out: string[] = [];
  let cur = "";
  for (let i = 0; i < sample.length; i++) {
    const c = sample[i];
    if (c >= 32 && c < 127) {
      cur += String.fromCharCode(c);
    } else {
      if (cur.length >= minLen) out.push(cur);
      cur = "";
    }
    if (out.length > 4000) break;
  }
  if (cur.length >= minLen) out.push(cur);
  return out;
}

function zipMemberNames(sample: Buffer): string[] {
  const names: string[] = [];
  // naive scan of local file headers PK\x03\x04
  let i = 0;
  while (i + 30 < sample.length && names.length < 80) {
    if (sample[i] === 0x50 && sample[i + 1] === 0x4b && sample[i + 2] === 0x03 && sample[i + 3] === 0x04) {
      const nameLen = sample.readUInt16LE(i + 26);
      const name = sample.slice(i + 30, i + 30 + nameLen).toString("utf8");
      if (name && name.length < 200) names.push(name);
      i += 30 + nameLen;
    } else {
      i++;
    }
  }
  return names;
}

export function analyzeInstallerPath(absPath: string): InstallerAnalysis {
  const checkedAt = new Date().toISOString();
  let resolved = "";
  try {
    resolved = fs.realpathSync(path.resolve(absPath));
  } catch {
    return {
      ok: false,
      error: "file_not_found",
      path: absPath,
      fileName: path.basename(absPath || ""),
      size: 0,
      hashes: { sha256: "", sha1: "", md5: "" },
      kind: "unknown",
      mimeGuess: "application/octet-stream",
      entropy: 0,
      urls: [],
      ips: [],
      suspiciousStrings: [],
      archiveMembers: [],
      riskFlags: ["file_not_found"],
      aiBrief: "File not found. Ask the user for the correct installer path.",
      checkedAt,
    };
  }
  const st = fs.statSync(resolved);
  if (!st.isFile()) {
    return {
      ok: false,
      error: "not_a_file",
      path: resolved,
      fileName: path.basename(resolved),
      size: 0,
      hashes: { sha256: "", sha1: "", md5: "" },
      kind: "directory",
      mimeGuess: "application/octet-stream",
      entropy: 0,
      urls: [],
      ips: [],
      suspiciousStrings: [],
      archiveMembers: [],
      riskFlags: ["not_a_file"],
      aiBrief: "Path is not a regular file.",
      checkedAt,
    };
  }

  const fd = fs.openSync(resolved, "r");
  try {
    const head = Buffer.alloc(Math.min(16, st.size));
    fs.readSync(fd, head, 0, head.length, 0);
    const sampleLen = Math.min(st.size, MAX_SAMPLE);
    const sample = Buffer.alloc(sampleLen);
    fs.readSync(fd, sample, 0, sampleLen, 0);

    const hashes = {
      sha256: crypto.createHash("sha256").update(sample).digest("hex"),
      sha1: "",
      md5: "",
    };
    // full-file hashes when file is small enough we already have full content
    if (st.size <= MAX_SAMPLE) {
      hashes.sha256 = crypto.createHash("sha256").update(sample).digest("hex");
      hashes.sha1 = crypto.createHash("sha1").update(sample).digest("hex");
      hashes.md5 = crypto.createHash("md5").update(sample).digest("hex");
    } else {
      // stream full hashes
      const buf = fs.readFileSync(resolved);
      hashes.sha256 = crypto.createHash("sha256").update(buf).digest("hex");
      hashes.sha1 = crypto.createHash("sha1").update(buf).digest("hex");
      hashes.md5 = crypto.createHash("md5").update(buf).digest("hex");
    }

    const kindInfo = detectKind(head, resolved);
    const kind = kindInfo.kind;
    const mimeGuess = kindInfo.mime;
    const entropy = shannon(sample.subarray(0, Math.min(sample.length, 256 * 1024)));
    const strings = extractStrings(sample);
    const urlRe = /https?:\/\/[^\s"'<>]{4,120}/gi;
    const ipRe = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    const urls = [...new Set((sample.toString("latin1").match(urlRe) ?? []).slice(0, 30))];
    const ips = [...new Set((sample.toString("latin1").match(ipRe) ?? []).slice(0, 20))];

    const suspiciousStrings: string[] = [];
    for (const s of strings) {
      for (const re of SUSPICIOUS) {
        if (re.test(s)) {
          if (suspiciousStrings.length < 40) suspiciousStrings.push(s.slice(0, 160));
          break;
        }
      }
    }

    const archiveMembers = kind.startsWith("zip") ? zipMemberNames(sample) : [];
    const riskyMembers = archiveMembers.filter((m) =>
      /\.(exe|dll|bat|cmd|ps1|vbs|js|jar|sh|msi|scr)$/i.test(m),
    );

    const riskFlags: string[] = [];
    if (entropy > 7.2) riskFlags.push("high_entropy");
    if (kind === "pe-exe" || kind === "pkg" || kind === "dmg" || kind === "msi") {
      riskFlags.push("installer_or_executable");
    }
    if (suspiciousStrings.length) riskFlags.push("suspicious_strings");
    if (riskyMembers.length) riskFlags.push("archive_executables");
    if (urls.length) riskFlags.push("embedded_urls");
    if (ips.length) riskFlags.push("embedded_ips");

    const aiBrief = [
      `Analyze this downloaded package for the user (static only; do not execute).`,
      `File: ${path.basename(resolved)} (${kind}, ${st.size} bytes)`,
      `SHA256: ${hashes.sha256}`,
      `Entropy: ${entropy}`,
      `Risk flags: ${riskFlags.join(", ") || "none"}`,
      urls.length ? `Embedded URLs (sample): ${urls.slice(0, 8).join(" | ")}` : "",
      suspiciousStrings.length
        ? `Suspicious strings: ${suspiciousStrings.slice(0, 8).join(" | ")}`
        : "",
      archiveMembers.length
        ? `Archive members: ${archiveMembers.length}, risky: ${riskyMembers.slice(0, 8).join(", ") || "no"}`
        : "",
      `Tasks: 1) Is this likely a legitimate installer? 2) List concrete risks.`,
      `3) Recommend allow / quarantine / delete for an AI agent download workflow.`,
      `4) Say what the user should verify (publisher, download origin) before install.`,
    ]
      .filter(Boolean)
      .join("\n");

    return {
      ok: true,
      path: resolved,
      fileName: path.basename(resolved),
      size: st.size,
      hashes,
      kind,
      mimeGuess,
      entropy,
      urls,
      ips,
      suspiciousStrings,
      archiveMembers: archiveMembers.slice(0, 40),
      riskFlags,
      aiBrief,
      checkedAt,
    };
  } finally {
    fs.closeSync(fd);
  }
}
