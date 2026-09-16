import { randomUUID } from "node:crypto";
import type { Decision, EngineConfig, FileGateResult, Reason } from "../types.js";
import { lookupFileVt } from "./virustotal.js";

const HASH_RE = {
  md5: /^[a-f0-9]{32}$/i,
  sha1: /^[a-f0-9]{40}$/i,
  sha256: /^[a-f0-9]{64}$/i,
} as const;

export type HashType = "md5" | "sha1" | "sha256";

export function detectHashType(hash: string): HashType | null {
  const h = hash.trim().toLowerCase();
  if (HASH_RE.sha256.test(h)) return "sha256";
  if (HASH_RE.sha1.test(h)) return "sha1";
  if (HASH_RE.md5.test(h)) return "md5";
  return null;
}

export async function runFileGate(
  hash: string,
  config: EngineConfig,
  options: { fileName?: string | null; context?: string } = {},
): Promise<FileGateResult> {
  const trimmed = hash.trim().toLowerCase();
  const hashType = detectHashType(trimmed);
  const id = `chk_${randomUUID().slice(0, 8)}`;
  const checkedAt = new Date().toISOString();

  if (!hashType) {
    return {
      id,
      hash: trimmed,
      hashType: "sha256",
      fileName: options.fileName ?? null,
      decision: "block",
      score: 0,
      reasons: [
        {
          code: "invalid_hash",
          severity: "critical",
          message: "Not a valid MD5 / SHA1 / SHA256 hex hash.",
        },
      ],
      virusTotal: {
        status: "degraded",
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        reputation: null,
        categories: [],
        cached: false,
        permalink: null,
      },
      checkedAt,
      context: options.context,
      kind: "file",
    };
  }

  const vt = await lookupFileVt(trimmed, config.vtApiKey, config.vtCacheTtlMs);
  const reasons: Reason[] = [];

  if (vt.status === "malicious") {
    reasons.push({
      code: "vt_file_malicious",
      severity: "critical",
      message: `VirusTotal file report: ${vt.malicious} malicious / ${vt.suspicious} suspicious engines.`,
    });
  } else if (vt.status === "suspicious") {
    reasons.push({
      code: "vt_file_suspicious",
      severity: "warn",
      message: `VirusTotal file report: ${vt.suspicious} suspicious detections.`,
    });
  } else if (vt.status === "clean") {
    reasons.push({
      code: "vt_file_clean",
      severity: "info",
      message: `VirusTotal: file clean (${vt.harmless} harmless${vt.cached ? ", cached" : ""}).`,
    });
  } else if (vt.status === "unknown") {
    reasons.push({
      code: "vt_file_unknown",
      severity: "warn",
      message: "No VirusTotal record for this file hash. Treat untrusted content with care.",
    });
  } else if (vt.status === "degraded") {
    reasons.push({
      code: "vt_degraded",
      severity: "warn",
      message: "VirusTotal unavailable (no API key or rate-limited). File cannot be fully verified.",
    });
  } else {
    reasons.push({
      code: "vt_error",
      severity: "warn",
      message: "VirusTotal file lookup failed.",
    });
  }

  if (options.fileName) {
    const lower = options.fileName.toLowerCase();
    if (/\.(exe|scr|bat|cmd|ps1|vbs|js|jar|msi|dll|apk|dmg|pkg|sh|psm1)$/i.test(lower)) {
      reasons.push({
        code: "executable_extension",
        severity: "warn",
        message: `File extension suggests executable/script: ${options.fileName}`,
      });
    }
  }

  const decision = decideFile(vt.status, config);
  const score = scoreFile(decision, vt.status);

  return {
    id,
    hash: trimmed,
    hashType,
    fileName: options.fileName ?? null,
    decision,
    score,
    reasons,
    virusTotal: vt,
    checkedAt,
    context: options.context,
    kind: "file",
  };
}

function decideFile(
  vtStatus: FileGateResult["virusTotal"]["status"],
  config: EngineConfig,
): Decision {
  if (vtStatus === "malicious") return "block";
  if (config.policyMode === "observe") {
    if (vtStatus === "suspicious" || vtStatus === "unknown" || vtStatus === "degraded") {
      return "review";
    }
    return "allow";
  }
  if (config.policyMode === "strict") {
    return vtStatus === "clean" ? "allow" : "block";
  }
  if (vtStatus === "clean") return "allow";
  if (vtStatus === "suspicious") return "review";
  if (vtStatus === "unknown" || vtStatus === "degraded" || vtStatus === "error") return "review";
  return "review";
}

function scoreFile(
  decision: Decision,
  vtStatus: FileGateResult["virusTotal"]["status"],
): number {
  let score = 50;
  if (vtStatus === "clean") score += 35;
  if (vtStatus === "malicious") score -= 60;
  if (vtStatus === "suspicious") score -= 30;
  if (vtStatus === "unknown") score -= 10;
  if (vtStatus === "degraded") score -= 8;
  if (decision === "allow") score = Math.max(score, 75);
  if (decision === "block") score = Math.min(score, 20);
  return Math.max(0, Math.min(100, Math.round(score)));
}
