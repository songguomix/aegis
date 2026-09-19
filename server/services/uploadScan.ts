import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import type { EngineConfig, FileGateResult, Reason } from "../types.js";
import { uploadFileVt } from "./virustotal.js";

export interface UploadScanInput {
  filename?: string | null;
  base64?: string;
  path?: string;
  context?: string;
}

export interface UploadScanOk {
  ok: true;
  result: FileGateResult;
}

export interface UploadScanErr {
  ok: false;
  error:
    | "vt_key_required"
    | "file_too_large"
    | "empty_file"
    | "invalid_base64"
    | "path_not_found"
    | "upload_failed"
    | "analysis_timeout"
    | "invalid_input";
  maxBytes?: number;
  message?: string;
}

export type UploadScanResult = UploadScanOk | UploadScanErr;

function decideFromVt(status: string, config: EngineConfig): "allow" | "review" | "block" {
  if (status === "malicious") return "block";
  if (config.policyMode === "strict") return status === "clean" ? "allow" : "block";
  if (config.policyMode === "observe") {
    return status === "clean" ? "allow" : "review";
  }
  if (status === "clean") return "allow";
  return "review";
}

function scoreFor(decision: string, status: string): number {
  let score = 50;
  if (status === "clean") score += 35;
  if (status === "malicious") score -= 60;
  if (status === "suspicious") score -= 30;
  if (status === "unknown" || status === "degraded" || status === "error") score -= 8;
  if (decision === "allow") score = Math.max(score, 75);
  if (decision === "block") score = Math.min(score, 20);
  return Math.max(0, Math.min(100, Math.round(score)));
}

export async function runUploadScan(
  input: UploadScanInput,
  config: EngineConfig,
): Promise<UploadScanResult> {
  if (!input.path && !input.base64) {
    return { ok: false, error: "invalid_input", message: "Provide path or base64" };
  }

  let data: Buffer;
  let fileName = input.filename?.trim() || null;

  if (input.path) {
    const abs = path.resolve(input.path);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) {
      return { ok: false, error: "path_not_found" };
    }
    data = fs.readFileSync(abs);
    fileName = fileName || path.basename(abs);
  } else {
    try {
      data = Buffer.from(input.base64 ?? "", "base64");
    } catch {
      return { ok: false, error: "invalid_base64" };
    }
    if (!data.length && (input.base64 ?? "").length > 0) {
      return { ok: false, error: "invalid_base64" };
    }
  }

  if (!data.length) return { ok: false, error: "empty_file" };

  const maxBytes = config.maxUploadBytes || 32 * 1024 * 1024;
  if (data.length > maxBytes) {
    return { ok: false, error: "file_too_large", maxBytes };
  }
  if (!config.vtApiKey) {
    return { ok: false, error: "vt_key_required" };
  }

  const upload = await uploadFileVt(data, fileName || "upload.bin", config.vtApiKey, {
    maxBytes,
    pollAttempts: 2,
    pollDelayMs: 1200,
  });
  if (!upload) {
    return { ok: false, error: "upload_failed" };
  }

  if (!upload.ok) {
    const err =
      upload.error === "http_error" ? "upload_failed" : upload.error;
    return {
      ok: false,
      error: err,
      maxBytes: upload.maxBytes,
    };
  }

  const vt = upload.value.report;
  const sha256 = upload.value.sha256;
  const reasons: Reason[] = [];
  if (upload.value.uploaded) {
    reasons.push({
      code: "vt_uploaded_scan",
      severity: "info",
      message: `Uploaded to VirusTotal (${data.length} bytes) and fetched analysis.`,
    });
  } else {
    reasons.push({
      code: "vt_known_file",
      severity: "info",
      message: "VirusTotal already had this file hash; returned cached/known report.",
    });
  }
  if (vt.status === "malicious") {
    reasons.push({
      code: "vt_file_malicious",
      severity: "critical",
      message: `VirusTotal upload scan: ${vt.malicious} malicious engines.`,
    });
  } else if (vt.status === "suspicious") {
    reasons.push({
      code: "vt_file_suspicious",
      severity: "warn",
      message: `VirusTotal upload scan: ${vt.suspicious} suspicious detections.`,
    });
  } else if (vt.status === "clean") {
    reasons.push({
      code: "vt_file_clean",
      severity: "info",
      message: `VirusTotal upload scan: clean (${vt.harmless} harmless).`,
    });
  } else {
    reasons.push({
      code: "vt_file_unknown",
      severity: "warn",
      message: "VirusTotal returned no conclusive stats after upload/poll.",
    });
  }

  const decision = decideFromVt(vt.status, config);
  const result: FileGateResult = {
    id: `chk_${randomUUID().slice(0, 8)}`,
    hash: sha256,
    hashType: "sha256",
    fileName: fileName,
    decision,
    score: scoreFor(decision, vt.status),
    reasons,
    virusTotal: vt,
    checkedAt: new Date().toISOString(),
    context: input.context,
    kind: "file",
    analysisId: upload.value.analysisId || undefined,
    uploaded: upload.value.uploaded,
    bytes: data.length,
    sha256,
  };
  return { ok: true, result };
}

export function maxUploadFromConfig(config: EngineConfig): number {
  return config.maxUploadBytes || 32 * 1024 * 1024;
}

// keep crypto import used
void crypto;
