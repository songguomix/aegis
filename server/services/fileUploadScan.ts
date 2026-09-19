import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { EngineConfig, FileGateResult } from "../types.js";
import { getConfig } from "./store.js";
import { runUploadScan } from "./uploadScan.js";

export const DEFAULT_MAX_UPLOAD_BYTES = 32 * 1024 * 1024;

export interface FileScanMeta {
  path: string;
  sha256: string;
  size: number;
  uploaded: boolean;
  analysisId: string | null;
  maxUploadBytes: number;
  vtApiKeyConfigured: boolean;
}

export type ScanFileResult = FileGateResult & {
  scan: FileScanMeta;
  sha256?: string;
};

function metaFromPath(rawPath: string, maxUploadBytes: number, key: boolean): FileScanMeta {
  return {
    path: rawPath,
    sha256: "",
    size: 0,
    uploaded: false,
    analysisId: null,
    maxUploadBytes,
    vtApiKeyConfigured: key,
  };
}

/** Downloaded-file scan: VT hash + upload when ≤ maxUploadBytes. Result is agent-facing. */
export async function scanDownloadedFile(
  rawPath: string,
  config: EngineConfig = getConfig(),
  opts: { fileName?: string | null } = {},
): Promise<ScanFileResult> {
  const limit = config.maxUploadBytes || DEFAULT_MAX_UPLOAD_BYTES;
  const key = Boolean(config.vtApiKey);
  let size = 0;
  let resolved = "";
  try {
    resolved = fs.realpathSync(path.resolve(String(rawPath || "")));
    size = fs.statSync(resolved).size;
  } catch {
    const id = `chk_${crypto.randomUUID().slice(0, 8)}`;
    return {
      id,
      hash: "",
      hashType: "sha256",
      fileName: opts.fileName ?? null,
      decision: "block",
      score: 0,
      reasons: [
        {
          code: "file_not_found",
          severity: "critical",
          message: "File path does not exist or is not a regular file.",
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
      checkedAt: new Date().toISOString(),
      kind: "file",
      scan: metaFromPath(String(rawPath), limit, key),
    };
  }

  if (size > limit) {
    const id = `chk_${crypto.randomUUID().slice(0, 8)}`;
    return {
      id,
      hash: "",
      hashType: "sha256",
      fileName: opts.fileName ?? path.basename(resolved),
      decision: "review",
      score: 35,
      reasons: [
        {
          code: "file_too_large",
          severity: "warn",
          message: `File ${size} bytes exceeds upload limit ${limit}. Use check_file_hash if you already have a hash.`,
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
      checkedAt: new Date().toISOString(),
      kind: "file",
      scan: { ...metaFromPath(resolved, limit, key), size },
    };
  }

  const outcome = await runUploadScan(
    { path: resolved, filename: opts.fileName ?? undefined },
    config,
  );
  if (!outcome.ok) {
    const id = `chk_${crypto.randomUUID().slice(0, 8)}`;
    return {
      id,
      hash: "",
      hashType: "sha256",
      fileName: opts.fileName ?? path.basename(resolved),
      decision: "review",
      score: 40,
      reasons: [
        {
          code: outcome.error,
          severity: outcome.error === "vt_key_required" ? "warn" : "warn",
          message: outcome.message ?? outcome.error,
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
      checkedAt: new Date().toISOString(),
      kind: "file",
      scan: { ...metaFromPath(resolved, limit, key), size },
    };
  }

  const result = outcome.result;
  const sha = result.sha256 ?? result.hash;
  return {
    ...result,
    hash: sha,
    sha256: sha,
    scan: {
      path: resolved,
      sha256: sha,
      size,
      uploaded: result.reasons.some((r) => r.code === "vt_uploaded") || Boolean(result.virusTotal.permalink),
      analysisId: result.reasons.find((r) => r.code === "vt_uploaded")?.message ?? null,
      maxUploadBytes: limit,
      vtApiKeyConfigured: key,
    },
  };
}

export async function sha256File(filePath: string): Promise<string> {
  const cryptoMod = await import("node:crypto");
  return new Promise((resolve, reject) => {
    const hash = cryptoMod.createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("data", (c) => hash.update(c));
    stream.on("error", reject);
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}
