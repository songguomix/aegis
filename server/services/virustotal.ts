import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import type { VirusTotalReport, VtStatus } from "../types.js";

interface CacheEntry {
  at: number;
  value: VirusTotalReport;
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..", "..");
const DATA_DIR = process.env.AEGIS_DATA_DIR
  ? path.resolve(process.env.AEGIS_DATA_DIR)
  : path.join(ROOT, ".aegis");
const DISK_CACHE = path.join(DATA_DIR, "vt-cache.json");

const memory = new Map<string, CacheEntry>();
let lastCallAt = 0;
let backoffUntil = 0;
let vtLock: Promise<void> = Promise.resolve();
const MIN_INTERVAL_MS = 16000;

async function withVtLock<T>(fn: () => Promise<T>): Promise<T> {
  const run = vtLock.then(fn, fn);
  vtLock = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
} // ~4/min free-tier safety

function loadDisk(): void {
  try {
    if (!fs.existsSync(DISK_CACHE)) return;
    const raw = JSON.parse(fs.readFileSync(DISK_CACHE, "utf8")) as Record<
      string,
      CacheEntry
    >;
    for (const [k, v] of Object.entries(raw)) memory.set(k, v);
  } catch {
    /* ignore corrupt cache */
  }
}

function persistDisk(): void {
  try {
    fs.mkdirSync(path.dirname(DISK_CACHE), { recursive: true });
    const obj: Record<string, CacheEntry> = {};
    for (const [k, v] of memory.entries()) obj[k] = v;
    fs.writeFileSync(DISK_CACHE, JSON.stringify(obj), "utf8");
  } catch {
    /* non-fatal */
  }
}

loadDisk();

function degraded(): VirusTotalReport {
  return {
    status: "degraded",
    malicious: 0,
    suspicious: 0,
    harmless: 0,
    undetected: 0,
    reputation: null,
    categories: [],
    cached: false,
    permalink: null,
  };
}

function mapStats(stats: {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
}): VtStatus {
  const mal = stats.malicious ?? 0;
  const sus = stats.suspicious ?? 0;
  // Fail closed: any malicious engine blocks; multiple suspicious → malicious.
  if (mal >= 1 || sus >= 3) return "malicious";
  if (sus >= 1) return "suspicious";
  if ((stats.harmless ?? 0) + (stats.undetected ?? 0) > 0) return "clean";
  return "unknown";
}

export async function lookupDomainVt(
  domain: string,
  apiKey: string | null,
  ttlMs = 6 * 60 * 60 * 1000,
): Promise<VirusTotalReport> {
  const host = domain.toLowerCase().replace(/\.$/, "");
  const cached = memory.get(host);
  if (cached && Date.now() - cached.at < ttlMs) {
    return { ...cached.value, cached: true };
  }

  if (!apiKey) {
    return degraded();
  }

  const now = Date.now();
  if (now < backoffUntil) {
    return degraded();
  }
  const wait = MIN_INTERVAL_MS - (now - lastCallAt);
  if (wait > 0) {
    await new Promise((r) => setTimeout(r, wait));
  }

  try {
    lastCallAt = Date.now();
    const res = await fetch(
      `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(host)}`,
      {
        headers: { "x-apikey": apiKey, Accept: "application/json" },
      },
    );
    if (res.status === 404) {
      const value: VirusTotalReport = {
        status: "unknown",
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        reputation: null,
        categories: [],
        cached: false,
        permalink: `https://www.virustotal.com/gui/domain/${host}`,
      };
      memory.set(host, { at: Date.now(), value });
      persistDisk();
      return value;
    }
    if (res.status === 429) {
      backoffUntil = Date.now() + 60_000;
      return degraded();
    }
    if (!res.ok) {
      return { ...degraded(), status: "error" };
    }
    const body = (await res.json()) as {
      data?: {
        id?: string;
        attributes?: {
          last_analysis_stats?: {
            malicious?: number;
            suspicious?: number;
            harmless?: number;
            undetected?: number;
          };
          reputation?: number;
          categories?: Record<string, string>;
        };
      };
    };
    const attrs = body.data?.attributes ?? {};
    const stats = attrs.last_analysis_stats ?? {};
    const categories = attrs.categories
      ? Object.values(attrs.categories).slice(0, 5)
      : [];
    const value: VirusTotalReport = {
      status: mapStats(stats),
      malicious: stats.malicious ?? 0,
      suspicious: stats.suspicious ?? 0,
      harmless: stats.harmless ?? 0,
      undetected: stats.undetected ?? 0,
      reputation: attrs.reputation ?? null,
      categories,
      cached: false,
      permalink: `https://www.virustotal.com/gui/domain/${host}`,
    };
    memory.set(host, { at: Date.now(), value });
    persistDisk();
    return value;
  } catch {
    return degraded();
  }
}

export function clearVtCache(): void {
  memory.clear();
  try {
    if (fs.existsSync(DISK_CACHE)) fs.unlinkSync(DISK_CACHE);
  } catch {
    /* ignore */
  }
}

export function vtCacheSize(): number {
  return memory.size;
}

/** Test helper: inject a report without network. */
export function primeVtCache(domain: string, value: VirusTotalReport): void {
  memory.set(domain.toLowerCase(), { at: Date.now(), value });
}

export function dropVtCacheKey(domain: string): void {
  const k = domain.toLowerCase();
  memory.delete(k);
  memory.delete(`file:${k}`);
}

async function vtFetch(
  path: string,
  apiKey: string,
  init: RequestInit = {},
): Promise<Response> {
  return withVtLock(async () => {
    const now = Date.now();
    if (now < backoffUntil) {
      throw Object.assign(new Error("backoff"), { status: 429 });
    }
    const wait = MIN_INTERVAL_MS - (now - lastCallAt);
    if (wait > 0) {
      await new Promise((r) => setTimeout(r, wait));
    }
    lastCallAt = Date.now();
    return fetch(`https://www.virustotal.com/api/v3${path}`, {
      ...init,
      headers: { "x-apikey": apiKey, Accept: "application/json", ...(init.headers as object | undefined) },
    });
  });
}

export interface VtUploadResult {
  analysisId: string;
  sha256: string;
  report: VirusTotalReport;
  uploaded: boolean;
}

/** Upload file bytes to VirusTotal and wait for analysis stats. */
export async function uploadFileVt(
  data: Buffer,
  filename: string,
  apiKey: string | null,
  opts: { maxBytes?: number; pollAttempts?: number; pollDelayMs?: number } = {},
): Promise<
  | { ok: true; value: VtUploadResult }
  | { ok: false; error: "vt_key_required" | "file_too_large" | "upload_failed" | "analysis_timeout" | "http_error"; maxBytes?: number }
> {
  const maxBytes = opts.maxBytes ?? 32 * 1024 * 1024;
  if (!apiKey) return { ok: false, error: "vt_key_required" };
  if (data.length > maxBytes) {
    return { ok: false, error: "file_too_large", maxBytes };
  }

  const sha256 = crypto.createHash("sha256").update(data).digest("hex");
  const cacheKey = `file:${sha256}`;
  const cached = memory.get(cacheKey);
  if (cached && Date.now() - cached.at < 6 * 60 * 60 * 1000) {
    return {
      ok: true,
      value: { analysisId: "", sha256, report: { ...cached.value, cached: true }, uploaded: false },
    };
  }

  try {
    const form = new FormData();
    const blob = new Blob([new Uint8Array(data)]);
    form.append("file", blob, filename || "upload.bin");

    let uploadRes: Response;
    try {
      uploadRes = await vtFetch("/files", apiKey, {
        method: "POST",
        body: form,
        headers: {},
      });
    } catch {
      return { ok: false, error: "upload_failed" };
    }

    if (uploadRes.status === 409 || uploadRes.status === 200) {
      // already exists or ok
    } else if (!uploadRes.ok) {
      if (uploadRes.status === 429) {
        backoffUntil = Date.now() + 60_000;
        return { ok: false, error: "upload_failed" };
      }
      return { ok: false, error: "upload_failed" };
    }

    let analysisId = "";
    try {
      const body = (await uploadRes.json()) as { data?: { id?: string; type?: string; links?: { self?: string } } };
      const id = body.data?.id ?? "";
      if (body.data?.type === "analysis") analysisId = id;
      else if (id.includes("-")) analysisId = id.split("-")[1] ?? id;
      else analysisId = id;
    } catch {
      analysisId = "";
    }

    // Prefer direct file report by sha256 (works for already-known files)
    const attempts = opts.pollAttempts ?? 15;
    const delay = opts.pollDelayMs ?? 2000;
    for (let i = 0; i < attempts; i++) {
      try {
        const fileRes = await vtFetch(`/files/${sha256}`, apiKey);
        if (fileRes.ok) {
          const body = (await fileRes.json()) as {
            data?: { attributes?: Parameters<typeof reportFromAttributes>[0] };
          };
          const attrs = body.data?.attributes ?? {};
          const stats = attrs.last_analysis_stats ?? {};
          const done =
            (stats.harmless ?? 0) + (stats.undetected ?? 0) + (stats.malicious ?? 0) + (stats.suspicious ?? 0) >
            0;
          if (done || i === attempts - 1) {
            const report = reportFromAttributes(
              attrs,
              `https://www.virustotal.com/gui/file/${sha256}`,
            );
            memory.set(cacheKey, { at: Date.now(), value: report });
            persistDisk();
            return {
              ok: true,
              value: {
                analysisId: analysisId || "",
                sha256,
                report,
                uploaded: true,
              },
            };
          }
        }
      } catch {
        /* retry */
      }
      if (analysisId) {
        try {
          await vtFetch(`/analyses/${analysisId}`, apiKey);
        } catch {
          /* ignore */
        }
      }
      if (i < attempts - 1) await new Promise((r) => setTimeout(r, delay));
    }

    // timeout: return unknown with permalink
    const report: VirusTotalReport = {
      status: "unknown",
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      reputation: null,
      categories: [],
      cached: false,
      permalink: `https://www.virustotal.com/gui/file/${sha256}`,
    };
    return { ok: false, error: "analysis_timeout" };
  } catch {
    return { ok: false, error: "upload_failed" };
  }
}

function reportFromAttributes(attrs: {
  last_analysis_stats?: {
    malicious?: number;
    suspicious?: number;
    harmless?: number;
    undetected?: number;
  };
  reputation?: number;
  categories?: Record<string, string>;
}, permalink: string): VirusTotalReport {
  const stats = attrs.last_analysis_stats ?? {};
  const categories = attrs.categories ? Object.values(attrs.categories).slice(0, 5) : [];
  return {
    status: mapStats(stats),
    malicious: stats.malicious ?? 0,
    suspicious: stats.suspicious ?? 0,
    harmless: stats.harmless ?? 0,
    undetected: stats.undetected ?? 0,
    reputation: attrs.reputation ?? null,
    categories,
    cached: false,
    permalink,
  };
}

/** VirusTotal file lookup by hash (sha256 / sha1 / md5). */
export async function lookupFileVt(
  hash: string,
  apiKey: string | null,
  ttlMs = 6 * 60 * 60 * 1000,
): Promise<VirusTotalReport> {
  const id = hash.toLowerCase().trim();
  const cacheKey = `file:${id}`;
  const cached = memory.get(cacheKey);
  if (cached && Date.now() - cached.at < ttlMs) {
    return { ...cached.value, cached: true };
  }
  if (!apiKey) return degraded();

  try {
    const res = await vtFetch(`/files/${encodeURIComponent(id)}`, apiKey);
    if (res.status === 404) {
      const value: VirusTotalReport = {
        status: "unknown",
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        reputation: null,
        categories: [],
        cached: false,
        permalink: `https://www.virustotal.com/gui/file/${id}`,
      };
      memory.set(cacheKey, { at: Date.now(), value });
      persistDisk();
      return value;
    }
    if (res.status === 429) {
      backoffUntil = Date.now() + 60_000;
      return degraded();
    }
    if (!res.ok) return { ...degraded(), status: "error" };

    const body = (await res.json()) as {
      data?: {
        attributes?: {
          last_analysis_stats?: {
            malicious?: number;
            suspicious?: number;
            harmless?: number;
            undetected?: number;
          };
          reputation?: number;
          categories?: Record<string, string>;
          meaningful_name?: string;
        };
      };
    };
    const value = reportFromAttributes(
      body.data?.attributes ?? {},
      `https://www.virustotal.com/gui/file/${id}`,
    );
    memory.set(cacheKey, { at: Date.now(), value });
    persistDisk();
    return value;
  } catch (err) {
    if ((err as { status?: number }).status === 429) return degraded();
    return degraded();
  }
}
