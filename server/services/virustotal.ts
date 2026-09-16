import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { VirusTotalReport, VtStatus } from "../types.js";

interface CacheEntry {
  at: number;
  value: VirusTotalReport;
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..", "..");
const DISK_CACHE = path.join(ROOT, ".aegis", "vt-cache.json");

const memory = new Map<string, CacheEntry>();
let lastCallAt = 0;
let backoffUntil = 0;
const MIN_INTERVAL_MS = 16000; // ~4/min free-tier safety

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
