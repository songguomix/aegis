import type { VirusTotalReport, VtStatus } from "../types.js";

interface CacheEntry {
  at: number;
  value: VirusTotalReport;
}

const cache = new Map<string, CacheEntry>();
let lastCallAt = 0;
const MIN_INTERVAL_MS = 16000; // ~4/min free tier safety

function degraded(reason: string): VirusTotalReport {
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
  if (mal >= 3) return "malicious";
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
  const cached = cache.get(host);
  if (cached && Date.now() - cached.at < ttlMs) {
    return { ...cached.value, cached: true };
  }

  if (!apiKey) {
    const value = degraded("no_api_key");
    return value;
  }

  const wait = MIN_INTERVAL_MS - (Date.now() - lastCallAt);
  if (wait > 0) {
    await new Promise((r) => setTimeout(r, Math.min(wait, 2000)));
  }
  lastCallAt = Date.now();

  try {
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
      cache.set(host, { at: Date.now(), value });
      return value;
    }
    if (!res.ok) {
      return {
        ...degraded(`http_${res.status}`),
        status: res.status === 429 ? "degraded" : "error",
      };
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
    cache.set(host, { at: Date.now(), value });
    return value;
  } catch {
    return degraded("network_error");
  }
}

export function clearVtCache(): void {
  cache.clear();
}

export function vtCacheSize(): number {
  return cache.size;
}

/** Test helper: inject a report without network. */
export function primeVtCache(domain: string, value: VirusTotalReport): void {
  cache.set(domain.toLowerCase(), { at: Date.now(), value });
}
