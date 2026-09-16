import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export type IntelStatus = "clean" | "listed" | "unknown" | "error" | "skipped";

export interface SourceHit {
  source: string;
  listed: boolean;
  detail?: string;
  url?: string;
}

export interface ThreatIntelReport {
  status: IntelStatus;
  sources: SourceHit[];
  listedBy: string[];
  cached: boolean;
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..", "..");
const DATA_DIR = process.env.AEGIS_DATA_DIR
  ? path.resolve(process.env.AEGIS_DATA_DIR)
  : path.join(ROOT, ".aegis");
const DISK = path.join(DATA_DIR, "intel-cache.json");

interface CacheEntry {
  at: number;
  value: ThreatIntelReport;
}

const memory = new Map<string, CacheEntry>();
const TTL_MS = 12 * 60 * 60 * 1000;
const TIMEOUT_MS = 4000;
const lastCallAt = new Map<string, number>();
const MIN_INTERVAL_MS = 1500;

function loadDisk(): void {
  try {
    if (!fs.existsSync(DISK)) return;
    const raw = JSON.parse(fs.readFileSync(DISK, "utf8")) as Record<string, CacheEntry>;
    for (const [k, v] of Object.entries(raw)) memory.set(k, v);
  } catch {
    /* ignore */
  }
}

function persistDisk(): void {
  try {
    fs.mkdirSync(path.dirname(DISK), { recursive: true });
    const obj: Record<string, CacheEntry> = {};
    for (const [k, v] of memory.entries()) obj[k] = v;
    fs.writeFileSync(DISK, JSON.stringify(obj), "utf8");
  } catch {
    /* ignore */
  }
}

loadDisk();

async function throttledFetch(
  key: string,
  url: string,
  init?: RequestInit,
): Promise<Response> {
  const last = lastCallAt.get(key) ?? 0;
  const wait = MIN_INTERVAL_MS - (Date.now() - last);
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  lastCallAt.set(key, Date.now());
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/** abuse.ch URLhaus — free, no API key for public lookups. */
async function queryUrlhaus(host: string, fullUrl?: string): Promise<SourceHit> {
  try {
    const body = new URLSearchParams();
    if (fullUrl) body.set("url", fullUrl);
    body.set("host", host);
    const res = await throttledFetch("urlhaus", "https://urlhaus-api.abuse.ch/v1/host/", {
      method: "POST",
      body,
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    if (!res.ok) {
      return { source: "URLhaus", listed: false, detail: `http_${res.status}` };
    }
    const data = (await res.json()) as {
      query_status?: string;
      blacklists?: Record<string, unknown>;
      urls?: Array<{ url?: string; url_status?: string; threat?: string }>;
    };
    const status = data.query_status ?? "";
    if (status === "no_results") {
      return { source: "URLhaus", listed: false, detail: "no_results" };
    }
    if (status === "ok") {
      const live = (data.urls ?? []).filter((u) => u.url_status === "online").length;
      return {
        source: "URLhaus",
        listed: true,
        detail: `malware host (${data.urls?.length ?? 0} urls${live ? `, ${live} online` : ""})`,
        url: `https://urlhaus.abuse.ch/host/${host}/`,
      };
    }
    return { source: "URLhaus", listed: false, detail: status || "unknown" };
  } catch {
    return { source: "URLhaus", listed: false, detail: "error" };
  }
}

/** abuse.ch ThreatFox — free IOC search (host or url hash). */
async function queryThreatFox(host: string): Promise<SourceHit> {
  try {
    const res = await throttledFetch("threatfox", "https://threatfox-api.abuse.ch/api/v1/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        query: "search_ioc",
        search_term: host,
      }),
    });
    if (!res.ok) {
      return { source: "ThreatFox", listed: false, detail: `http_${res.status}` };
    }
    const data = (await res.json()) as {
      query_status?: string;
      data?: unknown[] | null;
    };
    if (data.query_status === "no_result") {
      return { source: "ThreatFox", listed: false, detail: "no_result" };
    }
    if (data.query_status === "ok" && Array.isArray(data.data) && data.data.length > 0) {
      return {
        source: "ThreatFox",
        listed: true,
        detail: `${data.data.length} IOC hit(s)`,
        url: `https://threatfox.abuse.ch/browse.php?search=ioc%3A${encodeURIComponent(host)}`,
      };
    }
    return { source: "ThreatFox", listed: false, detail: data.query_status ?? "unknown" };
  } catch {
    return { source: "ThreatFox", listed: false, detail: "error" };
  }
}

/** OpenPhish community feed (public text list of phish URLs/hosts). */
let openphishHosts: Set<string> | null = null;
let openphishAt = 0;

async function loadOpenPhishHosts(): Promise<Set<string>> {
  const now = Date.now();
  if (openphishHosts && now - openphishAt < 6 * 60 * 60 * 1000) return openphishHosts;
  try {
    const res = await throttledFetch(
      "openphish",
      "https://openphish.com/feed.txt",
    );
    if (!res.ok) return openphishHosts ?? new Set();
    const text = await res.text();
    const hosts = new Set<string>();
    for (const line of text.split("\n")) {
      const u = line.trim();
      if (!u || !/^https?:\/\//i.test(u)) continue;
      try {
        hosts.add(new URL(u).hostname.toLowerCase());
      } catch {
        /* skip */
      }
    }
    openphishHosts = hosts;
    openphishAt = now;
    return hosts;
  } catch {
    return openphishHosts ?? new Set();
  }
}

async function queryOpenPhish(host: string): Promise<SourceHit> {
  try {
    const hosts = await loadOpenPhishHosts();
    if (!hosts.size) {
      return { source: "OpenPhish", listed: false, detail: "feed_unavailable" };
    }
    const listed = hosts.has(host) || [...hosts].some((h) => host.endsWith(`.${h}`));
    return {
      source: "OpenPhish",
      listed,
      detail: listed ? "in community phish feed" : "not_in_feed",
      url: listed ? `https://openphish.com/` : undefined,
    };
  } catch {
    return { source: "OpenPhish", listed: false, detail: "error" };
  }
}

export async function lookupThreatIntel(
  hostname: string,
  fullUrl?: string,
  enabled = true,
): Promise<ThreatIntelReport> {
  if (!enabled) {
    return { status: "skipped", sources: [], listedBy: [], cached: false };
  }
  const host = hostname.toLowerCase().replace(/\.$/, "");
  const cached = memory.get(host);
  if (cached && Date.now() - cached.at < TTL_MS) {
    return { ...cached.value, cached: true };
  }

  const [urlhaus, threatfox, openphish] = await Promise.all([
    queryUrlhaus(host, fullUrl),
    queryThreatFox(host),
    queryOpenPhish(host),
  ]);

  const sources = [urlhaus, threatfox, openphish];
  const listedBy = sources.filter((s) => s.listed).map((s) => s.source);
  const errors = sources.filter((s) => s.detail === "error" || String(s.detail).startsWith("http_"));

  let status: IntelStatus;
  if (listedBy.length > 0) status = "listed";
  else if (errors.length === sources.length) status = "error";
  else status = "clean";

  const value: ThreatIntelReport = {
    status,
    sources,
    listedBy,
    cached: false,
  };
  memory.set(host, { at: Date.now(), value });
  persistDisk();
  return value;
}

export function clearIntelCache(): void {
  memory.clear();
  openphishHosts = null;
  try {
    if (fs.existsSync(DISK)) fs.unlinkSync(DISK);
  } catch {
    /* ignore */
  }
}

export function intelCacheSize(): number {
  return memory.size;
}
