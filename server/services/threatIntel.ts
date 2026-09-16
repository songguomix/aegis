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
const TTL_MS = 6 * 60 * 60 * 1000;
const FEED_TTL_MS = 6 * 60 * 60 * 1000;

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

async function fetchText(url: string, timeoutMs = 15000): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "Aegis-Security-Gateway/0.1 (+local-ai-agent-gate)",
        Accept: "text/plain, application/json;q=0.9, */*;q=0.8",
      },
    });
    if (!res.ok) throw new Error(`http_${res.status}`);
    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

interface FeedState {
  hosts: Set<string>;
  at: number;
  ok: boolean;
  error?: string;
}

const feeds: Record<string, FeedState> = {};

async function loadFeed(
  key: string,
  url: string,
  parse: (text: string) => Set<string>,
): Promise<FeedState> {
  const existing = feeds[key];
  if (existing && Date.now() - existing.at < FEED_TTL_MS) return existing;
  try {
    const text = await fetchText(url);
    const hosts = parse(text);
    const state: FeedState = { hosts, at: Date.now(), ok: hosts.size > 0 };
    feeds[key] = state;
    persistFeedState();
    return state;
  } catch (e) {
    const state: FeedState = {
      hosts: existing?.hosts ?? new Set(),
      at: Date.now(),
      ok: (existing?.hosts.size ?? 0) > 0,
      error: e instanceof Error ? e.message : "error",
    };
    feeds[key] = state;
    return state;
  }
}

function persistFeedState(): void {
  try {
    const file = path.join(DATA_DIR, "intel-feeds.json");
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const obj: Record<string, { hosts: string[]; at: number }> = {};
    for (const [k, v] of Object.entries(feeds)) {
      if (v.ok) obj[k] = { hosts: [...v.hosts].slice(0, 200000), at: v.at };
    }
    fs.writeFileSync(file, JSON.stringify(obj), "utf8");
  } catch {
    /* ignore */
  }
}

function restoreFeedState(): void {
  try {
    const file = path.join(DATA_DIR, "intel-feeds.json");
    if (!fs.existsSync(file)) return;
    const raw = JSON.parse(fs.readFileSync(file, "utf8")) as Record<
      string,
      { hosts: string[]; at: number }
    >;
    for (const [k, v] of Object.entries(raw)) {
      if (Date.now() - v.at < 24 * 60 * 60 * 1000) {
        feeds[k] = { hosts: new Set(v.hosts), at: v.at, ok: true };
      }
    }
  } catch {
    /* ignore */
  }
}

restoreFeedState();

function hostFromLine(line: string): string | null {
  const t = line.trim().toLowerCase();
  if (!t || t.startsWith("#")) return null;
  // host-only dump
  if (/^[a-z0-9.-]+$/.test(t) && t.includes(".")) return t.replace(/^\./, "");
  try {
    const u = new URL(t);
    return u.hostname.toLowerCase();
  } catch {
    return null;
  }
}

/** Public malware host dump (no Auth-Key). */
async function urlhausFeed(host: string): Promise<SourceHit> {
  const state = await loadFeed(
    "urlhaus",
    "https://urlhaus.abuse.ch/downloads/hostfile/",
    (text) => {
      const set = new Set<string>();
      for (const line of text.split("\n")) {
        // hostfile: may start with #
        const cleaned = line.replace(/^#\s*/, "");
        const h = hostFromLine(cleaned.split(/\s+/)[0] ?? "");
        if (h) set.add(h);
      }
      return set;
    },
  );
  if (!state.ok && state.error) {
    return { source: "URLhaus", listed: false, detail: state.error };
  }
  const listed =
    state.hosts.has(host) ||
    [...state.hosts].some((h) => host === h || host.endsWith(`.${h}`));
  return {
    source: "URLhaus",
    listed,
    detail: listed
      ? "in public malware host dump"
      : state.ok
        ? `not_listed (${state.hosts.size} hosts)`
        : "feed_unavailable",
    url: listed ? `https://urlhaus.abuse.ch/host/${host}/` : undefined,
  };
}

/** Public ThreatFox recent URL IOC export. */
async function threatFoxFeed(host: string): Promise<SourceHit> {
  const state = await loadFeed(
    "threatfox",
    "https://threatfox.abuse.ch/export/json/urls/recent/",
    (text) => {
      const set = new Set<string>();
      try {
        const data = JSON.parse(text) as Array<Record<string, unknown>>;
        for (const row of data) {
          const ioc = String(row.ioc ?? "");
          const h = hostFromLine(ioc);
          if (h) set.add(h);
        }
      } catch {
        // fallback: scan host-like tokens
        for (const line of text.split(/[\s,}"]+/)) {
          const h = hostFromLine(line);
          if (h) set.add(h);
        }
      }
      return set;
    },
  );
  if (!state.ok && state.error) {
    return { source: "ThreatFox", listed: false, detail: state.error };
  }
  const listed =
    state.hosts.has(host) ||
    [...state.hosts].some((h) => host.endsWith(`.${h}`));
  return {
    source: "ThreatFox",
    listed,
    detail: listed
      ? "in recent URL IOC export"
      : state.ok
        ? `not_listed (${state.hosts.size} hosts)`
        : "feed_unavailable",
    url: listed
      ? `https://threatfox.abuse.ch/browse.php?search=ioc%3A${encodeURIComponent(host)}`
      : undefined,
  };
}

async function openPhishFeed(host: string): Promise<SourceHit> {
  const state = await loadFeed("openphish", "https://openphish.com/feed.txt", (text) => {
    const set = new Set<string>();
    for (const line of text.split("\n")) {
      const h = hostFromLine(line);
      if (h) set.add(h);
    }
    return set;
  });
  if (!state.ok && state.error) {
    return { source: "OpenPhish", listed: false, detail: state.error };
  }
  const listed =
    state.hosts.has(host) ||
    [...state.hosts].some((h) => host.endsWith(`.${h}`));
  return {
    source: "OpenPhish",
    listed,
    detail: listed
      ? "in community phish feed"
      : state.ok
        ? `not_listed (${state.hosts.size} hosts)`
        : "feed_unavailable",
  };
}

export async function lookupThreatIntel(
  hostname: string,
  _fullUrl?: string,
  enabled = true,
): Promise<ThreatIntelReport> {
  if (!enabled) {
    return { status: "skipped", sources: [], listedBy: [], cached: false };
  }
  const host = hostname.toLowerCase().replace(/^\./, "").replace(/\.$/, "");
  const cached = memory.get(host);
  if (cached && Date.now() - cached.at < TTL_MS) {
    return { ...cached.value, cached: true };
  }

  const sources = await Promise.all([
    urlhausFeed(host),
    threatFoxFeed(host),
    openPhishFeed(host),
  ]);

  const listedBy = sources.filter((s) => s.listed).map((s) => s.source);
  const failed = sources.filter(
    (s) =>
      !s.listed &&
      (s.detail === "feed_unavailable" ||
        String(s.detail).startsWith("http_") ||
        s.detail === "aborted" ||
        s.detail === "error"),
  );

  let status: IntelStatus;
  if (listedBy.length > 0) status = "listed";
  else if (failed.length === sources.length) status = "error";
  else if (failed.length > 0) status = "unknown"; // partial coverage is not “clean”
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
  for (const k of Object.keys(feeds)) delete feeds[k];
  try {
    if (fs.existsSync(DISK)) fs.unlinkSync(DISK);
    const ff = path.join(DATA_DIR, "intel-feeds.json");
    if (fs.existsSync(ff)) fs.unlinkSync(ff);
  } catch {
    /* ignore */
  }
}

export function intelCacheSize(): number {
  return memory.size;
}

export function intelFeedStatus(): Record<
  string,
  { hosts: number; ageMinutes: number | null; error?: string }
> {
  const out: Record<string, { hosts: number; ageMinutes: number | null; error?: string }> = {};
  for (const [k, v] of Object.entries(feeds)) {
    out[k] = {
      hosts: v.hosts.size,
      ageMinutes: v.at ? Math.round((Date.now() - v.at) / 60000) : null,
      error: v.error,
    };
  }
  return out;
}
