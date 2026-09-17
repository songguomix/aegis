import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { SessionTrustEntry } from "../types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..", "..");
const DATA_DIR = process.env.AEGIS_DATA_DIR
  ? path.resolve(process.env.AEGIS_DATA_DIR)
  : path.join(ROOT, ".aegis");
const FILE = path.join(DATA_DIR, "session-trust.json");

const entries = new Map<string, SessionTrustEntry>();

/** Hostname-like: labels + dots, optional trailing dot. No scheme/path/space. */
const HOST_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

export function isValidHostname(raw: string): boolean {
  const host = String(raw ?? "")
    .trim()
    .toLowerCase()
    .replace(/^\./, "")
    .replace(/\.$/, "");
  if (!host || host.includes("://") || /\s/.test(host) || host.includes("/")) {
    return false;
  }
  // allow single-label localhost-style and .example TLDs
  if (host === "localhost") return true;
  return HOST_RE.test(host) || /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(host);
}

function persist(): void {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(FILE, JSON.stringify([...entries.values()], null, 2), "utf8");
  } catch {
    /* ignore */
  }
}

function load(): void {
  try {
    if (!fs.existsSync(FILE)) return;
    const raw = JSON.parse(fs.readFileSync(FILE, "utf8")) as SessionTrustEntry[];
    for (const e of raw) entries.set(e.hostname.toLowerCase(), e);
  } catch {
    /* ignore */
  }
}

load();

function normalize(host: string): string {
  return host.trim().toLowerCase().replace(/^\./, "").replace(/\.$/, "");
}

export function trustDomain(
  hostname: string,
  opts: { reason?: string; source?: SessionTrustEntry["source"] } = {},
): SessionTrustEntry {
  if (!isValidHostname(hostname)) {
    throw Object.assign(new Error("invalid_hostname"), { code: "invalid_hostname" });
  }
  const host = normalize(hostname);
  const entry: SessionTrustEntry = {
    hostname: host,
    addedAt: new Date().toISOString(),
    reason: opts.reason,
    source: opts.source ?? "agent",
  };
  entries.set(host, entry);
  persist();
  return entry;
}

export function untrustDomain(hostname: string): boolean {
  const ok = entries.delete(normalize(hostname));
  persist();
  return ok;
}

export function isTrusted(hostname: string): boolean {
  return entries.has(normalize(hostname));
}

export function listTrust(): SessionTrustEntry[] {
  return [...entries.values()].sort((a, b) => b.addedAt.localeCompare(a.addedAt));
}

export function clearTrust(): void {
  entries.clear();
  persist();
}