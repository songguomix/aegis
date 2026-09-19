import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { CustomBrand, OfficialEntry } from "../types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function resolveDataPath(): string {
  const candidates = [
    path.join(__dirname, "..", "data", "official-domains.json"),
    path.join(__dirname, "..", "..", "server", "data", "official-domains.json"),
    path.join(__dirname, "..", "..", "..", "server", "data", "official-domains.json"),
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  return candidates[0];
}

const DATA_PATH = resolveDataPath();

let cache: Record<string, OfficialEntry> | null = null;
let custom: Record<string, OfficialEntry> = {};

export function setCustomBrands(list: CustomBrand[] | undefined): void {
  custom = {};
  const builtin = builtinMap();
  for (const b of list ?? []) {
    const host = normalizeHostname(b.host);
    if (!host || !b.brand) continue;
    if (host.includes("/") || host.includes("://") || /\s/.test(host)) continue;
    // Never override built-in official registry entries
    if (builtin[host]) continue;
    custom[host] = {
      brand: b.brand,
      subject: b.subject || b.brand,
      category: "custom",
    };
  }
}

export function loadOfficialMap(): Record<string, OfficialEntry> {
  if (cache) return cache;
  const raw = fs.readFileSync(DATA_PATH, "utf8");
  cache = JSON.parse(raw) as Record<string, OfficialEntry>;
  return cache;
}

export function normalizeHostname(host: string): string {
  return host.trim().toLowerCase().replace(/^\./, "").replace(/\.$/, "");
}

/** Built-in registry only (for lookalike base list). */
function builtinMap(): Record<string, OfficialEntry> {
  return loadOfficialMap();
}

/** Builtin wins; custom fills unknown hosts only. */
function mergedMap(): Record<string, OfficialEntry> {
  return { ...custom, ...builtinMap() };
}

/** Official entry for hostname or a parent domain match. */
export function lookupOfficial(hostname: string): {
  host: string;
  entry: OfficialEntry;
} | null {
  const map = mergedMap();
  const host = normalizeHostname(hostname);
  if (map[host]) return { host, entry: map[host] };

  const labels = host.split(".");
  for (let i = 1; i < labels.length - 1; i++) {
    const parent = labels.slice(i).join(".");
    if (map[parent]) return { host: parent, entry: map[parent] };
  }
  return null;
}

export function officialHostnames(): string[] {
  return Object.keys(mergedMap()).sort();
}

export function brandKeys(): { brand: string; hosts: string[]; category?: string }[] {
  const map = mergedMap();
  const byBrand = new Map<string, string[]>();
  for (const [host, entry] of Object.entries(map)) {
    const list = byBrand.get(entry.brand) ?? [];
    list.push(host);
    byBrand.set(entry.brand, list);
  }
  return [...byBrand.entries()]
    .map(([brand, hosts]) => ({
      brand,
      hosts: hosts.sort(),
      category: map[hosts[0]]?.category,
    }))
    .sort((a, b) => a.brand.localeCompare(b.brand));
}