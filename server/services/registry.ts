import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { OfficialEntry } from "../types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_PATH = path.join(__dirname, "..", "data", "official-domains.json");

let cache: Record<string, OfficialEntry> | null = null;

export function loadOfficialMap(): Record<string, OfficialEntry> {
  if (cache) return cache;
  const raw = fs.readFileSync(DATA_PATH, "utf8");
  cache = JSON.parse(raw) as Record<string, OfficialEntry>;
  return cache;
}

export function normalizeHostname(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, "");
}

/** Return official entry for hostname or a parent domain match. */
export function lookupOfficial(hostname: string): {
  host: string;
  entry: OfficialEntry;
} | null {
  const map = loadOfficialMap();
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
  return Object.keys(loadOfficialMap()).sort();
}

export function brandKeys(): { brand: string; hosts: string[] }[] {
  const map = loadOfficialMap();
  const byBrand = new Map<string, string[]>();
  for (const [host, entry] of Object.entries(map)) {
    const list = byBrand.get(entry.brand) ?? [];
    list.push(host);
    byBrand.set(entry.brand, list);
  }
  return [...byBrand.entries()]
    .map(([brand, hosts]) => ({ brand, hosts: hosts.sort() }))
    .sort((a, b) => a.brand.localeCompare(b.brand));
}
