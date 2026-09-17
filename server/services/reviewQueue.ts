import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import type { GateResult } from "../types.js";

export type ReviewStatus = "pending" | "allowed" | "blocked" | "expired";

export interface ReviewItem {
  id: string;
  createdAt: string;
  expiresAt: string;
  status: ReviewStatus;
  url: string;
  hostname: string;
  score: number;
  context?: string;
  summary: {
    official: boolean;
    brand: string | null;
    lookalikeOf: string | null;
    vtStatus: string;
    intelStatus: string;
  };
  reasons: GateResult["reasons"];
  resolvedAt?: string;
  resolvedBy?: "user" | "agent" | "system";
  note?: string;
}

const TTL_MS = 30 * 60 * 1000;
const MAX_ITEMS = 200;

const DATA_DIR = process.env.AEGIS_DATA_DIR
  ? path.resolve(process.env.AEGIS_DATA_DIR)
  : path.join(process.cwd(), ".aegis");
const FILE = path.join(DATA_DIR, "reviews.json");

const items = new Map<string, ReviewItem>();

function persist(): void {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(FILE, JSON.stringify([...items.values()], null, 2), "utf8");
  } catch {
    /* non-fatal */
  }
}

function load(): void {
  try {
    if (!fs.existsSync(FILE)) return;
    const raw = JSON.parse(fs.readFileSync(FILE, "utf8")) as ReviewItem[];
    for (const it of raw) items.set(it.id, it);
  } catch {
    /* ignore */
  }
}

load();

function expireStale(): void {
  const now = Date.now();
  for (const it of items.values()) {
    if (it.status === "pending" && Date.parse(it.expiresAt) < now) {
      it.status = "expired";
      it.resolvedAt = new Date().toISOString();
      it.resolvedBy = "system";
    }
  }
}

export function enqueueReview(result: GateResult): ReviewItem {
  expireStale();
  for (const it of items.values()) {
    if (
      it.status === "pending" &&
      it.hostname === result.hostname &&
      (it.context ?? "") === (result.context ?? "")
    ) {
      it.url = result.url;
      it.score = result.score;
      it.reasons = result.reasons;
      it.summary = {
        official: result.authority.official,
        brand: result.authority.brand,
        lookalikeOf: result.authority.lookalikeOf,
        vtStatus: result.virusTotal.status,
        intelStatus: result.threatIntel?.status ?? "skipped",
      };
      persist();
      return it;
    }
  }

  const now = Date.now();
  const item: ReviewItem = {
    id: `rev_${crypto.randomUUID().slice(0, 8)}`,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + TTL_MS).toISOString(),
    status: "pending",
    url: result.url,
    hostname: result.hostname,
    score: result.score,
    context: result.context,
    summary: {
      official: result.authority.official,
      brand: result.authority.brand,
      lookalikeOf: result.authority.lookalikeOf,
      vtStatus: result.virusTotal.status,
      intelStatus: result.threatIntel?.status ?? "skipped",
    },
    reasons: result.reasons,
  };
  items.set(item.id, item);
  if (items.size > MAX_ITEMS) {
    const oldest = [...items.values()]
      .filter((x) => x.status !== "pending")
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt))[0];
    if (oldest) items.delete(oldest.id);
  }
  persist();
  return item;
}

export function listReviews(includeResolved = false): ReviewItem[] {
  expireStale();
  const all = [...items.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  return includeResolved ? all : all.filter((i) => i.status === "pending");
}

export function getReview(id: string): ReviewItem | null {
  expireStale();
  return items.get(id) ?? null;
}

export function resolveReview(
  id: string,
  decision: "allow" | "block",
  opts: { by?: "user" | "agent"; note?: string } = {},
): ReviewItem | null {
  expireStale();
  const it = items.get(id);
  if (!it) return null;
  if (it.status !== "pending") return it;
  it.status = decision === "allow" ? "allowed" : "blocked";
  it.resolvedAt = new Date().toISOString();
  it.resolvedBy = opts.by ?? "agent";
  it.note = opts.note;
  persist();
  return it;
}

export function reviewStats(): { pending: number; allowed: number; blocked: number } {
  expireStale();
  let pending = 0;
  let allowed = 0;
  let blocked = 0;
  for (const it of items.values()) {
    if (it.status === "pending") pending++;
    else if (it.status === "allowed") allowed++;
    else if (it.status === "blocked") blocked++;
  }
  return { pending, allowed, blocked };
}
