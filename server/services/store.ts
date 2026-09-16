import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_CONFIG, type EngineConfig, type GateResult } from "../types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, "..", "..", ".aegis");
const CONFIG_PATH = path.join(DATA_DIR, "config.json");
const HISTORY_PATH = path.join(DATA_DIR, "history.json");

const MAX_HISTORY = 500;

let config: EngineConfig = { ...DEFAULT_CONFIG };
let history: GateResult[] = [];

function ensureDir(): void {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

export function loadStore(): void {
  ensureDir();
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      const raw = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8")) as Partial<EngineConfig>;
      config = { ...DEFAULT_CONFIG, ...raw };
    }
  } catch {
    config = { ...DEFAULT_CONFIG };
  }
  try {
    if (fs.existsSync(HISTORY_PATH)) {
      history = JSON.parse(fs.readFileSync(HISTORY_PATH, "utf8")) as GateResult[];
    }
  } catch {
    history = [];
  }
}

export function getConfig(): EngineConfig {
  return config;
}

export function updateConfig(patch: Partial<EngineConfig>): EngineConfig {
  config = { ...config, ...patch };
  ensureDir();
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), "utf8");
  return config;
}

export function appendHistory(result: GateResult): void {
  history.unshift(result);
  if (history.length > MAX_HISTORY) history = history.slice(0, MAX_HISTORY);
  ensureDir();
  fs.writeFileSync(HISTORY_PATH, JSON.stringify(history, null, 2), "utf8");
}

export function getHistory(limit = 100): GateResult[] {
  return history.slice(0, limit);
}

export function clearHistory(): void {
  history = [];
  ensureDir();
  fs.writeFileSync(HISTORY_PATH, "[]", "utf8");
}

export function stats(): {
  total: number;
  allow: number;
  review: number;
  block: number;
  vtMode: "live" | "degraded";
} {
  const allow = history.filter((h) => h.decision === "allow").length;
  const review = history.filter((h) => h.decision === "review").length;
  const block = history.filter((h) => h.decision === "block").length;
  return {
    total: history.length,
    allow,
    review,
    block,
    vtMode: config.vtApiKey ? "live" : "degraded",
  };
}
