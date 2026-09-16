export type Decision = "allow" | "review" | "block";

export interface Reason {
  code: string;
  severity: "info" | "warn" | "critical";
  message: string;
}

export interface GateResult {
  id: string;
  url: string;
  hostname: string;
  decision: Decision;
  score: number;
  reasons: Reason[];
  authority: {
    official: boolean;
    brand: string | null;
    subject: string | null;
    category: string | null;
    rdap: {
      status: string;
      registrant: string | null;
      organization: string | null;
    };
    lookalikeOf: string | null;
    punycode: boolean;
    mixedScript: boolean;
    allowlisted: boolean;
    denylisted: boolean;
  };
  virusTotal: {
    status: string;
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
    reputation: number | null;
    categories: string[];
    cached: boolean;
    permalink: string | null;
  };
  checkedAt: string;
  context?: string;
}

export interface EngineConfigView {
  vtApiKey: string | null;
  hasVtKey: boolean;
  policyMode: "tri" | "strict" | "observe";
  language: "en" | "zh";
  enableRdap: boolean;
  allowlist: string[];
  denylist: string[];
  vtCacheTtlMs: number;
  rdapTimeoutMs: number;
  httpPort: number;
}

export interface Health {
  ok: boolean;
  service: string;
  version: string;
  stats: {
    total: number;
    allow: number;
    review: number;
    block: number;
    vtMode: "live" | "degraded";
  };
  vtCache: number;
  policyMode: string;
}

const FALLBACK = "http://127.0.0.1:7832/api/v1";

async function apiBase(): Promise<string> {
  const w = window as unknown as { aegis?: { getApiBase?: () => Promise<string> } };
  if (w.aegis?.getApiBase) {
    try {
      return await w.aegis.getApiBase();
    } catch {
      /* fall through */
    }
  }
  return import.meta.env.DEV ? "/api/v1" : FALLBACK;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const base = await apiBase();
  const url = `${base}${path}`;
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    ...init,
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(body || `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => request<Health>("/health"),
  check: (url: string, context?: string) =>
    request<GateResult>("/check", {
      method: "POST",
      body: JSON.stringify({ url, context }),
    }),
  history: (limit = 100) =>
    request<{ items: GateResult[] }>(`/history?limit=${limit}`),
  clearHistory: () => request<{ ok: boolean }>("/history", { method: "DELETE" }),
  config: () => request<EngineConfigView>("/config"),
  saveConfig: (patch: Partial<EngineConfigView> & { vtApiKey?: string | null }) =>
    request<EngineConfigView>("/config", {
      method: "PUT",
      body: JSON.stringify(patch),
    }),
};
