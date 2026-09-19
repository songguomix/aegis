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
  threatIntel?: {
    status: string;
    listedBy: string[];
    cached: boolean;
    sources: {
      source: string;
      listed: boolean;
      detail?: string;
      url?: string;
    }[];
  };
  checkedAt: string;
  context?: string;
  kind?: "url" | "file" | "batch";
  reviewId?: string;
  reviewHint?: string;
}

export interface FileGateResult {
  id: string;
  hash: string;
  hashType: string;
  fileName: string | null;
  decision: Decision;
  score: number;
  reasons: Reason[];
  virusTotal: GateResult["virusTotal"];
  checkedAt: string;
  context?: string;
  kind: "file";
}

export interface BatchResult {
  decision: Decision;
  total: number;
  allow: number;
  review: number;
  block: number;
  results: GateResult[];
}

export interface IntegrationInfo {
  mcpCommand: string;
  mcpConfig: {
    mcpServers: Record<
      string,
      {
        command: string;
        args: string[];
      }
    >;
  };
  tools: {
    name: string;
    description: string;
    input: string[];
  }[];
  http: {
    base: string;
    checkUrl: string;
    statusUrl: string;
    example: {
      method: string;
      url: string;
      body: { url: string; context?: string };
    };
  };
  projectRoot: string;
  mcpEntry: string;
}

export interface DeployBundle {
  name: string;
  generatedAt: string;
  mcpEntry: string;
  mcpCommand: string;
  mcpConfig: { mcpServers: Record<string, { command: string; args: string[] }> };
  files: { filename: string; content: string; mediaType: string }[];
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
  soundEnabled?: boolean;
  customBrands?: CustomBrand[];
}

export interface SessionTrustEntry {
  hostname: string;
  addedAt: string;
  reason?: string;
  source: string;
}

export interface CustomBrand {
  host: string;
  brand: string;
  subject: string;
}

export interface AgentPolicy {
  name: string;
  version: string;
  rules: { id: string; text: string }[];
  mcpTools: string[];
  text: string;
  sessionTrusted?: SessionTrustEntry[];
  customBrands?: CustomBrand[];
}

export interface ReviewItem {
  id: string;
  createdAt: string;
  expiresAt: string;
  status: "pending" | "allowed" | "blocked" | "expired";
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
  reasons: Reason[];
  resolvedAt?: string;
  resolvedBy?: string;
  note?: string;
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
  reviews?: { pending: number; allowed: number; blocked: number };
  vtCache: number;
  policyMode: string;
}

const FALLBACK = "http://127.0.0.1:7832/api/v1";
let cachedToken: string | null = null;

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

export async function ensureApiToken(): Promise<string | null> {
  if (cachedToken) return cachedToken;
  const w = window as unknown as { aegis?: { getToken?: () => Promise<string | null> } };
  if (w.aegis?.getToken) {
    try {
      const t = await w.aegis.getToken();
      if (t) {
        cachedToken = t;
        return t;
      }
    } catch {
      /* fall through */
    }
  }
  try {
    const base = await apiBase();
    const res = await fetch(`${base}/session-token`);
    if (res.ok) {
      const d = (await res.json()) as { token?: string };
      if (d.token) {
        cachedToken = d.token;
        return d.token;
      }
    }
  } catch {
    /* ignore */
  }
  return null;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const base = await apiBase();
  const url = `${base}${path}`;
  const method = (init?.method ?? "GET").toUpperCase();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };
  if (method !== "GET" && method !== "HEAD") {
    const token = await ensureApiToken();
    if (token) headers["X-Aegis-Token"] = token;
  }
  const res = await fetch(url, { ...init, headers });
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
  integration: () => request<IntegrationInfo>("/integration"),
  checkFile: (hash: string, fileName?: string, context?: string) =>
    request<FileGateResult>("/check-file", {
      method: "POST",
      body: JSON.stringify({ hash, fileName, context }),
    }),
  checkBatch: (urls: string[], context?: string) =>
    request<BatchResult>("/check-batch", {
      method: "POST",
      body: JSON.stringify({ urls, context }),
    }),
  reviews: () => request<{ items: ReviewItem[]; stats: { pending: number; allowed: number; blocked: number } }>("/reviews"),
  resolveReview: (
    id: string,
    decision: "allow" | "block",
    opts?: {
      alwaysAllow?: boolean;
      note?: string;
      by?: "user" | "agent";
      sessionTrust?: boolean;
    },
  ) =>
    request<ReviewItem>(`/reviews/${id}/resolve`, {
      method: "POST",
      body: JSON.stringify({ decision, ...opts, by: opts?.by ?? "user" }),
    }),
  agentPolicy: () => request<AgentPolicy>("/agent-policy"),
  sessionTrust: () => request<{ items: SessionTrustEntry[] }>("/session-trust"),
  trustDomain: (hostname: string, reason?: string) =>
    request<SessionTrustEntry>("/session-trust", {
      method: "POST",
      body: JSON.stringify({ hostname, reason, source: "user" }),
    }),
  untrustDomain: (hostname: string) =>
    request<{ ok: boolean }>(
      `/session-trust/${encodeURIComponent(hostname)}`,
      { method: "DELETE" },
    ),
  clearSessionTrust: () =>
    request<{ ok: boolean; cleared: boolean }>("/session-trust/%2A", {
      method: "DELETE",
    }),
  mcpDeployBundle: () => request<DeployBundle>("/mcp-deploy/bundle"),
  mcpDeployZipUrl: async () => {
    const w = window as unknown as { aegis?: { getApiBase?: () => Promise<string> } };
    const base = w.aegis?.getApiBase
      ? await w.aegis.getApiBase()
      : import.meta.env.DEV
        ? "/api/v1"
        : "http://127.0.0.1:7832/api/v1";
    return `${base}/mcp-deploy/bundle.zip`;
  },
};
