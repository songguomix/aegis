export type Decision = "allow" | "review" | "block";

export type Severity = "info" | "warn" | "critical";

export interface Reason {
  code: string;
  severity: Severity;
  message: string;
}

export type VtStatus =
  | "clean"
  | "malicious"
  | "suspicious"
  | "unknown"
  | "degraded"
  | "error";

export type RdapStatus = "ok" | "skipped" | "error";

export interface OfficialEntry {
  brand: string;
  subject: string;
  category: string;
}

export interface AuthorityReport {
  official: boolean;
  brand: string | null;
  subject: string | null;
  category: string | null;
  rdap: {
    status: RdapStatus;
    registrant: string | null;
    organization: string | null;
  };
  lookalikeOf: string | null;
  punycode: boolean;
  mixedScript: boolean;
  allowlisted: boolean;
  denylisted: boolean;
}

export interface VirusTotalReport {
  status: VtStatus;
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  reputation: number | null;
  categories: string[];
  cached: boolean;
  permalink: string | null;
}

export interface SourceHit {
  source: string;
  listed: boolean;
  detail?: string;
  url?: string;
}

export interface ThreatIntelReport {
  status: "clean" | "listed" | "unknown" | "error" | "skipped";
  sources: SourceHit[];
  listedBy: string[];
  cached: boolean;
}

export interface GateResult {
  id: string;
  url: string;
  hostname: string;
  decision: Decision;
  score: number;
  reasons: Reason[];
  authority: AuthorityReport;
  virusTotal: VirusTotalReport;
  threatIntel?: ThreatIntelReport;
  checkedAt: string;
  context?: string;
  kind?: "url" | "file" | "batch";
  batch?: {
    total: number;
    allow: number;
    review: number;
    block: number;
  };
}

export interface FileGateResult {
  id: string;
  hash: string;
  hashType: "sha256" | "sha1" | "md5";
  fileName: string | null;
  decision: Decision;
  score: number;
  reasons: Reason[];
  virusTotal: VirusTotalReport;
  checkedAt: string;
  context?: string;
  kind: "file";
}

export interface EngineConfig {
  vtApiKey: string | null;
  policyMode: "tri" | "strict" | "observe";
  language: "en" | "zh";
  enableRdap: boolean;
  allowlist: string[];
  denylist: string[];
  vtCacheTtlMs: number;
  rdapTimeoutMs: number;
  httpPort: number;
}

export const DEFAULT_CONFIG: EngineConfig = {
  vtApiKey: null,
  policyMode: "tri",
  language: "en",
  enableRdap: true,
  allowlist: [],
  denylist: [],
  vtCacheTtlMs: 6 * 60 * 60 * 1000,
  rdapTimeoutMs: 3000,
  httpPort: 7832,
};
