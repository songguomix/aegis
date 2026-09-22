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
  sessionTrusted?: boolean;
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
  /** When decision=review, pending review id for human/agent approval */
  reviewId?: string;
  reviewHint?: string;
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
  analysisId?: string;
  uploaded?: boolean;
  bytes?: number;
  sha256?: string;
}

export interface CustomBrand {
  host: string;
  brand: string;
  subject: string;
}

export interface SessionTrustEntry {
  hostname: string;
  addedAt: string;
  reason?: string;
  source: "user" | "agent" | "resolve";
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
  soundEnabled: boolean;
  /** Max bytes for VirusTotal file upload scan (default 32MB) */
  maxUploadBytes: number;
  /** Operator-defined official hosts: host → brand/subject */
  customBrands: CustomBrand[];
}

export const DEFAULT_CONFIG: EngineConfig = {
  vtApiKey: null,
  policyMode: "tri",
  language: "en",
  enableRdap: true,
  allowlist: [],
  denylist: [],
  vtCacheTtlMs: 6 * 60 * 60 * 1000,
  rdapTimeoutMs: 1500,
  httpPort: 7832,
  soundEnabled: true,
  maxUploadBytes: 32 * 1024 * 1024,
  customBrands: [],
};
