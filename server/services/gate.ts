import { randomUUID } from "node:crypto";
import type {
  Decision,
  EngineConfig,
  GateResult,
  Reason,
} from "../types.js";
import { buildAuthority } from "./authority.js";
import { lookupDomainVt } from "./virustotal.js";
import { normalizeHostname } from "./registry.js";

export function parseUrl(input: string): { ok: true; url: URL; hostname: string } | { ok: false; error: string } {
  const trimmed = input.trim();
  if (!trimmed) return { ok: false, error: "Empty URL" };
  let candidate = trimmed;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(candidate)) {
    candidate = `https://${candidate}`;
  }
  try {
    const url = new URL(candidate);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return { ok: false, error: `Unsupported protocol: ${url.protocol}` };
    }
    if (!url.hostname || !url.hostname.includes(".")) {
      return { ok: false, error: "Invalid hostname" };
    }
    return { ok: true, url, hostname: normalizeHostname(url.hostname) };
  } catch {
    return { ok: false, error: "Invalid URL" };
  }
}

function clamp(n: number, min = 0, max = 100): number {
  return Math.max(min, Math.min(max, n));
}

export interface GateOptions {
  context?: string;
  /** Skip VirusTotal lookup (authority-only, e.g. MCP verify_domain). */
  skipVt?: boolean;
}

export async function runGate(
  rawUrl: string,
  config: EngineConfig,
  contextOrOptions?: string | GateOptions,
): Promise<GateResult> {
  const options: GateOptions =
    typeof contextOrOptions === "string"
      ? { context: contextOrOptions }
      : (contextOrOptions ?? {});
  const context = options.context;
  const parsed = parseUrl(rawUrl);
  if (!parsed.ok) {
    return {
      id: `chk_${randomUUID().slice(0, 8)}`,
      url: rawUrl,
      hostname: "",
      decision: "block",
      score: 0,
      reasons: [
        {
          code: "invalid_url",
          severity: "critical",
          message: parsed.error,
        },
      ],
      authority: {
        official: false,
        brand: null,
        subject: null,
        category: null,
        rdap: { status: "skipped", registrant: null, organization: null },
        lookalikeOf: null,
        punycode: false,
        mixedScript: false,
        allowlisted: false,
        denylisted: false,
      },
      virusTotal: {
        status: "degraded",
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        reputation: null,
        categories: [],
        cached: false,
        permalink: null,
      },
      checkedAt: new Date().toISOString(),
      context,
    };
  }

  const { hostname } = parsed;
  const { report: authority, reasons } = await buildAuthority(hostname, config);
  const vt = options.skipVt
    ? {
        status: "degraded" as const,
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        reputation: null,
        categories: [] as string[],
        cached: false,
        permalink: null,
      }
    : await lookupDomainVt(hostname, config.vtApiKey, config.vtCacheTtlMs);

  if (options.skipVt) {
    reasons.push({
      code: "vt_skipped",
      severity: "info",
      message: "VirusTotal lookup skipped (authority-only check).",
    });
  } else if (vt.status === "malicious") {
    reasons.push({
      code: "vt_malicious",
      severity: "critical",
      message: `VirusTotal reports ${vt.malicious} malicious / ${vt.suspicious} suspicious engines.`,
    });
  } else if (vt.status === "suspicious") {
    reasons.push({
      code: "vt_suspicious",
      severity: "warn",
      message: `VirusTotal flags ${vt.suspicious} suspicious detections.`,
    });
  } else if (vt.status === "clean") {
    reasons.push({
      code: "vt_clean",
      severity: "info",
      message: `VirusTotal: clean (${vt.harmless} harmless${vt.cached ? ", cached" : ""}).`,
    });
  } else if (vt.status === "degraded") {
    reasons.push({
      code: "vt_degraded",
      severity: "warn",
      message: "VirusTotal unavailable (no API key or rate-limited). Authority checks still applied.",
    });
  } else if (vt.status === "unknown") {
    reasons.push({
      code: "vt_unknown",
      severity: "warn",
      message: "No VirusTotal record for this domain yet.",
    });
  } else if (vt.status === "error") {
    reasons.push({
      code: "vt_error",
      severity: "warn",
      message: "VirusTotal lookup failed.",
    });
  }

  const decision = decide(authority, vt.status, config, reasons);
  const score = scoreOf(decision, authority, vt.status, reasons);

  return {
    id: `chk_${randomUUID().slice(0, 8)}`,
    url: parsed.url.toString(),
    hostname,
    decision,
    score,
    reasons,
    authority,
    virusTotal: vt,
    checkedAt: new Date().toISOString(),
    context,
  };
}

function decide(
  authority: GateResult["authority"],
  vtStatus: GateResult["virusTotal"]["status"],
  config: EngineConfig,
  reasons: Reason[],
): Decision {
  // Observe mode: never hard-block except denylist/invalid already handled
  const hardBlockSignals =
    authority.denylisted ||
    vtStatus === "malicious" ||
    (authority.lookalikeOf !== null && !authority.allowlisted && authority.official === false && reasons.some((r) => r.code === "lookalike_domain" && r.severity === "critical"));

  if (config.policyMode === "observe") {
    if (authority.denylisted || vtStatus === "malicious") return "block";
    if (hardBlockSignals || vtStatus === "suspicious" || authority.lookalikeOf) return "review";
    return "allow";
  }

  if (hardBlockSignals) return "block";

  if (config.policyMode === "strict") {
    if (authority.allowlisted && (vtStatus === "clean" || vtStatus === "degraded")) return "allow";
    if (authority.official && vtStatus === "clean") return "allow";
    if (authority.official && vtStatus === "degraded") return "allow";
    return "block";
  }

  // tri-state (default)
  const vt = vtStatus as string;
  if (authority.allowlisted && vt !== "malicious" && vt !== "suspicious") {
    return "allow";
  }
  if (authority.official && (vtStatus === "clean" || vtStatus === "degraded" || vtStatus === "unknown")) {
    // official + clean (or no VT data but known brand) → allow
    if (vtStatus === "clean" || vtStatus === "degraded") return "allow";
    return "review";
  }
  if (vtStatus === "suspicious") return "review";
  if (authority.lookalikeOf) return "block";
  if (authority.punycode || authority.mixedScript) return "review";

  // Unknown domain, no hard signal → review
  return "review";
}

function scoreOf(
  decision: Decision,
  authority: GateResult["authority"],
  vtStatus: GateResult["virusTotal"]["status"],
  reasons: Reason[],
): number {
  let score = 50;
  if (authority.official) score += 30;
  if (authority.allowlisted) score += 25;
  if (authority.denylisted) score -= 50;
  if (authority.lookalikeOf) score -= 35;
  if (authority.punycode) score -= 15;
  if (authority.mixedScript) score -= 10;
  if (vtStatus === "clean") score += 20;
  if (vtStatus === "malicious") score -= 60;
  if (vtStatus === "suspicious") score -= 25;
  if (vtStatus === "unknown") score -= 5;
  if (vtStatus === "degraded") score -= 5;
  for (const r of reasons) {
    if (r.severity === "critical") score -= 10;
    if (r.severity === "warn") score -= 3;
  }
  if (decision === "allow") score = Math.max(score, 70);
  if (decision === "block") score = Math.min(score, 25);
  return clamp(Math.round(score));
}
