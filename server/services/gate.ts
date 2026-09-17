import { randomUUID } from "node:crypto";
import type {
  Decision,
  EngineConfig,
  GateResult,
  Reason,
} from "../types.js";
import { buildAuthority } from "./authority.js";
import { lookupDomainVt } from "./virustotal.js";
import { lookupThreatIntel } from "./threatIntel.js";
import { normalizeHostname } from "./registry.js";
import { isTrusted } from "./sessionTrust.js";

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
  /** Skip free threat intel (offline unit tests). */
  skipIntel?: boolean;
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
  const sessionTrusted = isTrusted(hostname);
  authority.sessionTrusted = sessionTrusted;
  if (sessionTrusted) {
    reasons.push({
      code: "session_trust",
      severity: "info",
      message: `Session-trusted host (${hostname}). Human/agent already allowed this host in Aegis.`,
    });
  }
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

  const intel =
    options.skipVt || options.skipIntel
      ? { status: "skipped" as const, sources: [], listedBy: [], cached: false }
      : await lookupThreatIntel(hostname, parsed.url.toString());

  if (intel.status === "listed") {
    reasons.push({
      code: "threat_intel_listed",
      severity: "critical",
      message: `Listed on free threat intel: ${intel.listedBy.join(", ")}.`,
    });
    for (const s of intel.sources.filter((x) => x.listed)) {
      reasons.push({
        code: `intel_${s.source.toLowerCase().replace(/\s+/g, "_")}`,
        severity: "critical",
        message: `${s.source}: ${s.detail ?? "listed"}`,
      });
    }
  } else if (intel.status === "clean") {
    reasons.push({
      code: "threat_intel_clean",
      severity: "info",
      message: `Free intel clean (URLhaus / ThreatFox / OpenPhish)${intel.cached ? ", cached" : ""}.`,
    });
  } else if (intel.status === "unknown") {
    reasons.push({
      code: "threat_intel_partial",
      severity: "info",
      message:
        "Some free intel feeds unavailable; remaining sources found no list. Not treated as full clean.",
    });
  } else if (intel.status === "error") {
    reasons.push({
      code: "threat_intel_error",
      severity: "info",
      message: "Free threat intel feeds unavailable; relying on authority + VirusTotal.",
    });
  }

  const decision = decide(authority, vt.status, config, reasons, intel.status);
  const score = scoreOf(decision, authority, vt.status, reasons, intel.status);

  const result: GateResult = {
    id: `chk_${randomUUID().slice(0, 8)}`,
    url: parsed.url.toString(),
    hostname,
    decision,
    score,
    reasons,
    authority,
    virusTotal: vt,
    threatIntel: intel,
    checkedAt: new Date().toISOString(),
    context,
  };

  if (decision === "review") {
    const { enqueueReview } = await import("./reviewQueue.js");
    const item = enqueueReview(result);
    result.reviewId = item.id;
    result.reviewHint =
      "Agent Guard: decision=review — do NOT visit. Ask the human, then resolve_review. After allow you may call trust_domain(hostname) for this session.";
    reasons.push({
      code: "review_required",
      severity: "warn",
      message: `Queued for review ${item.id}. Waiting for human/agent approval before continuing.`,
    });
  }

  return result;
}

function decide(
  authority: GateResult["authority"],
  vtStatus: GateResult["virusTotal"]["status"],
  config: EngineConfig,
  reasons: Reason[],
  intelStatus?: string,
): Decision {
  const intelListed = intelStatus === "listed";
  const sessionTrusted = Boolean(authority.sessionTrusted);
  const hardBlockSignals =
    authority.denylisted ||
    vtStatus === "malicious" ||
    intelListed ||
    (authority.lookalikeOf !== null &&
      !authority.allowlisted &&
      !sessionTrusted &&
      authority.official === false &&
      reasons.some((r) => r.code === "lookalike_domain" && r.severity === "critical"));

  if (config.policyMode === "observe") {
    if (authority.denylisted || vtStatus === "malicious" || intelListed) return "block";
    if (hardBlockSignals || vtStatus === "suspicious" || authority.lookalikeOf) return "review";
    return "allow";
  }

  if (hardBlockSignals) return "block";

  // Session trust: already human-approved this session — allow unless hard danger
  if (sessionTrusted && !authority.denylisted) {
    if (vtStatus === "clean" || vtStatus === "degraded" || vtStatus === "unknown") {
      return "allow";
    }
    if (vtStatus === "suspicious") return "review";
    return "allow";
  }

  if (config.policyMode === "strict") {
    if (authority.allowlisted && (vtStatus === "clean" || vtStatus === "degraded")) return "allow";
    if (authority.official && vtStatus === "clean") return "allow";
    if (authority.official && vtStatus === "degraded") return "allow";
    return "block";
  }

  // tri-state (default)
  const vt = vtStatus as string;
  if (authority.allowlisted && vt !== "malicious" && vt !== "suspicious" && !intelListed) {
    return "allow";
  }
  if (
    authority.official &&
    (vtStatus === "clean" || vtStatus === "degraded" || vtStatus === "unknown")
  ) {
    if (intelListed) return "block";
    if (vtStatus === "clean" || vtStatus === "degraded") return "allow";
    return "review";
  }
  if (vtStatus === "suspicious") return "review";
  if (authority.lookalikeOf) return "block";
  if (authority.punycode || authority.mixedScript) return "review";

  return "review";
}

function scoreOf(
  decision: Decision,
  authority: GateResult["authority"],
  vtStatus: GateResult["virusTotal"]["status"],
  reasons: Reason[],
  intelStatus?: string,
): number {
  let score = 50;
  if (authority.official) score += 30;
  if (authority.allowlisted) score += 25;
  if (authority.sessionTrusted) score += 20;
  if (authority.denylisted) score -= 50;
  if (authority.lookalikeOf) score -= 35;
  if (authority.punycode) score -= 15;
  if (authority.mixedScript) score -= 10;
  if (vtStatus === "clean") score += 20;
  if (vtStatus === "malicious") score -= 60;
  if (vtStatus === "suspicious") score -= 25;
  if (vtStatus === "unknown") score -= 5;
  if (vtStatus === "degraded") score -= 5;
  if (intelStatus === "listed") score -= 55;
  if (intelStatus === "clean") score += 10;
  for (const r of reasons) {
    if (r.severity === "critical") score -= 10;
    if (r.severity === "warn") score -= 3;
  }
  if (decision === "allow") score = Math.max(score, 70);
  if (decision === "block") score = Math.min(score, 25);
  return clamp(Math.round(score));
}
