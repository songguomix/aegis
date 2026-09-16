import type { AuthorityReport, EngineConfig, Reason } from "../types.js";
import { lookupOfficial, officialHostnames, normalizeHostname } from "./registry.js";
import {
  detectLookalike,
  hasMixedScript,
  isPunycode,
  suspiciousTld,
} from "./lookalike.js";
import { fetchRdap } from "./rdap.js";

export async function buildAuthority(
  hostname: string,
  config: EngineConfig,
): Promise<{ report: AuthorityReport; reasons: Reason[] }> {
  const host = normalizeHostname(hostname);
  const official = lookupOfficial(host);
  const allowlisted = config.allowlist.some((d) => host === normalizeHostname(d) || host.endsWith(`.${normalizeHostname(d)}`));
  const denylisted = config.denylist.some((d) => host === normalizeHostname(d) || host.endsWith(`.${normalizeHostname(d)}`));

  const look = detectLookalike(host, officialHostnames());
  const puny = isPunycode(host);
  const mixed = hasMixedScript(host);
  const badTld = suspiciousTld(host);

  const rdap = await fetchRdap(host, config.rdapTimeoutMs, config.enableRdap && !official);

  const reasons: Reason[] = [];

  if (denylisted) {
    reasons.push({
      code: "denylisted",
      severity: "critical",
      message: `Hostname ${host} is on the operator denylist.`,
    });
  }
  if (allowlisted) {
    reasons.push({
      code: "allowlisted",
      severity: "info",
      message: `Hostname ${host} is on the operator allowlist.`,
    });
  }
  if (official) {
    reasons.push({
      code: "official_domain",
      severity: "info",
      message: `Matched official registry: ${official.entry.brand} — ${official.entry.subject}`,
    });
  }
  if (look.lookalikeOf && look.lookalikeOf !== official?.host && look.reason && look.reason !== "exact_official") {
    reasons.push({
      code: "lookalike_domain",
      severity: "critical",
      message: `Possible lookalike of ${look.lookalikeOf} (${look.reason}).`,
    });
  }
  if (puny) {
    reasons.push({
      code: "punycode",
      severity: "warn",
      message: "Hostname uses punycode (possible homograph attack).",
    });
  }
  if (mixed) {
    reasons.push({
      code: "mixed_script",
      severity: "warn",
      message: "Hostname mixes Latin and non-Latin scripts.",
    });
  }
  if (badTld) {
    reasons.push({
      code: "suspicious_tld",
      severity: "warn",
      message: `TLD .${badTld} is frequently abused; treat with caution.`,
    });
  }
  if (rdap.status === "ok") {
    const subject = rdap.organization || rdap.registrant;
    if (official && subject) {
      const s = subject.toLowerCase();
      const expected = official.entry.subject.toLowerCase();
      const brand = official.entry.brand.toLowerCase().replace(/[^a-z0-9]/g, "");
      const subjectNorm = s.replace(/[^a-z0-9]/g, "");
      const match =
        s.includes(expected.split(/[ ,]/)[0]) ||
        subjectNorm.includes(brand) ||
        expected.includes(s);
      if (!match) {
        reasons.push({
          code: "subject_mismatch",
          severity: "warn",
          message: `RDAP subject "${subject}" does not clearly match expected "${official.entry.subject}".`,
        });
      } else {
        reasons.push({
          code: "subject_confirmed",
          severity: "info",
          message: `RDAP subject confirms ${subject}.`,
        });
      }
    } else if (subject) {
      reasons.push({
        code: "rdap_subject",
        severity: "info",
        message: `RDAP registrant: ${subject}.`,
      });
    }
  } else if (rdap.status === "error") {
    reasons.push({
      code: "rdap_unavailable",
      severity: "info",
      message: "RDAP lookup unavailable; relying on static authority checks.",
    });
  } else if (rdap.status === "skipped") {
    reasons.push({
      code: "rdap_skipped",
      severity: "info",
      message: "RDAP lookup skipped.",
    });
  }

  const report: AuthorityReport = {
    official: Boolean(official),
    brand: official?.entry.brand ?? null,
    subject: official?.entry.subject ?? null,
    category: official?.entry.category ?? null,
    rdap: {
      status: rdap.status,
      registrant: rdap.registrant,
      organization: rdap.organization,
    },
    lookalikeOf:
      look.lookalikeOf && look.lookalikeOf !== official?.host ? look.lookalikeOf : null,
    punycode: puny,
    mixedScript: mixed,
    allowlisted,
    denylisted,
  };

  return { report, reasons };
}
