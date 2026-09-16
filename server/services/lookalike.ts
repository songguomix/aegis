import { lookupOfficial, normalizeHostname } from "./registry.js";

const CYRILLIC_MAP: Record<string, string> = {
  а: "a",
  е: "e",
  о: "o",
  р: "p",
  с: "c",
  у: "y",
  х: "x",
  ѕ: "s",
  і: "i",
  ј: "j",
  ԁ: "d",
  ɡ: "g",
  ո: "n",
  հ: "h",
};

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  const prev = new Array(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
    }
    for (let j = 0; j <= b.length; j++) prev[j] = cur[j];
  }
  return prev[b.length];
}

export function isPunycode(hostname: string): boolean {
  return normalizeHostname(hostname).split(".").some((l) => l.startsWith("xn--"));
}

export function hasMixedScript(hostname: string): boolean {
  let hasLatin = false;
  let hasNonLatin = false;
  for (const ch of hostname) {
    if (/[a-z0-9.-]/i.test(ch)) hasLatin = true;
    else if (/[^\x00-\x7F]/.test(ch)) hasNonLatin = true;
  }
  return hasLatin && hasNonLatin;
}

function skeleton(host: string): string {
  let out = "";
  for (const ch of host.toLowerCase()) {
    out += CYRILLIC_MAP[ch] ?? ch;
  }
  return out.replace(/[^a-z0-9.]/g, "").replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e");
}

/** Second-level label for comparison, e.g. github.com → github */
function sld(host: string): string {
  const labels = normalizeHostname(host).split(".");
  if (labels.length < 2) return labels[0] ?? "";
  return labels[labels.length - 2];
}

export interface LookalikeFinding {
  lookalikeOf: string | null;
  distance: number;
  reason: string | null;
}

export function detectLookalike(
  hostname: string,
  candidateHosts: string[] = [],
): LookalikeFinding {
  const host = normalizeHostname(hostname);
  const officialHit = lookupOfficial(host);
  if (officialHit) {
    return { lookalikeOf: officialHit.host, distance: 0, reason: "exact_official" };
  }

  const hostSld = sld(host);
  const hostSk = skeleton(hostSld);
  let best: LookalikeFinding = { lookalikeOf: null, distance: Infinity, reason: null };

  const hosts = candidateHosts.length ? candidateHosts : [];
  for (const cand of hosts) {
    const candHost = normalizeHostname(cand);
    if (candHost === host) continue;
    const candSld = sld(candHost);
    if (!candSld || !hostSld) continue;

    const dist = levenshtein(hostSk, skeleton(candSld));
    // Strong signal: near-identical registrable label
    if (dist === 0 && candSld !== hostSld) {
      return {
        lookalikeOf: candHost,
        distance: 0,
        reason: "homograph_or_skeleton_match",
      };
    }
    if (dist === 1 && Math.min(hostSld.length, candSld.length) >= 5) {
      if (dist < best.distance) {
        best = { lookalikeOf: candHost, distance: dist, reason: "typosquat_distance_1" };
      }
    }
    if (dist === 2 && Math.min(hostSld.length, candSld.length) >= 10) {
      if (dist < best.distance) {
        best = { lookalikeOf: candHost, distance: dist, reason: "typosquat_distance_2" };
      }
    }
  }

  // Embed brand as substring with deceptive affixes: secure-github-login.com
  if (!best.lookalikeOf) {
    for (const cand of hosts) {
      const candSld = sld(cand);
      if (candSld.length < 5) continue;
      if (hostSld.includes(candSld) && hostSld !== candSld) {
        const extra = hostSld.replace(candSld, "");
        if (extra && extra.length <= 24) {
          return {
            lookalikeOf: normalizeHostname(cand),
            distance: 1,
            reason: "brand_embedded_in_deceptive_label",
          };
        }
      }
    }
  }

  return best.lookalikeOf
    ? best
    : { lookalikeOf: null, distance: Infinity, reason: null };
}

const SUSPICIOUS_TLDS = new Set([
  "zip",
  "mov",
  "xyz",
  "top",
  "club",
  "work",
  "click",
  "link",
  "gq",
  "cf",
  "tk",
  "ml",
  "ga",
  "icu",
  "rest",
  "loan",
]);

export function suspiciousTld(hostname: string): string | null {
  const labels = normalizeHostname(hostname).split(".");
  const tld = labels[labels.length - 1];
  return SUSPICIOUS_TLDS.has(tld) ? tld : null;
}
