import { describe, it, expect, beforeEach } from "vitest";
import { runGate, parseUrl } from "../services/gate.js";
import { DEFAULT_CONFIG, type EngineConfig, type VirusTotalReport } from "../types.js";
import { primeVtCache, clearVtCache } from "../services/virustotal.js";
import { clearRdapCache } from "../services/rdap.js";
import { detectLookalike, levenshtein } from "../services/lookalike.js";
import { lookupOfficial } from "../services/registry.js";

const baseConfig: EngineConfig = {
  ...DEFAULT_CONFIG,
  vtApiKey: "test-key",
  enableRdap: false, // offline tests
};

const offline = { skipIntel: true } as const;

function vt(over: Partial<VirusTotalReport>): VirusTotalReport {
  return {
    status: "clean",
    malicious: 0,
    suspicious: 0,
    harmless: 80,
    undetected: 10,
    reputation: 0,
    categories: [],
    cached: false,
    permalink: null,
    ...over,
  };
}

beforeEach(() => {
  clearVtCache();
  clearRdapCache();
});

describe("parseUrl", () => {
  it("accepts https URLs", () => {
    const r = parseUrl("https://github.com/foo/bar");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.hostname).toBe("github.com");
  });

  it("prepends https for bare hosts", () => {
    const r = parseUrl("pypi.org/project/x");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.hostname).toBe("pypi.org");
  });

  it("rejects javascript: protocol", () => {
    const r = parseUrl("javascript:alert(1)");
    expect(r.ok).toBe(false);
  });

  it("rejects empty", () => {
    expect(parseUrl("").ok).toBe(false);
  });
});

describe("registry", () => {
  it("matches official github.com", () => {
    const hit = lookupOfficial("github.com");
    expect(hit?.entry.brand).toBe("GitHub");
  });

  it("matches subdomain of official", () => {
    const hit = lookupOfficial("raw.githubusercontent.com");
    expect(hit?.entry.brand).toBe("GitHub");
  });

  it("returns null for unknown", () => {
    expect(lookupOfficial("totally-not-real-xyz.invalid")).toBeNull();
  });
});

describe("lookalike", () => {
  it("computes levenshtein", () => {
    expect(levenshtein("github", "guthub")).toBe(1);
  });

  it("flags typosquat of github", () => {
    const f = detectLookalike("guthub.com", ["github.com"]);
    expect(f.lookalikeOf).toBe("github.com");
  });

  it("flags embedded brand", () => {
    const f = detectLookalike("secure-github-login.com", ["github.com"]);
    expect(f.lookalikeOf).toBe("github.com");
  });

  it("does not flag unrelated short domains", () => {
    const f = detectLookalike("example-shop.cn", ["github.com", "google.com"]);
    expect(f.lookalikeOf).toBeNull();
  });
});

describe("gate decisions (offline)", () => {
  it("ALLOWS official domain with clean VT", async () => {
    primeVtCache("github.com", vt({ status: "clean" }));
    const r = await runGate(
      "https://github.com/anthropics/anthropic-sdk",
      { ...baseConfig, vtApiKey: "k" },
      offline,
    );
    expect(r.hostname).toBe("github.com");
    expect(r.decision).toBe("allow");
    expect(r.authority.official).toBe(true);
    expect(r.authority.subject).toContain("GitHub");
    expect(r.score).toBeGreaterThanOrEqual(70);
  });

  it("BLOCKS VT malicious", async () => {
    primeVtCache("evil-malware-download.example", vt({ status: "malicious", malicious: 12 }));
    const r = await runGate(
      "https://evil-malware-download.example/payload",
      baseConfig,
      offline,
    );
    expect(r.decision).toBe("block");
    expect(r.reasons.some((x) => x.code === "vt_malicious")).toBe(true);
  });

  it("BLOCKS lookalike of official brand", async () => {
    primeVtCache("guthub.com", vt({ status: "clean" }));
    const r = await runGate("https://guthub.com/login", baseConfig, offline);
    expect(r.decision).toBe("block");
    expect(r.authority.lookalikeOf).toBe("github.com");
  });

  it("BLOCKS denylisted host", async () => {
    primeVtCache("bad.actor", vt({ status: "clean" }));
    const r = await runGate(
      "https://bad.actor",
      { ...baseConfig, denylist: ["bad.actor"] },
      offline,
    );
    expect(r.decision).toBe("block");
  });

  it("REVIEWS unknown domain when VT degraded (no key)", async () => {
    const r = await runGate(
      "https://random-startup-site.example",
      { ...baseConfig, vtApiKey: null, enableRdap: false },
      offline,
    );
    expect(r.decision).toBe("review");
    expect(r.virusTotal.status).toBe("degraded");
  });

  it("ALLOWS unknown domain when allowlisted and VT clean", async () => {
    primeVtCache("internal.corp.example", vt({ status: "clean" }));
    const r = await runGate(
      "https://internal.corp.example/docs",
      { ...baseConfig, allowlist: ["internal.corp.example"] },
      offline,
    );
    expect(r.decision).toBe("allow");
  });

  it("BLOCKS invalid URL", async () => {
    const r = await runGate("not a url at all", baseConfig, offline);
    expect(r.decision).toBe("block");
    expect(r.reasons[0].code).toBe("invalid_url");
  });

  it("observe mode never blocks clean unknown", async () => {
    primeVtCache("unknown-but-clean.example", vt({ status: "clean" }));
    const r = await runGate(
      "https://unknown-but-clean.example",
      { ...baseConfig, policyMode: "observe" },
      offline,
    );
    expect(r.decision).toBe("allow");
  });
});
