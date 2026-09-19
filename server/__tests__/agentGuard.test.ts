import { describe, it, expect, beforeEach } from "vitest";
import { runGate } from "../services/gate.js";
import { DEFAULT_CONFIG, type EngineConfig } from "../types.js";
import { primeVtCache, clearVtCache } from "../services/virustotal.js";
import { clearTrust, trustDomain, untrustDomain, isTrusted } from "../services/sessionTrust.js";
import { setCustomBrands, lookupOfficial } from "../services/registry.js";

const base: EngineConfig = { ...DEFAULT_CONFIG, vtApiKey: "k", enableRdap: false };
const offline = { skipIntel: true } as const;

beforeEach(() => {
  clearVtCache();
  clearTrust();
  setCustomBrands([]);
});

describe("session trust", () => {
  it("allows unknown host after trust_domain", async () => {
    primeVtCache("partner.example", {
      status: "degraded",
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      reputation: null,
      categories: [],
      cached: false,
      permalink: null,
    });
    const before = await runGate("https://partner.example/doc", base, offline);
    expect(before.decision).toBe("review");

    trustDomain("partner.example", { source: "user" });
    expect(isTrusted("partner.example")).toBe(true);

    const after = await runGate("https://partner.example/doc", base, offline);
    expect(after.decision).toBe("allow");
    expect(after.authority.sessionTrusted).toBe(true);
  });

  it("still blocks denylisted host even if trusted", async () => {
    trustDomain("evil.example", { source: "agent" });
    primeVtCache("evil.example", {
      status: "clean",
      malicious: 0,
      suspicious: 0,
      harmless: 5,
      undetected: 2,
      reputation: 0,
      categories: [],
      cached: true,
      permalink: null,
    });
    const r = await runGate("https://evil.example", {
      ...base,
      denylist: ["evil.example"],
    }, offline);
    expect(r.decision).toBe("block");
  });

  it("still blocks VT malicious even if session-trusted", async () => {
    trustDomain("malware-partner.example", { source: "user" });
    primeVtCache("malware-partner.example", {
      status: "malicious",
      malicious: 15,
      suspicious: 2,
      harmless: 0,
      undetected: 0,
      reputation: -20,
      categories: ["malware"],
      cached: false,
      permalink: null,
    });
    const r = await runGate(
      "https://malware-partner.example/payload",
      base,
      offline,
    );
    expect(r.decision).toBe("block");
  });

  it("rejects invalid hostname for trust", async () => {
    const { isValidHostname } = await import("../services/sessionTrust.js");
    expect(isValidHostname("https://evil.com")).toBe(false);
    expect(isValidHostname("evil.com/path")).toBe(false);
    expect(isValidHostname("not a host")).toBe(false);
    expect(isValidHostname("partner.example")).toBe(true);
  });

  it("session trust does not override lookalike hard-block", async () => {
    primeVtCache("guthub.com", {
      status: "clean",
      malicious: 0,
      suspicious: 0,
      harmless: 20,
      undetected: 5,
      reputation: 0,
      categories: [],
      cached: true,
      permalink: null,
    });
    trustDomain("guthub.com", { source: "agent" });
    const r = await runGate("https://guthub.com/login", base, offline);
    expect(r.decision).toBe("block");
    expect(r.authority.lookalikeOf).toBe("github.com");
  });

  it("untrust restores review", async () => {
    trustDomain("x.example");
    untrustDomain("x.example");
    expect(isTrusted("x.example")).toBe(false);
  });
});

describe("custom brands", () => {
  it("treats custom brand as official", async () => {
    setCustomBrands([
      { host: "acme-corp.example", brand: "Acme", subject: "Acme Corp" },
    ]);
    const hit = lookupOfficial("portal.acme-corp.example");
    expect(hit?.entry.brand).toBe("Acme");

    primeVtCache("portal.acme-corp.example", {
      status: "clean",
      malicious: 0,
      suspicious: 0,
      harmless: 40,
      undetected: 5,
      reputation: 0,
      categories: [],
      cached: true,
      permalink: null,
    });
    const r = await runGate("https://portal.acme-corp.example/login", base, offline);
    expect(r.decision).toBe("allow");
    expect(r.authority.brand).toBe("Acme");
    expect(r.authority.subject).toContain("Acme");
  });
});
