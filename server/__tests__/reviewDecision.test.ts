import { describe, it, expect, beforeEach } from "vitest";
import { resolveReviewDecision } from "../services/reviewDecision.js";
import { enqueueReview, getReview, listReviews } from "../services/reviewQueue.js";
import { clearTrust, isTrusted } from "../services/sessionTrust.js";
import { runGate } from "../services/gate.js";
import { primeVtCache, clearVtCache } from "../services/virustotal.js";
import { getConfig, updateConfig } from "../services/store.js";
import { DEFAULT_CONFIG, type EngineConfig, type GateResult } from "../types.js";

const base: EngineConfig = { ...DEFAULT_CONFIG, vtApiKey: "k", enableRdap: false };
const offline = { skipIntel: true } as const;

function reviewResult(hostname: string, context = "test"): GateResult {
  return {
    id: `chk_${hostname}`,
    url: `https://${hostname}/x`,
    hostname,
    decision: "review",
    score: 40,
    reasons: [{ code: "needs_review", severity: "warn", message: "review" }],
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

beforeEach(() => {
  clearVtCache();
  clearTrust();
  updateConfig({
    allowlist: [...getConfig().allowlist],
    denylist: [...getConfig().denylist],
  });
});

describe("resolveReviewDecision", () => {
  it("grants session trust on allow so the next check returns allow", async () => {
    const item = enqueueReview(reviewResult("partner.example"));
    const out = resolveReviewDecision(item.id, "allow", { by: "user" });
    expect(out.ok).toBe(true);
    expect(isTrusted("partner.example")).toBe(true);

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
    const after = await runGate("https://partner.example/doc", base, offline);
    expect(after.decision).toBe("allow");
  });

  it("does not grant session trust on block", () => {
    const item = enqueueReview(reviewResult("evil.example"));
    const out = resolveReviewDecision(item.id, "block", { by: "user" });
    expect(out.ok).toBe(true);
    expect(isTrusted("evil.example")).toBe(false);
  });

  it("honours sessionTrust=false", () => {
    const item = enqueueReview(reviewResult("no-trust.example"));
    const out = resolveReviewDecision(item.id, "allow", {
      by: "user",
      sessionTrust: false,
    });
    expect(out.ok).toBe(true);
    expect(isTrusted("no-trust.example")).toBe(false);
  });

  it("alwaysAllow writes the permanent allow/deny list", () => {
    const allowed = enqueueReview(reviewResult("always-ok.example"));
    resolveReviewDecision(allowed.id, "allow", { by: "user", alwaysAllow: true });
    expect(getConfig().allowlist).toContain("always-ok.example");

    const blocked = enqueueReview(reviewResult("always-no.example"));
    resolveReviewDecision(blocked.id, "block", { by: "user", alwaysAllow: true });
    expect(getConfig().denylist).toContain("always-no.example");
  });

  it("reports not_found and not_pending", () => {
    expect(resolveReviewDecision("rev_missing", "allow").ok).toBe(false);
    expect(resolveReviewDecision("rev_missing", "allow").error).toBe("not_found");

    const item = enqueueReview(reviewResult("twice.example"));
    expect(resolveReviewDecision(item.id, "allow").ok).toBe(true);
    const second = resolveReviewDecision(item.id, "allow");
    expect(second.ok).toBe(false);
    expect(second.error).toBe("not_pending");
    expect(getReview(item.id)?.status).toBe("allowed");
  });

  it("keeps the review queue free of duplicate pending items", () => {
    enqueueReview(reviewResult("dup.example"));
    enqueueReview(reviewResult("dup.example"));
    const pending = listReviews(false).filter((r) => r.hostname === "dup.example");
    expect(pending.length).toBe(1);
  });
});
