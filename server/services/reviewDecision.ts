import type { ReviewItem } from "./reviewQueue.js";
import { getReview, resolveReview } from "./reviewQueue.js";
import { isValidHostname, trustDomain } from "./sessionTrust.js";
import { getConfig, updateConfig } from "./store.js";

export interface ReviewDecisionOptions {
  by?: "user" | "agent";
  note?: string;
  /** Also persist the host into the permanent allow/deny list. */
  alwaysAllow?: boolean;
  /** Grant session trust on allow (default true). */
  sessionTrust?: boolean;
}

export type ReviewDecisionResult =
  | { ok: true; item: ReviewItem }
  | { ok: false; error: "not_found" | "not_pending"; item?: ReviewItem };

/**
 * Single entry point for resolving a pending review.
 *
 * Both the HTTP API and the MCP tool go through here so they cannot drift
 * apart: an allowed host always becomes session-trusted, otherwise the agent
 * gets "review" again on the very next check and loops forever.
 */
export function resolveReviewDecision(
  id: string,
  decision: "allow" | "block",
  opts: ReviewDecisionOptions = {},
): ReviewDecisionResult {
  const existing = getReview(id);
  if (!existing) return { ok: false, error: "not_found" };

  const { item, changed } = resolveReview(id, decision, {
    by: opts.by ?? "user",
    note: opts.note,
  });
  if (!changed) return { ok: false, error: "not_pending", item: item ?? undefined };

  const hostname = existing.hostname;
  const valid = Boolean(hostname) && isValidHostname(hostname);

  if (valid && opts.alwaysAllow) {
    const cfg = getConfig();
    const key = decision === "allow" ? "allowlist" : "denylist";
    const list = cfg[key];
    if (!list.includes(hostname)) {
      updateConfig({ [key]: [...list, hostname] });
    }
  }

  if (decision === "allow" && opts.sessionTrust !== false && valid) {
    trustDomain(hostname, {
      source: opts.by ?? "user",
      reason: `review ${existing.id}`,
    });
  }

  return { ok: true, item: item as ReviewItem };
}
