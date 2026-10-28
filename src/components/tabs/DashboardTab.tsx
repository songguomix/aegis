import React, { useState } from "react";
import type { GateResult, Health, ReviewItem } from "../../lib/api";
import { t, type Lang } from "../../lib/i18n";
import { DecisionPill } from "../DecisionPill";
import { IconSearch, IconAlertTriangle } from "../Icons";

interface DashboardTabProps {
  lang: Lang;
  health: Health | null;
  history: GateResult[];
  reviews: ReviewItem[];
  onCheckUrl: (url: string) => Promise<GateResult | void>;
  onResolveReview: (id: string, decision: "allow" | "block", alwaysAllow?: boolean) => Promise<void>;
  onSelectRecord?: (record: GateResult) => void;
  onNavigateToCheck: () => void;
}

export function DashboardTab({
  lang,
  health,
  history,
  reviews,
  onCheckUrl,
  onResolveReview,
  onSelectRecord,
  onNavigateToCheck,
}: DashboardTabProps) {
  const L = (k: Parameters<typeof t>[1]) => t(lang, k);
  const stats = health?.stats;
  const recent = history.slice(0, 10);

  const [quickUrl, setQuickUrl] = useState("");
  const [quickLoading, setQuickLoading] = useState(false);
  const [quickResult, setQuickResult] = useState<GateResult | null>(null);

  async function handleQuickCheck() {
    if (!quickUrl.trim() || quickLoading) return;
    setQuickLoading(true);
    try {
      const res = await onCheckUrl(quickUrl.trim());
      if (res) setQuickResult(res);
    } finally {
      setQuickLoading(false);
    }
  }

  return (
    <div className="tab-container">
      <div className="page-header">
        <div>
          <h2>{L("dashboard")}</h2>
          <p className="sub">
            {L("status")}: Aegis core · {L("activePolicies")} {health?.policyMode ?? "—"}
          </p>
        </div>
        <div className="actions">
          <button className="btn btn-primary" onClick={onNavigateToCheck}>
            <IconSearch size={14} style={{ marginRight: 6 }} />
            {L("liveCheck")}
          </button>
        </div>
      </div>

      <div className="stack">
        {/* Metric Cards */}
        <div className="stats">
          <div className="stat-card">
            <div className="label">{L("total")}</div>
            <div className="value">{stats?.total ?? 0}</div>
            <div className="hint">VT Cache: {health?.vtCache ?? 0} entries</div>
          </div>
          <div className="stat-card allow">
            <div className="label">{L("allow")}</div>
            <div className="value">{stats?.allow ?? 0}</div>
            <div className="hint">{stats?.total ? `${Math.round(((stats.allow || 0) / stats.total) * 100)}%` : "0%"} rate</div>
          </div>
          <div className="stat-card review">
            <div className="label">{L("review")}</div>
            <div className="value">{stats?.review ?? 0}</div>
            <div className="hint">{reviews.length} pending action</div>
          </div>
          <div className="stat-card block">
            <div className="label">{L("block")}</div>
            <div className="value">{stats?.block ?? 0}</div>
            <div className="hint">Threats neutralized</div>
          </div>
        </div>

        {/* Pending Reviews Section */}
        {reviews.length > 0 && (
          <section className="panel pending-panel">
            <div className="panel-head">
              <div className="pending-head-title">
                <span className="pending-badge-icon">
                  <IconAlertTriangle size={15} />
                </span>
                <h3>
                  {L("pendingReviews")} · {reviews.length}
                </h3>
              </div>
              <span className="sub">{L("pendingSub")}</span>
            </div>
            <div className="pending-list">
              {reviews.map((r) => (
                <div className="pending-item" key={r.id}>
                  <div className="pending-main">
                    <div className="pending-host mono">{r.hostname}</div>
                    <div className="pending-meta">
                      {r.summary.official ? r.summary.brand ?? "official" : "unknown site"} · VT:{" "}
                      <span className="mono">{r.summary.vtStatus}</span> · Intel:{" "}
                      <span className="mono">{r.summary.intelStatus}</span>
                      {r.summary.lookalikeOf ? ` · lookalike → ${r.summary.lookalikeOf}` : ""}
                    </div>
                    <div className="pending-reasons">
                      {r.reasons
                        .filter((x) => x.severity !== "info")
                        .slice(0, 2)
                        .map((x) => (
                          <span key={x.code} className="reason-item">
                            <span className={`sev-dot ${x.severity}`} />
                            {x.message}
                          </span>
                        ))}
                    </div>
                  </div>
                  <div className="pending-actions">
                    <button
                      className="btn btn-sm btn-allow"
                      onClick={() => onResolveReview(r.id, "allow", true)}
                    >
                      {L("approve")} · {L("alwaysAllow")}
                    </button>
                    <button
                      className="btn btn-sm btn-ghost"
                      onClick={() => onResolveReview(r.id, "allow", false)}
                    >
                      {L("approve")}
                    </button>
                    <button
                      className="btn btn-sm btn-ghost deny-btn"
                      onClick={() => onResolveReview(r.id, "block", false)}
                    >
                      {L("deny")}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* Split Grid: Recent activity & Quick check */}
        <div className="grid-2">
          {/* Left: Recent Activity */}
          <section className="panel">
            <div className="panel-head">
              <h3>{L("recent")}</h3>
              <span className="sub hint">{recent.length} checks</span>
            </div>
            {recent.length === 0 ? (
              <div className="empty">{L("noResults")}</div>
            ) : (
              <div className="list-scroll">
                <table className="table cols-url">
                  <thead>
                    <tr>
                      <th>{L("decision")}</th>
                      <th>{L("url")}</th>
                      <th style={{ textAlign: "right" }}>{L("score")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recent.map((item) => (
                      <tr
                        key={item.id}
                        className={onSelectRecord ? "clickable-row" : ""}
                        onClick={() => onSelectRecord?.(item)}
                        title="Click to view details"
                      >
                        <td>
                          <DecisionPill decision={item.decision} />
                        </td>
                        <td className="mono truncate-cell">{item.hostname || item.url}</td>
                        <td style={{ textAlign: "right" }}>
                          <span className="score-num">{item.score}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          {/* Right: Quick check station */}
          <section className="panel">
            <div className="panel-head">
              <h3>{L("quickCheck")}</h3>
            </div>
            <div className="check-row">
              <div className="field">
                <input
                  className="input"
                  placeholder={L("urlPlaceholder")}
                  value={quickUrl}
                  onChange={(e) => setQuickUrl(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleQuickCheck()}
                />
              </div>
              <button
                className="btn btn-primary"
                onClick={handleQuickCheck}
                disabled={quickLoading || !quickUrl.trim()}
              >
                {quickLoading ? L("checking") : L("runCheck")}
              </button>
            </div>

            {quickResult ? (
              <div className="result" style={{ marginTop: 14 }}>
                <div className="result-head" style={{ marginBottom: 12, paddingBottom: 12 }}>
                  <div>
                    <div className="url mono">{quickResult.hostname}</div>
                    <div className="sub">{new Date(quickResult.checkedAt).toLocaleTimeString()}</div>
                  </div>
                  <div className="split">
                    <span className="score">{quickResult.score}</span>
                    <DecisionPill decision={quickResult.decision} />
                  </div>
                </div>
                <div className="meta-grid cols-2">
                  <div className="meta-item">
                    <div className="k">{L("official")}</div>
                    <div className="v">
                      {quickResult.authority.official ? quickResult.authority.brand : "—"}
                    </div>
                  </div>
                  <div className="meta-item">
                    <div className="k">{L("vt")}</div>
                    <div className="v">{quickResult.virusTotal.status}</div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="empty quick-check-empty">
                <IconSearch size={24} style={{ opacity: 0.3, marginBottom: 8 }} />
                <span>Enter any URL or domain to test the gateway</span>
              </div>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}
