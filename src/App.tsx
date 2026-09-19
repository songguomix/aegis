import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  api,
  type BatchResult,
  type EngineConfigView,
  type FileGateResult,
  type GateResult,
  type Health,
  type IntegrationInfo,
  type ReviewItem,
  type SessionTrustEntry,
} from "./lib/api";
import { t, type Lang } from "./lib/i18n";

type Tab = "dashboard" | "check" | "history" | "settings" | "integrate";
type CheckMode = "url" | "file" | "batch";

function DecisionPill({ decision }: { decision: GateResult["decision"] }) {
  return <span className={`decision-pill ${decision}`}>{decision}</span>;
}

function SourceRow({
  name,
  status,
  detail,
  level,
}: {
  name: string;
  status: string;
  detail?: string;
  level: "ok" | "warn" | "bad" | "muted";
}) {
  return (
    <div className={`source-row ${level}`}>
      <span className="source-name">{name}</span>
      <span className="source-status">{status}</span>
      {detail ? <span className="source-detail">{detail}</span> : null}
    </div>
  );
}

function DataSources({ result }: { result: GateResult }) {
  const intel = result.threatIntel;
  const vt = result.virusTotal;
  const auth = result.authority;

  const vtLevel: "ok" | "warn" | "bad" | "muted" =
    vt.status === "malicious"
      ? "bad"
      : vt.status === "suspicious"
        ? "warn"
        : vt.status === "clean"
          ? "ok"
          : "muted";

  return (
    <div className="sources">
      <div className="panel-head" style={{ marginBottom: 8 }}>
        <h3>Data sources</h3>
      </div>
      <SourceRow
        name="Official registry"
        status={auth.official ? auth.brand ?? "match" : "no match"}
        detail={auth.subject ?? auth.category ?? undefined}
        level={auth.official ? "ok" : "muted"}
      />
      <SourceRow
        name="Lookalike"
        status={auth.lookalikeOf ? "suspicious" : "ok"}
        detail={auth.lookalikeOf ? `→ ${auth.lookalikeOf}` : undefined}
        level={auth.lookalikeOf ? "bad" : "ok"}
      />
      <SourceRow
        name="RDAP"
        status={auth.rdap.status}
        detail={auth.rdap.organization || auth.rdap.registrant || undefined}
        level={auth.rdap.status === "ok" ? "ok" : "muted"}
      />
      <SourceRow
        name="VirusTotal"
        status={vt.status}
        detail={`mal ${vt.malicious} · sus ${vt.suspicious} · harm ${vt.harmless}${vt.cached ? " · cache" : ""}`}
        level={vtLevel}
      />
      {(intel?.sources ?? []).map((s) => (
        <SourceRow
          key={s.source}
          name={s.source}
          status={s.listed ? "LISTED" : "clear"}
          detail={s.detail}
          level={s.listed ? "bad" : String(s.detail ?? "").includes("fail") || String(s.detail ?? "").startsWith("http_") ? "muted" : "ok"}
        />
      ))}
      {intel && (
        <SourceRow
          name="Intel overall"
          status={intel.status}
          detail={
            intel.listedBy.length
              ? intel.listedBy.join(", ")
              : intel.status === "unknown"
                ? "partial feeds"
                : undefined
          }
          level={
            intel.status === "listed"
              ? "bad"
              : intel.status === "clean"
                ? "ok"
                : intel.status === "unknown"
                  ? "warn"
                  : "muted"
          }
        />
      )}
    </div>
  );
}

export default function App() {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [lang, setLang] = useState<Lang>("en");
  const [health, setHealth] = useState<Health | null>(null);
  const [history, setHistory] = useState<GateResult[]>([]);
  const [config, setConfig] = useState<EngineConfigView | null>(null);
  const [url, setUrl] = useState("");
  const [context, setContext] = useState("");
  const [checkMode, setCheckMode] = useState<CheckMode>("url");
  const [hash, setHash] = useState("");
  const [fileName, setFileName] = useState("");
  const [batchText, setBatchText] = useState("");
  const [fileResult, setFileResult] = useState<FileGateResult | null>(null);
  const [batchResult, setBatchResult] = useState<BatchResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<GateResult | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [integration, setIntegration] = useState<IntegrationInfo | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [reviews, setReviews] = useState<ReviewItem[]>([]);
  const [sessionTrust, setSessionTrust] = useState<SessionTrustEntry[]>([]);
  const [customBrandsText, setCustomBrandsText] = useState("");
  const [settingsDirty, setSettingsDirty] = useState(false);
  const [deployBundle, setDeployBundle] = useState<{
    mcpCommand: string;
    mcpEntry: string;
    files: { filename: string; content: string }[];
  } | null>(null);

  const L = useCallback((k: Parameters<typeof t>[1]) => t(lang, k), [lang]);

  const refresh = useCallback(async () => {
    try {
      const [h, hist, cfg, integ, rev, trust] = await Promise.all([
        api.health(),
        api.history(80),
        api.config(),
        api.integration(),
        api.reviews().catch(() => ({ items: [], stats: { pending: 0, allowed: 0, blocked: 0 } })),
        api.sessionTrust().catch(() => ({ items: [] })),
      ]);
      setHealth(h);
      setHistory(hist.items);
      if (!settingsDirty) {
        setConfig(cfg);
        setLang(cfg.language);
        setCustomBrandsText(
          (cfg.customBrands ?? [])
            .map((b) => `${b.host} | ${b.brand} | ${b.subject || ""}`)
            .join("\n"),
        );
      }
      setIntegration(integ);
      setReviews(rev.items);
      setSessionTrust(trust.items);
      const bundle = await api.mcpDeployBundle().catch(() => null);
      if (bundle) {
        setDeployBundle({
          mcpCommand: bundle.mcpCommand,
          mcpEntry: bundle.mcpEntry,
          files: bundle.files,
        });
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [settingsDirty]);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 8000);
    return () => clearInterval(id);
  }, [refresh]);

  useEffect(() => {
    if (!toast && !copied) return;
    const id = setTimeout(() => {
      setToast(null);
      setCopied(null);
    }, 2200);
    return () => clearTimeout(id);
  }, [toast, copied]);

  async function copyText(key: string, text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
    } catch {
      setError("Copy failed");
    }
  }

  function selectCode(e: React.MouseEvent<HTMLPreElement>) {
    const el = e.currentTarget;
    const range = document.createRange();
    range.selectNodeContents(el);
    const sel = window.getSelection();
    sel?.removeAllRanges();
    sel?.addRange(range);
  }

  function onCodeKeyDown(e: React.KeyboardEvent<HTMLPreElement>) {
    const meta = e.metaKey || e.ctrlKey;
    if (meta && e.key.toLowerCase() === "a") {
      e.preventDefault();
      const el = e.currentTarget;
      const range = document.createRange();
      range.selectNodeContents(el);
      const sel = window.getSelection();
      sel?.removeAllRanges();
      sel?.addRange(range);
    }
    if (meta && e.key.toLowerCase() === "c" && window.getSelection()?.toString()) {
      // native copy of selection; no-op here
    }
  }

  async function runCheck() {
    setLoading(true);
    setError(null);
    try {
      if (checkMode === "file") {
        if (!hash.trim()) return;
        const r = await api.checkFile(
          hash.trim(),
          fileName.trim() || undefined,
          context.trim() || undefined,
        );
        setFileResult(r);
        setResult(null);
        setBatchResult(null);
        setToast(L("fileChecked"));
      } else if (checkMode === "batch") {
        const urls = batchText
          .split(/[\n\s,]+/)
          .map((s) => s.trim())
          .filter(Boolean)
          .slice(0, 20);
        if (!urls.length) return;
        const r = await api.checkBatch(urls, context.trim() || undefined);
        setBatchResult(r);
        setResult(null);
        setFileResult(null);
        setToast(`${L("batchDone")} · ${r.total}`);
      } else {
        if (!url.trim()) return;
        const r = await api.check(url.trim(), context.trim() || undefined);
        setResult(r);
        setFileResult(null);
        setBatchResult(null);
      }
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  function canRunCheck(): boolean {
    if (loading) return true;
    if (checkMode === "file") return !hash.trim();
    if (checkMode === "batch") return !batchText.trim();
    return !url.trim();
  }

  async function resolvePending(
    id: string,
    decision: "allow" | "block",
    alwaysAllow = false,
  ) {
    try {
      await api.resolveReview(id, decision, {
        alwaysAllow,
        by: "user",
        sessionTrust: decision === "allow",
      });
      setToast(decision === "allow" ? "Allowed" : "Blocked");
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function apiBaseExport(format: "csv" | "json") {
    try {
      const w = window as unknown as { aegis?: { getApiBase?: () => Promise<string> } };
      const base = w.aegis?.getApiBase
        ? await w.aegis.getApiBase()
        : import.meta.env.DEV
          ? "/api/v1"
          : "http://127.0.0.1:7832/api/v1";
      const res = await fetch(`${base}/history/export?format=${format}`);
      const blob = await res.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `aegis-history.${format}`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function saveSettings(patch: Partial<EngineConfigView> & { vtApiKey?: string | null }) {
    try {
      const cfg = await api.saveConfig(patch);
      setConfig(cfg);
      setLang(cfg.language);
      setSettingsDirty(false);
      setToast(L("saved"));
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  const stats = health?.stats;
  const recent = useMemo(() => history.slice(0, 12), [history]);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div>
            <h1>Aegis</h1>
            <p>{L("brandTag")}</p>
          </div>
        </div>
        <nav className="nav">
          {(
            [
              ["dashboard", L("dashboard")],
              ["check", L("liveCheck")],
              ["history", L("history")],
              ["settings", L("settings")],
              ["integrate", L("integrate")],
            ] as const
          ).map(([id, label]) => (
            <button
              key={id}
              className={`nav-btn ${tab === id ? "active" : ""}`}
              onClick={() => setTab(id)}
            >
              {label}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          {stats?.vtMode === "live" ? (
            <span className="badge live">● {L("modeLive")}</span>
          ) : (
            <span className="badge degraded">● {L("modeDegraded")}</span>
          )}
          <div className="ver">v0.1.0 · MCP + HTTP</div>
        </div>
      </aside>

      <main className="main">
        <div className={`main-inner${tab === "settings" || tab === "history" || tab === "integrate" ? " wide" : ""}`}>
        {tab === "dashboard" && (
          <>
            <div className="page-header">
              <div>
                <h2>{L("dashboard")}</h2>
                <p className="sub">
                  {L("status")}: Aegis core · policy {health?.policyMode ?? "—"}
                </p>
              </div>
              <div className="actions">
                <button className="btn" onClick={() => setTab("check")}>
                  {L("liveCheck")}
                </button>
              </div>
            </div>

            <div className="stack">
              <div className="stats">
                <div className="stat-card">
                  <div className="label">{L("total")}</div>
                  <div className="value">{stats?.total ?? 0}</div>
                  <div className="hint">VT cache {health?.vtCache ?? 0}</div>
                </div>
                <div className="stat-card allow">
                  <div className="label">{L("allow")}</div>
                  <div className="value">{stats?.allow ?? 0}</div>
                  <div className="hint">&nbsp;</div>
                </div>
                <div className="stat-card review">
                  <div className="label">{L("review")}</div>
                  <div className="value">{stats?.review ?? 0}</div>
                  <div className="hint">&nbsp;</div>
                </div>
                <div className="stat-card block">
                  <div className="label">{L("block")}</div>
                  <div className="value">{stats?.block ?? 0}</div>
                  <div className="hint">&nbsp;</div>
                </div>
              </div>

              {reviews.length > 0 && (
                <section className="panel pending-panel">
                  <div className="panel-head">
                    <h3>
                      {L("pendingReviews")} · {reviews.length}
                    </h3>
                    <span className="sub">{L("pendingSub")}</span>
                  </div>
                  <div className="pending-list">
                    {reviews.map((r) => (
                      <div className="pending-item" key={r.id}>
                        <div className="pending-main">
                          <div className="pending-host mono">{r.hostname}</div>
                          <div className="pending-meta">
                            {r.summary.official
                              ? r.summary.brand ?? "official"
                              : "unknown"}{" "}
                            · VT {r.summary.vtStatus} · intel {r.summary.intelStatus}
                            {r.summary.lookalikeOf
                              ? ` · lookalike→${r.summary.lookalikeOf}`
                              : ""}
                          </div>
                          <div className="pending-reasons">
                            {r.reasons
                              .filter((x) => x.severity !== "info")
                              .slice(0, 2)
                              .map((x) => (
                                <span key={x.code}>{x.message}</span>
                              ))}
                          </div>
                        </div>
                        <div className="pending-actions">
                          <button
                            className="btn"
                            onClick={() => resolvePending(r.id, "allow", true)}
                          >
                            {L("approve")} · {L("alwaysAllow")}
                          </button>
                          <button
                            className="btn btn-ghost"
                            onClick={() => resolvePending(r.id, "allow", false)}
                          >
                            {L("approve")}
                          </button>
                          <button
                            className="btn btn-ghost deny-btn"
                            onClick={() => resolvePending(r.id, "block", false)}
                          >
                            {L("deny")}
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </section>
              )}

              <div className="grid-2">
              <section className="panel">
                <div className="panel-head">
                  <h3>{L("recent")}</h3>
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
                          <tr key={item.id}>
                            <td>
                              <DecisionPill decision={item.decision} />
                            </td>
                            <td className="mono">{item.hostname || item.url}</td>
                            <td>
                              <div className="score">{item.score}</div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>

              <section className="panel">
                <div className="panel-head">
                  <h3>{L("checkTitle")}</h3>
                </div>
                <div className="check-row">
                  <div className="field">
                    <input
                      className="input"
                      placeholder={L("urlPlaceholder")}
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && runCheck()}
                    />
                  </div>
                  <button className="btn" onClick={runCheck} disabled={loading}>
                    {loading ? L("checking") : L("runCheck")}
                  </button>
                </div>
                {result ? (
                  <div className="result" style={{ marginTop: 14 }}>
                    <div className="result-head" style={{ marginBottom: 12, paddingBottom: 12 }}>
                      <div>
                        <div className="url mono">{result.hostname}</div>
                      </div>
                      <div className="split">
                        <span className="score">{result.score}</span>
                        <DecisionPill decision={result.decision} />
                      </div>
                    </div>
                    <div className="meta-grid cols-2">
                      <div className="meta-item">
                        <div className="k">{L("official")}</div>
                        <div className="v">
                          {result.authority.official ? result.authority.brand : "—"}
                        </div>
                      </div>
                      <div className="meta-item">
                        <div className="k">{L("vt")}</div>
                        <div className="v">{result.virusTotal.status}</div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="empty">No check yet</div>
                )}
              </section>
            </div>
            </div>
          </>
        )}

        {tab === "check" && (
          <>
            <div className="page-header">
              <div>
                <h2>{L("checkTitle")}</h2>
                <p className="sub">{L("checkSub")}</p>
              </div>
            </div>
            <div className="stack">
            <section className="panel check-hero">
              <div className="seg" role="tablist">
                {(
                  [
                    ["url", L("modeUrl")],
                    ["file", L("modeFile")],
                    ["batch", L("modeBatch")],
                  ] as const
                ).map(([id, label]) => (
                  <button
                    key={id}
                    type="button"
                    role="tab"
                    aria-selected={checkMode === id}
                    className={`seg-item${checkMode === id ? " active" : ""}`}
                    onClick={() => setCheckMode(id)}
                  >
                    {label}
                  </button>
                ))}
              </div>

              {checkMode === "url" && (
                <div className="check-row" style={{ marginTop: 12 }}>
                  <div className="field">
                    <input
                      className="input"
                      placeholder={L("urlPlaceholder")}
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && runCheck()}
                    />
                  </div>
                  <button className="btn" onClick={runCheck} disabled={canRunCheck()}>
                    {loading ? L("checking") : L("runCheck")}
                  </button>
                </div>
              )}

              {checkMode === "file" && (
                <div className="check-row" style={{ marginTop: 12 }}>
                  <div className="field">
                    <input
                      className="input mono"
                      placeholder={L("hashPlaceholder")}
                      value={hash}
                      onChange={(e) => setHash(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && runCheck()}
                    />
                  </div>
                  <div className="field" style={{ maxWidth: 200 }}>
                    <input
                      className="input"
                      placeholder={L("fileNamePlaceholder")}
                      value={fileName}
                      onChange={(e) => setFileName(e.target.value)}
                    />
                  </div>
                  <button className="btn" onClick={runCheck} disabled={canRunCheck()}>
                    {loading ? L("checking") : L("runCheck")}
                  </button>
                </div>
              )}

              {checkMode === "batch" && (
                <>
                  <textarea
                    className="input"
                    style={{ marginTop: 12, minHeight: 120 }}
                    placeholder={L("batchPlaceholder")}
                    value={batchText}
                    onChange={(e) => setBatchText(e.target.value)}
                  />
                  <div className="check-row" style={{ marginTop: 10 }}>
                    <button className="btn" onClick={runCheck} disabled={canRunCheck()}>
                      {loading ? L("checking") : L("runCheck")}
                    </button>
                  </div>
                </>
              )}

              <div className="field context">
                <input
                  className="input"
                  placeholder={L("contextPlaceholder")}
                  value={context}
                  onChange={(e) => setContext(e.target.value)}
                />
              </div>
            </section>

            {fileResult && (
              <section className="panel result">
                <div className="result-head">
                  <div>
                    <div className="url mono">{fileResult.fileName || fileResult.hash}</div>
                    <div className="sub">
                      {fileResult.hashType} · {fileResult.hash.slice(0, 24)}… ·{" "}
                      {new Date(fileResult.checkedAt).toLocaleString()}
                    </div>
                  </div>
                  <div className="split">
                    <span className="score">{fileResult.score}</span>
                    <DecisionPill decision={fileResult.decision} />
                  </div>
                </div>
                <div className="meta-grid cols-2">
                  <div className="meta-item">
                    <div className="k">{L("vt")}</div>
                    <div className="v">
                      {fileResult.virusTotal.status} · mal {fileResult.virusTotal.malicious} ·
                      sus {fileResult.virusTotal.suspicious}
                    </div>
                  </div>
                  <div className="meta-item">
                    <div className="k">{L("decision")}</div>
                    <div className="v">{fileResult.decision}</div>
                  </div>
                </div>
                <div className="reasons">
                  {fileResult.reasons.map((r, i) => (
                    <div className="reason" key={`${r.code}-${i}`}>
                      <span className={`sev ${r.severity}`}>{r.severity}</span>
                      <span>{r.message}</span>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {batchResult && (
              <section className="panel">
                <div className="panel-head">
                  <h3>
                    Batch · {batchResult.total} · allow {batchResult.allow} · review{" "}
                    {batchResult.review} · block {batchResult.block}
                  </h3>
                  <DecisionPill decision={batchResult.decision} />
                </div>
                <table className="table">
                  <thead>
                    <tr>
                      <th>{L("decision")}</th>
                      <th>{L("hostname")}</th>
                      <th>{L("vt")}</th>
                      <th style={{ textAlign: "right" }}>{L("score")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {batchResult.results.map((item) => (
                      <tr key={item.id}>
                        <td>
                          <DecisionPill decision={item.decision} />
                        </td>
                        <td className="mono" title={item.hostname}>{item.hostname}</td>
                        <td>{item.virusTotal?.status ?? "—"}</td>
                        <td>
                          <div className="score">{item.score}</div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </section>
            )}

            {result && (
              <section className="panel result">
                <div className="result-head">
                  <div>
                    <div className="url">{result.url}</div>
                    <div className="sub">
                      {result.hostname} · {new Date(result.checkedAt).toLocaleString()}
                    </div>
                  </div>
                  <div className="split">
                    <span className="score">{result.score}</span>
                    <DecisionPill decision={result.decision} />
                  </div>
                </div>

                <div className="result-body">
                  <div className="meta-grid cols-2">
                    <div className="meta-item">
                      <div className="k">{L("brand")}</div>
                      <div className="v">{result.authority.brand ?? "—"}</div>
                    </div>
                    <div className="meta-item">
                      <div className="k">{L("subject")}</div>
                      <div className="v">{result.authority.subject ?? "—"}</div>
                    </div>
                    <div className="meta-item">
                      <div className="k">{L("rdap")}</div>
                      <div className="v">
                        {result.authority.rdap.status}
                        {result.authority.rdap.organization
                          ? ` · ${result.authority.rdap.organization}`
                          : ""}
                      </div>
                    </div>
                    <div className="meta-item">
                      <div className="k">{L("lookalike")}</div>
                      <div className="v">{result.authority.lookalikeOf ?? "—"}</div>
                    </div>
                  </div>

                  <DataSources result={result} />
                </div>

                <div className="panel-head" style={{ marginTop: 14 }}>
                  <h3>{L("reasons")}</h3>
                </div>
                <div className="reasons">
                  {result.reasons.map((r, i) => (
                    <div className="reason" key={`${r.code}-${i}`}>
                      <span className={`sev ${r.severity}`}>{r.severity}</span>
                      <span>{r.message}</span>
                    </div>
                  ))}
                </div>

                {result.decision === "review" && result.reviewId && (
                  <div className="ask-box">
                    <div className="ask-title">{L("askUser")}</div>
                    <p className="help" style={{ margin: "4px 0 10px" }}>
                      {L("askUserHelp")} · <code>{result.reviewId}</code>
                    </p>
                    <div className="pending-actions" style={{ flexDirection: "row" }}>
                      <button
                        className="btn"
                        onClick={() => resolvePending(result.reviewId!, "allow", true)}
                      >
                        {L("approve")} · {L("alwaysAllow")}
                      </button>
                      <button
                        className="btn btn-ghost"
                        onClick={() => resolvePending(result.reviewId!, "allow", false)}
                      >
                        {L("approve")}
                      </button>
                      <button
                        className="btn btn-ghost deny-btn"
                        onClick={() => resolvePending(result.reviewId!, "block", false)}
                      >
                        {L("deny")}
                      </button>
                    </div>
                  </div>
                )}
              </section>
            )}
            </div>
          </>
        )}

        {tab === "history" && (
          <>
            <div className="page-header">
              <div>
                <h2>{L("history")}</h2>
                <p className="sub">{history.length} records</p>
              </div>
              <div className="actions">
                <a
                  className="btn btn-ghost"
                  href="#"
                  onClick={(e) => {
                    e.preventDefault();
                    void apiBaseExport("csv");
                  }}
                >
                  CSV
                </a>
                <a
                  className="btn btn-ghost"
                  href="#"
                  onClick={(e) => {
                    e.preventDefault();
                    void apiBaseExport("json");
                  }}
                >
                  JSON
                </a>
                <button
                  className="btn btn-ghost"
                  onClick={async () => {
                    await api.clearHistory();
                    await refresh();
                    setToast(L("historyCleared"));
                  }}
                >
                  {L("clearHistory")}
                </button>
              </div>
            </div>
            <section className="panel">
              {history.length === 0 ? (
                <div className="empty">{L("noResults")}</div>
              ) : (
                <div className="history-scroll">
                  <table className="table">
                    <thead>
                      <tr>
                        <th>{L("time")}</th>
                        <th>{L("decision")}</th>
                        <th>{L("hostname")}</th>
                        <th>{L("score")}</th>
                        <th>{L("vt")}</th>
                        <th>{L("official")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {history.map((item) => (
                        <tr key={item.id}>
                          <td className="mono">
                            {new Date(item.checkedAt).toLocaleTimeString()}
                          </td>
                          <td>
                            <DecisionPill decision={item.decision} />
                          </td>
                          <td className="mono" title={item.hostname}>{item.hostname}</td>
                          <td>{item.score}</td>
                          <td>{item.virusTotal?.status ?? "—"}</td>
                          <td>{item.authority?.brand ?? "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          </>
        )}

        {tab === "settings" && config && (
          <>
            <div className="page-header">
              <div>
                <h2>{L("settingsTitle")}</h2>
                <p className="sub">{L("settingsSub")}</p>
              </div>
            </div>
            <div className="settings-layout">
              <section className="panel">
                <div className="panel-head">
                  <h3>{L("vtKey")}</h3>
                </div>
                <div className="form-stack full">
                  <div className="form-row">
                    <label>{L("vtKey")}</label>
                    <input
                      className="input"
                      type="password"
                      placeholder={config.hasVtKey ? "••••••••" : "VT API key"}
                      onChange={(e) => {
                        setSettingsDirty(true);
                        const v = e.target.value;
                        setConfig({ ...config, vtApiKey: v || null, hasVtKey: Boolean(v) });
                      }}
                    />
                    <div className="help">{L("vtKeyHelp")}</div>
                  </div>

                  <div className="form-grid-2 policy-row">
                    <div className="form-row">
                      <label>{L("policy")}</label>
                      <select
                        className="input"
                        value={config.policyMode}
                        onChange={(e) => {
                          setSettingsDirty(true);
                          setConfig({
                            ...config,
                            policyMode: e.target.value as EngineConfigView["policyMode"],
                          });
                        }}
                      >
                        <option value="tri">{L("policyTri")}</option>
                        <option value="strict">{L("policyStrict")}</option>
                        <option value="observe">{L("policyObserve")}</option>
                      </select>
                    </div>

                    <div className="form-row">
                      <label>{L("language")}</label>
                      <select
                        className="input"
                        value={config.language}
                        onChange={(e) => {
                          const language = e.target.value as Lang;
                          setSettingsDirty(true);
                          setConfig({ ...config, language });
                          setLang(language);
                        }}
                      >
                        <option value="en">English</option>
                        <option value="zh">中文</option>
                      </select>
                    </div>
                  </div>

                  <div className="form-row">
                    <label>{L("maxUploadMB")}</label>
                    <input
                      className="input"
                      type="number"
                      min={1}
                      max={64}
                      value={Math.round((config.maxUploadBytes ?? 33554432) / (1024 * 1024))}
                      onChange={(e) => {
                        setSettingsDirty(true);
                        const mb = Math.min(64, Math.max(1, Number(e.target.value) || 32));
                        setConfig({ ...config, maxUploadBytes: mb * 1024 * 1024 });
                      }}
                    />
                    <div className="help">{L("maxUploadHelp")}</div>
                  </div>

                  <div className="toggle-row">
                    <div>
                      <div className="title">{L("enableRdap")}</div>
                      <div className="help" style={{ marginTop: 4 }}>
                        {L("enableRdapHelp")}
                      </div>
                    </div>
                    <button
                      className={`switch ${config.enableRdap ? "on" : ""}`}
                      aria-label="RDAP"
                      onClick={() => { setSettingsDirty(true); setConfig({ ...config, enableRdap: !config.enableRdap }); }}
                    />
                  </div>

                  <div className="toggle-row">
                    <div>
                      <div className="title">{L("enableSound")}</div>
                      <div className="help" style={{ marginTop: 4 }}>
                        {L("enableSoundHelp")}
                      </div>
                    </div>
                    <button
                      className={`switch ${config.soundEnabled !== false ? "on" : ""}`}
                      aria-label="Sound"
                      onClick={() => {
                        setSettingsDirty(true);
                        setConfig({
                          ...config,
                          soundEnabled: config.soundEnabled === false,
                        });
                      }}
                    />
                  </div>

                  <div className="form-actions">
                    <button
                      className="btn"
                      onClick={() => {
                        saveSettings({
                          vtApiKey: config.vtApiKey,
                          policyMode: config.policyMode,
                          language: config.language,
                          enableRdap: config.enableRdap,
                          allowlist: config.allowlist,
                          denylist: config.denylist,
                          soundEnabled: config.soundEnabled !== false,
                          maxUploadBytes: config.maxUploadBytes ?? 33554432,
                          customBrands: customBrandsText
                            .split("\n")
                            .map((line) => line.trim())
                            .filter(Boolean)
                            .map((line) => {
                              const parts = line.split("|").map((s) => s.trim());
                              return {
                                host: parts[0] || "",
                                brand: parts[1] || parts[0] || "",
                                subject: parts[2] || parts[1] || parts[0] || "",
                              };
                            })
                            .filter((b) => b.host && b.brand),
                        });
                      }}
                    >
                      {L("save")}
                    </button>
                  </div>
                </div>
              </section>

              <section className="panel">
                <div className="panel-head">
                  <h3>Lists</h3>
                </div>
                <div className="form-stack full">
                  <div className="form-grid-2">
                    <div className="form-row">
                      <label>{L("allowlist")}</label>
                      <textarea
                        className="input"
                        rows={5}
                        value={config.allowlist.join("\n")}
                        onChange={(e) =>
                          setConfig({
                            ...config,
                            allowlist: e.target.value
                              .split("\n")
                              .map((s) => s.trim())
                              .filter(Boolean),
                          })
                        }
                      />
                      <div className="help">{L("allowlistHelp")}</div>
                    </div>

                    <div className="form-row">
                      <label>{L("denylist")}</label>
                      <textarea
                        className="input"
                        rows={5}
                        value={config.denylist.join("\n")}
                        onChange={(e) =>
                          setConfig({
                            ...config,
                            denylist: e.target.value
                              .split("\n")
                              .map((s) => s.trim())
                              .filter(Boolean),
                          })
                        }
                      />
                      <div className="help">{L("denylistHelp")}</div>
                    </div>
                  </div>

                  <div className="form-row">
                    <label>{L("customBrands")}</label>
                    <textarea
                      className="input"
                      rows={4}
                      placeholder="intranet.corp.example | Acme | Acme Internal"
                      value={customBrandsText}
                      onChange={(e) => { setSettingsDirty(true); setCustomBrandsText(e.target.value); }}
                    />
                    <div className="help">{L("customBrandsHelp")}</div>
                  </div>

                  <div className="form-row">
                    <label>{L("sessionTrust")}</label>
                    <div className="glass-soft" style={{ overflow: "hidden" }}>
                      {sessionTrust.length === 0 ? (
                        <div className="empty" style={{ padding: 14 }}>
                          —
                        </div>
                      ) : (
                        sessionTrust.map((t) => (
                          <div className="trust-row" key={t.hostname}>
                            <code>{t.hostname}</code>
                            <span>{t.source}</span>
                            <button
                              className="btn btn-ghost btn-sm"
                              onClick={async () => {
                                await api.untrustDomain(t.hostname);
                                await refresh();
                              }}
                            >
                              ×
                            </button>
                          </div>
                        ))
                      )}
                    </div>
                    <div className="help">{L("sessionTrustHelp")}</div>
                    {sessionTrust.length > 0 && (
                      <div>
                        <button
                          className="btn btn-ghost btn-sm"
                          onClick={async () => {
                            await api.clearSessionTrust();
                            await refresh();
                            setToast(L("historyCleared"));
                          }}
                        >
                          {L("clearTrust")}
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              </section>
            </div>
          </>
        )}

        {tab === "integrate" && (
          <>
            <div className="page-header">
              <div>
                <h2>{L("integrateTitle")}</h2>
                <p className="sub">{L("integrateSub")}</p>
              </div>
            </div>

            <div className="stack">
              <section className="panel">
                <div className="panel-head">
                  <h3>{L("agentGuard")}</h3>
                </div>
                <p className="help" style={{ marginTop: 0 }}>
                  {L("agentGuardSub")}
                </p>
                <ul className="tool-list" style={{ marginTop: 8 }}>
                  <li>
                    <code>preflight</code>
                    <span>{L("agPreflight")}</span>
                  </li>
                  <li>
                    <code>allow</code>
                    <span>{L("agAllow")}</span>
                  </li>
                  <li>
                    <code>block</code>
                    <span>{L("agBlock")}</span>
                  </li>
                  <li>
                    <code>review</code>
                    <span>{L("agReview")}</span>
                  </li>
                  <li>
                    <code>search</code>
                    <span>{L("agSearch")}</span>
                  </li>
                  <li>
                    <code>files</code>
                    <span>{L("agFiles")}</span>
                  </li>
                </ul>
              </section>

              <section className="panel">
                <div className="panel-head">
                  <h3>{L("deployBundle")}</h3>
                </div>
                <p className="help" style={{ marginTop: 0 }}>
                  {L("deployBundleSub")}
                </p>
                <div className="code-block" style={{ marginTop: 10 }}>
                  <div className="code-block-head">
                    <span>MCP command</span>
                    <button
                      className="btn btn-ghost btn-sm"
                      onClick={() =>
                        deployBundle && copyText("deploy-cmd", deployBundle.mcpCommand)
                      }
                    >
                      {copied === "deploy-cmd" ? L("copied") : L("copy")}
                    </button>
                  </div>
                  <pre className="code">
                    {deployBundle?.mcpCommand ?? integration?.mcpCommand ?? "…"}
                  </pre>
                </div>
                <div className="split" style={{ marginTop: 12, flexWrap: "wrap" }}>
                  <button
                    className="btn"
                    onClick={async () => {
                      const fromBundle = deployBundle?.files.find(
                        (f) => f.filename === "mcp.claude.json",
                      )?.content;
                      const json =
                        fromBundle ??
                        (integration?.mcpConfig
                          ? JSON.stringify(integration.mcpConfig, null, 2)
                          : "");
                      await copyText("deploy-json", json);
                    }}
                  >
                    {L("copyMcpJson")}
                  </button>
                  <a
                    className="btn btn-ghost"
                    href="#"
                    onClick={async (e) => {
                      e.preventDefault();
                      const url = await api.mcpDeployZipUrl();
                      const a = document.createElement("a");
                      a.href = url;
                      a.download = "aegis-mcp-deploy.zip";
                      a.click();
                    }}
                  >
                    {L("downloadZip")}
                  </a>
                </div>
                <p className="help">{L("installHint")}</p>
              </section>

              <section className="panel">
                <div className="panel-head">
                  <h3>{L("mcpSection")}</h3>
                </div>
                <p className="help" style={{ marginTop: 8 }}>
                  {L("mcpSub")}
                </p>

                <div className="code-block">
                  <div className="code-block-head">
                    <span>MCP config</span>
                    <span className="hint">Click code to select · Cmd/Ctrl+C</span>
                    <button
                      className="btn btn-ghost btn-sm"
                      onClick={() =>
                        integration &&
                        copyText("mcp", JSON.stringify(integration.mcpConfig, null, 2))
                      }
                    >
                      {copied === "mcp" ? L("copied") : L("copy")}
                    </button>
                  </div>
                  <pre
                    className="code"
                    tabIndex={0}
                    onClick={selectCode}
                    onKeyDown={onCodeKeyDown}
                    title="Click to select · Cmd/Ctrl+A · Cmd/Ctrl+C"
                  >
                    {integration
                      ? JSON.stringify(integration.mcpConfig, null, 2)
                      : "{\n  \"mcpServers\": { \"aegis\": { ... } }\n}"}
                  </pre>
                </div>

                <div className="code-block" style={{ marginTop: 12 }}>
                  <div className="code-block-head">
                    <span>{L("runMcp")}</span>
                    <button
                      className="btn btn-ghost btn-sm"
                      onClick={() => integration && copyText("cmd", integration.mcpCommand)}
                    >
                      {copied === "cmd" ? L("copied") : L("copy")}
                    </button>
                  </div>
                  <pre
                    className="code"
                    tabIndex={0}
                    onClick={selectCode}
                    onKeyDown={onCodeKeyDown}
                    title="Click to select · Cmd/Ctrl+A · Cmd/Ctrl+C"
                  >
                    {integration?.mcpCommand ?? "node … --mcp"}
                  </pre>
                </div>
                <p className="help">{L("runMcpHelp")}</p>

                <div className="panel-head" style={{ marginTop: 16 }}>
                  <h3>{L("mcpTools")}</h3>
                </div>
                <ul className="tool-list">
                  {(integration?.tools ?? []).map((tool) => (
                    <li key={tool.name}>
                      <code>{tool.name}</code>
                      <span>{tool.description}</span>
                      {tool.input.length > 0 && (
                        <em className="mono">{tool.input.join(", ")}</em>
                      )}
                    </li>
                  ))}
                  {integration?.tools == null && <li className="empty">…</li>}
                </ul>
                <p className="note">{L("replacePathNote")}</p>
              </section>

              <section className="panel">
                <div className="panel-head">
                  <h3>{L("httpSection")}</h3>
                </div>
                <p className="help" style={{ marginTop: 0 }}>
                  {L("httpSub")}
                </p>
                <div className="code-block">
                  <div className="code-block-head">
                    <span>{L("httpExample")}</span>
                    <button
                      className="btn btn-ghost btn-sm"
                      onClick={() =>
                        integration &&
                        copyText(
                          "http",
                          `curl -sS ${integration.http.checkUrl} -H 'content-type: application/json' -d '${JSON.stringify(
                            integration.http.example.body,
                          )}'`,
                        )
                      }
                    >
                      {copied === "http" ? L("copied") : L("copy")}
                    </button>
                  </div>
                  <pre
                    className="code"
                    tabIndex={0}
                    onClick={selectCode}
                    onKeyDown={onCodeKeyDown}
                    title="Click to select · Cmd/Ctrl+A · Cmd/Ctrl+C"
                  >
                    {integration
                      ? `curl -sS ${integration.http.checkUrl} \\\n  -H 'content-type: application/json' \\\n  -d '${JSON.stringify(integration.http.example.body, null, 2)}'`
                      : "curl -sS http://127.0.0.1:7832/api/v1/check -H 'content-type: application/json' -d '{\"url\":\"https://example.com\"}'"}
                  </pre>
                </div>
                <ul className="tool-list endpoints" style={{ marginTop: 12 }}>
                  <li>
                    <code>{integration?.http.checkUrl ?? "/check"}</code>
                    <span>POST · check URL / host</span>
                  </li>
                  <li>
                    <code>{integration?.http.statusUrl ?? "/health"}</code>
                    <span>GET · engine health</span>
                  </li>
                  <li>
                    <code>{`${integration?.http.base ?? "http://127.0.0.1:7832/api/v1"}/check-file`}</code>
                    <span>POST · file hash</span>
                  </li>
                  <li>
                    <code>{`${integration?.http.base ?? "http://127.0.0.1:7832/api/v1"}/check-batch`}</code>
                    <span>POST · batch URLs</span>
                  </li>
                </ul>
              </section>
            </div>
          </>
        )}
        </div>

        {error && (
          <div className="toast error">
            {L("error")}: {error}
          </div>
        )}
        {toast && <div className="toast info">{toast}</div>}
      </main>
    </div>
  );
}
