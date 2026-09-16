import { useCallback, useEffect, useMemo, useState } from "react";
import { api, type EngineConfigView, type GateResult, type Health } from "./lib/api";
import { t, type Lang } from "./lib/i18n";

type Tab = "dashboard" | "check" | "history" | "settings";

function DecisionPill({ decision }: { decision: GateResult["decision"] }) {
  return <span className={`decision-pill ${decision}`}>{decision}</span>;
}

export default function App() {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [lang, setLang] = useState<Lang>("en");
  const [health, setHealth] = useState<Health | null>(null);
  const [history, setHistory] = useState<GateResult[]>([]);
  const [config, setConfig] = useState<EngineConfigView | null>(null);
  const [url, setUrl] = useState("");
  const [context, setContext] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<GateResult | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const L = useCallback((k: Parameters<typeof t>[1]) => t(lang, k), [lang]);

  const refresh = useCallback(async () => {
    try {
      const [h, hist, cfg] = await Promise.all([
        api.health(),
        api.history(80),
        api.config(),
      ]);
      setHealth(h);
      setHistory(hist.items);
      setConfig(cfg);
      setLang(cfg.language);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 8000);
    return () => clearInterval(id);
  }, [refresh]);

  useEffect(() => {
    if (!toast) return;
    const id = setTimeout(() => setToast(null), 2200);
    return () => clearTimeout(id);
  }, [toast]);

  async function runCheck() {
    if (!url.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const r = await api.check(url.trim(), context.trim() || undefined);
      setResult(r);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  async function saveSettings(patch: Partial<EngineConfigView> & { vtApiKey?: string | null }) {
    try {
      const cfg = await api.saveConfig(patch);
      setConfig(cfg);
      setLang(cfg.language);
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
          <div className="brand-mark">A</div>
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
          <div style={{ marginTop: 10 }}>
            v0.1.0 · MCP + HTTP
          </div>
        </div>
      </aside>

      <main className="main">
        {tab === "dashboard" && (
          <>
            <div className="page-header">
              <div>
                <h2>{L("dashboard")}</h2>
                <p className="sub">{L("status")}: Aegis core · policy {health?.policyMode ?? "—"}</p>
              </div>
              <button className="btn" onClick={() => setTab("check")}>
                {L("liveCheck")}
              </button>
            </div>

            <div className="stats">
              <div className="glass stat-card">
                <div className="label">{L("total")}</div>
                <div className="value">{stats?.total ?? 0}</div>
                <div className="hint">VT cache {health?.vtCache ?? 0}</div>
              </div>
              <div className="glass stat-card allow">
                <div className="label">{L("allow")}</div>
                <div className="value">{stats?.allow ?? 0}</div>
              </div>
              <div className="glass stat-card review">
                <div className="label">{L("review")}</div>
                <div className="value">{stats?.review ?? 0}</div>
              </div>
              <div className="glass stat-card block">
                <div className="label">{L("block")}</div>
                <div className="value">{stats?.block ?? 0}</div>
              </div>
            </div>

            <div className="grid-2">
              <section className="glass panel">
                <h3>{L("recent")}</h3>
                {recent.length === 0 ? (
                  <div className="empty">{L("noResults")}</div>
                ) : (
                  <div className="list-scroll">
                    <table className="table">
                      <thead>
                        <tr>
                          <th>{L("decision")}</th>
                          <th>{L("url")}</th>
                          <th>{L("score")}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {recent.map((item) => (
                          <tr key={item.id}>
                            <td>
                              <DecisionPill decision={item.decision} />
                            </td>
                            <td className="mono">{item.hostname || item.url}</td>
                            <td>{item.score}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>

              <section className="glass panel">
                <h3>{L("checkTitle")}</h3>
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
                {result && (
                  <div className="glass-soft result-card">
                    <div className="result-head">
                      <div className="url mono">{result.hostname}</div>
                      <div className="split">
                        <div className="score-ring">{result.score}</div>
                        <DecisionPill decision={result.decision} />
                      </div>
                    </div>
                    <div className="meta-grid">
                      <div className="glass-soft meta-item">
                        <div className="k">{L("official")}</div>
                        <div className="v">
                          {result.authority.official
                            ? result.authority.brand
                            : "—"}
                        </div>
                      </div>
                      <div className="glass-soft meta-item">
                        <div className="k">{L("subject")}</div>
                        <div className="v">{result.authority.subject ?? "—"}</div>
                      </div>
                      <div className="glass-soft meta-item">
                        <div className="k">{L("vt")}</div>
                        <div className="v">{result.virusTotal.status}</div>
                      </div>
                    </div>
                  </div>
                )}
              </section>
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
            <section className="glass panel">
              <div className="form-stack">
                <div className="field">
                  <label>URL</label>
                  <input
                    className="input"
                    placeholder={L("urlPlaceholder")}
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && runCheck()}
                  />
                </div>
                <div className="field">
                  <label>Context</label>
                  <input
                    className="input"
                    placeholder={L("contextPlaceholder")}
                    value={context}
                    onChange={(e) => setContext(e.target.value)}
                  />
                </div>
                <div>
                  <button className="btn" onClick={runCheck} disabled={loading || !url.trim()}>
                    {loading ? L("checking") : L("runCheck")}
                  </button>
                </div>
              </div>

              {result && (
                <div className="glass-soft result-card">
                  <div className="result-head">
                    <div>
                      <div className="url">{result.url}</div>
                      <div className="sub mono" style={{ color: "var(--text-dim)", marginTop: 4 }}>
                        {result.hostname} · {new Date(result.checkedAt).toLocaleString()}
                      </div>
                    </div>
                    <div className="split">
                      <div className="score-ring">{result.score}</div>
                      <DecisionPill decision={result.decision} />
                    </div>
                  </div>

                  <div className="meta-grid">
                    <div className="glass-soft meta-item">
                      <div className="k">{L("brand")}</div>
                      <div className="v">{result.authority.brand ?? "—"}</div>
                    </div>
                    <div className="glass-soft meta-item">
                      <div className="k">{L("subject")}</div>
                      <div className="v">{result.authority.subject ?? "—"}</div>
                    </div>
                    <div className="glass-soft meta-item">
                      <div className="k">{L("rdap")}</div>
                      <div className="v">
                        {result.authority.rdap.status}
                        {result.authority.rdap.organization
                          ? ` · ${result.authority.rdap.organization}`
                          : ""}
                      </div>
                    </div>
                    <div className="glass-soft meta-item">
                      <div className="k">{L("vt")}</div>
                      <div className="v">
                        {result.virusTotal.status} · mal {result.virusTotal.malicious} ·
                        sus {result.virusTotal.suspicious}
                        {result.virusTotal.cached ? " · cached" : ""}
                      </div>
                    </div>
                    <div className="glass-soft meta-item">
                      <div className="k">{L("lookalike")}</div>
                      <div className="v">{result.authority.lookalikeOf ?? "—"}</div>
                    </div>
                    <div className="glass-soft meta-item">
                      <div className="k">{L("official")}</div>
                      <div className="v">
                        {result.authority.official ? "yes" : "no"}
                        {result.authority.punycode ? " · punycode" : ""}
                      </div>
                    </div>
                  </div>

                  <h3 style={{ marginTop: 8 }}>{L("reasons")}</h3>
                  <div className="reasons">
                    {result.reasons.map((r, i) => (
                      <div className="reason" key={`${r.code}-${i}`}>
                        <span className={`sev ${r.severity}`}>{r.severity}</span>
                        <span>{r.message}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </section>
          </>
        )}

        {tab === "history" && (
          <>
            <div className="page-header">
              <div>
                <h2>{L("history")}</h2>
                <p className="sub">{history.length} records</p>
              </div>
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
            <section className="glass panel">
              {history.length === 0 ? (
                <div className="empty">{L("noResults")}</div>
              ) : (
                <div className="list-scroll" style={{ maxHeight: "65vh" }}>
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
                          <td className="mono">{item.hostname}</td>
                          <td>{item.score}</td>
                          <td>{item.virusTotal.status}</td>
                          <td>{item.authority.brand ?? "—"}</td>
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
            <section className="glass panel">
              <div className="form-stack">
                <div className="form-row">
                  <label>{L("vtKey")}</label>
                  <input
                    className="input"
                    type="password"
                    placeholder={config.hasVtKey ? "••••••••" : "VT API key"}
                    onChange={(e) => {
                      const v = e.target.value;
                      setConfig({ ...config, vtApiKey: v || null, hasVtKey: Boolean(v) });
                    }}
                  />
                  <div className="help">{L("vtKeyHelp")}</div>
                </div>

                <div className="form-row">
                  <label>{L("policy")}</label>
                  <select
                    className="input"
                    value={config.policyMode}
                    onChange={(e) =>
                      setConfig({
                        ...config,
                        policyMode: e.target.value as EngineConfigView["policyMode"],
                      })
                    }
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
                      setConfig({ ...config, language });
                      setLang(language);
                    }}
                  >
                    <option value="en">English</option>
                    <option value="zh">中文</option>
                  </select>
                </div>

                <div className="glass-soft toggle-row">
                  <div>
                    <div style={{ fontWeight: 600, fontSize: 14 }}>{L("enableRdap")}</div>
                    <div className="help" style={{ marginTop: 4 }}>
                      {L("enableRdapHelp")}
                    </div>
                  </div>
                  <button
                    className={`switch ${config.enableRdap ? "on" : ""}`}
                    aria-label="RDAP"
                    onClick={() =>
                      setConfig({ ...config, enableRdap: !config.enableRdap })
                    }
                  />
                </div>

                <div className="form-row">
                  <label>{L("allowlist")}</label>
                  <textarea
                    className="input"
                    rows={4}
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
                    rows={4}
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

                <div>
                  <button
                    className="btn"
                    onClick={() =>
                      saveSettings({
                        vtApiKey: config.vtApiKey,
                        policyMode: config.policyMode,
                        language: config.language,
                        enableRdap: config.enableRdap,
                        allowlist: config.allowlist,
                        denylist: config.denylist,
                      })
                    }
                  >
                    {L("save")}
                  </button>
                </div>
              </div>
            </section>
          </>
        )}

        {error && (
          <div className="glass toast" style={{ color: "var(--rose)" }}>
            {L("error")}: {error}
          </div>
        )}
        {toast && <div className="glass toast">{toast}</div>}
      </main>
    </div>
  );
}
