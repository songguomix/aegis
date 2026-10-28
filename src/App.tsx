import React, { useCallback, useEffect, useState } from "react";
import {
  api,
  type DeployBundle,
  type EngineConfigView,
  type GateResult,
  type Health,
  type IntegrationInfo,
  type ReviewItem,
  type SessionTrustEntry,
} from "./lib/api";
import { t, type Lang } from "./lib/i18n";
import { Sidebar, type Tab } from "./components/Sidebar";
import { DashboardTab } from "./components/tabs/DashboardTab";
import { CheckTab } from "./components/tabs/CheckTab";
import { HistoryTab } from "./components/tabs/HistoryTab";
import { SandboxTab } from "./components/tabs/SandboxTab";
import { SettingsTab } from "./components/tabs/SettingsTab";
import { IntegrateTab } from "./components/tabs/IntegrateTab";
import { Toast, type ToastMessage } from "./components/Toast";

export default function App() {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [lang, setLang] = useState<Lang>("en");
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    const saved = localStorage.getItem("aegis_theme");
    if (saved === "dark" || saved === "light") return saved;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "dark"; // Default to dark cyber theme
  });

  const [health, setHealth] = useState<Health | null>(null);
  const [history, setHistory] = useState<GateResult[]>([]);
  const [config, setConfig] = useState<EngineConfigView | null>(null);
  const [integration, setIntegration] = useState<IntegrationInfo | null>(null);
  const [deployBundle, setDeployBundle] = useState<DeployBundle | null>(null);
  const [reviews, setReviews] = useState<ReviewItem[]>([]);
  const [sessionTrust, setSessionTrust] = useState<SessionTrustEntry[]>([]);
  const [customBrandsText, setCustomBrandsText] = useState("");
  const [selectedHistoryRecord, setSelectedHistoryRecord] = useState<GateResult | null>(null);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  // Apply theme to document element
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("aegis_theme", theme);
  }, [theme]);

  // Toast Helpers
  const addToast = useCallback((text: string, type: "info" | "success" | "error" = "info") => {
    const id = Math.random().toString(36).substring(2, 9);
    setToasts((prev) => [...prev, { id, text, type }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 3200);
  }, []);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  // Fast periodic refresh: health & reviews
  const refreshFast = useCallback(async () => {
    try {
      const [h, rev] = await Promise.all([
        api.health(),
        api.reviews().catch(() => ({ items: [], stats: { pending: 0, allowed: 0, blocked: 0 } })),
      ]);
      setHealth(h);
      setReviews(rev.items);
    } catch {
      // offline / starting up
    }
  }, []);

  // Full refresh
  const refreshAll = useCallback(async () => {
    try {
      const [h, hist, cfg, integ, rev, trust] = await Promise.all([
        api.health(),
        api.history(100),
        api.config(),
        api.integration().catch(() => null),
        api.reviews().catch(() => ({ items: [], stats: { pending: 0, allowed: 0, blocked: 0 } })),
        api.sessionTrust().catch(() => ({ items: [] })),
      ]);
      setHealth(h);
      setHistory(hist.items);
      setConfig(cfg);
      setLang(cfg.language);
      setCustomBrandsText(
        (cfg.customBrands ?? [])
          .map((b) => `${b.host} | ${b.brand} | ${b.subject || ""}`)
          .join("\n"),
      );
      if (integ) setIntegration(integ);
      setReviews(rev.items);
      setSessionTrust(trust.items);
    } catch (e) {
      addToast(e instanceof Error ? e.message : String(e), "error");
    }
  }, [addToast]);

  // Initial load
  useEffect(() => {
    void refreshAll();
    const interval = setInterval(refreshFast, 6000);
    return () => clearInterval(interval);
  }, [refreshAll, refreshFast]);

  // Fetch deploy bundle lazily when Integrate tab opens
  useEffect(() => {
    if (tab === "integrate" && !deployBundle) {
      void api.mcpDeployBundle()
        .then(setDeployBundle)
        .catch(() => null);
    }
  }, [tab, deployBundle]);

  // Handlers
  async function handleCheckUrl(url: string): Promise<GateResult | void> {
    try {
      const res = await api.check(url);
      setHistory((prev) => [res, ...prev.filter((h) => h.id !== res.id)]);
      addToast(`Checked: ${res.hostname} (${res.decision})`, res.decision === "block" ? "error" : "success");
      void refreshFast();
      return res;
    } catch (e) {
      addToast(e instanceof Error ? e.message : String(e), "error");
    }
  }

  async function handleResolveReview(id: string, decision: "allow" | "block", alwaysAllow = false) {
    try {
      await api.resolveReview(id, decision, {
        alwaysAllow,
        by: "user",
        sessionTrust: decision === "allow",
      });
      addToast(decision === "allow" ? "Approved and allowed" : "Blocked", "success");
      await refreshAll();
    } catch (e) {
      addToast(e instanceof Error ? e.message : String(e), "error");
    }
  }

  async function handleSaveSettings(patch: Partial<EngineConfigView> & { vtApiKey?: string | null }) {
    try {
      const cfg = await api.saveConfig(patch);
      setConfig(cfg);
      setLang(cfg.language);
      addToast(t(cfg.language, "saved"), "success");
      await refreshAll();
    } catch (e) {
      addToast(e instanceof Error ? e.message : String(e), "error");
    }
  }

  async function handleExportHistory(format: "csv" | "json") {
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
      addToast(`Exported history as ${format.toUpperCase()}`, "success");
    } catch (e) {
      addToast(e instanceof Error ? e.message : String(e), "error");
    }
  }

  async function handleClearHistory() {
    try {
      await api.clearHistory();
      setHistory([]);
      addToast(t(lang, "historyCleared"), "success");
    } catch (e) {
      addToast(e instanceof Error ? e.message : String(e), "error");
    }
  }

  async function handleUntrustDomain(host: string) {
    try {
      await api.untrustDomain(host);
      setSessionTrust((prev) => prev.filter((t) => t.hostname !== host));
      addToast(`Removed session trust: ${host}`, "info");
    } catch (e) {
      addToast(e instanceof Error ? e.message : String(e), "error");
    }
  }

  async function handleClearSessionTrust() {
    try {
      await api.clearSessionTrust();
      setSessionTrust([]);
      addToast("Cleared session trusts", "info");
    } catch (e) {
      addToast(e instanceof Error ? e.message : String(e), "error");
    }
  }

  async function handleDownloadZip() {
    try {
      const url = await api.mcpDeployZipUrl();
      const a = document.createElement("a");
      a.href = url;
      a.download = "aegis-mcp-deploy.zip";
      a.click();
      addToast("Downloaded MCP deploy bundle", "success");
    } catch (e) {
      addToast(e instanceof Error ? e.message : String(e), "error");
    }
  }

  return (
    <div className="app-shell">
      <Sidebar
        tab={tab}
        setTab={setTab}
        lang={lang}
        setLang={(l) => {
          setLang(l);
          if (config) void handleSaveSettings({ language: l });
        }}
        theme={theme}
        setTheme={setTheme}
        vtMode={health?.stats?.vtMode ?? "degraded"}
        pendingCount={reviews.length}
      />

      <main className="main">
        <div className={`main-inner ${tab === "history" || tab === "settings" || tab === "integrate" || tab === "sandbox" ? "wide" : ""}`}>
          {tab === "dashboard" && (
            <DashboardTab
              lang={lang}
              health={health}
              history={history}
              reviews={reviews}
              onCheckUrl={handleCheckUrl}
              onResolveReview={handleResolveReview}
              onSelectRecord={(rec) => {
                setSelectedHistoryRecord(rec);
                setTab("history");
              }}
              onNavigateToCheck={() => setTab("check")}
            />
          )}

          {tab === "check" && (
            <CheckTab
              lang={lang}
              maxUploadBytes={config?.maxUploadBytes ?? 33554432}
              onRefresh={refreshAll}
              onToast={(msg) => addToast(msg, "info")}
              onError={(err) => addToast(err, "error")}
            />
          )}

          {tab === "history" && (
            <HistoryTab
              lang={lang}
              history={history}
              onExport={handleExportHistory}
              onClearHistory={handleClearHistory}
              selectedItem={selectedHistoryRecord}
              onSelectItem={setSelectedHistoryRecord}
            />
          )}

          {tab === "sandbox" && (
            <SandboxTab
              lang={lang}
              onToast={(msg) => addToast(msg, "info")}
              onError={(err) => addToast(err, "error")}
            />
          )}

          {tab === "settings" && config && (
            <SettingsTab
              lang={lang}
              config={config}
              sessionTrust={sessionTrust}
              customBrandsText={customBrandsText}
              setCustomBrandsText={setCustomBrandsText}
              onSave={handleSaveSettings}
              onUntrustDomain={handleUntrustDomain}
              onClearSessionTrust={handleClearSessionTrust}
            />
          )}

          {tab === "integrate" && (
            <IntegrateTab
              lang={lang}
              integration={integration}
              deployBundle={deployBundle}
              onDownloadZip={handleDownloadZip}
              onToast={(msg) => addToast(msg, "info")}
              onError={(err) => addToast(err, "error")}
            />
          )}
        </div>

        <Toast toasts={toasts} onDismiss={dismissToast} />
      </main>
    </div>
  );
}
