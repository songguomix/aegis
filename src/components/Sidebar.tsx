import React from "react";
import logoImg from "../assets/logo.jpg";
import type { Lang } from "../lib/i18n";
import { t } from "../lib/i18n";
import {
  IconShield,
  IconActivity,
  IconSearch,
  IconHistory,
  IconBox,
  IconSettings,
  IconTerminal,
  IconMoon,
  IconSun,
} from "./Icons";

export type Tab = "dashboard" | "check" | "history" | "sandbox" | "settings" | "integrate";

interface SidebarProps {
  tab: Tab;
  setTab: (tab: Tab) => void;
  lang: Lang;
  setLang: (lang: Lang) => void;
  theme: "light" | "dark";
  setTheme: (theme: "light" | "dark") => void;
  vtMode: "live" | "degraded";
  pendingCount?: number;
}

export function Sidebar({
  tab,
  setTab,
  lang,
  setLang,
  theme,
  setTheme,
  vtMode,
  pendingCount = 0,
}: SidebarProps) {
  const L = (k: Parameters<typeof t>[1]) => t(lang, k);

  const navItems: Array<{ id: Tab; label: string; icon: React.ReactNode; badge?: number }> = [
    { id: "dashboard", label: L("dashboard"), icon: <IconActivity size={16} />, badge: pendingCount },
    { id: "check", label: L("liveCheck"), icon: <IconSearch size={16} /> },
    { id: "history", label: L("history"), icon: <IconHistory size={16} /> },
    { id: "sandbox", label: L("modeSandbox"), icon: <IconBox size={16} /> },
    { id: "settings", label: L("settings"), icon: <IconSettings size={16} /> },
    { id: "integrate", label: L("integrate"), icon: <IconTerminal size={16} /> },
  ];

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-icon">
          <img
            src={logoImg}
            alt="Aegis Logo"
            className="brand-logo-img"
          />
        </div>
        <div>
          <h1>Aegis</h1>
          <p>{L("brandTag")}</p>
        </div>
      </div>

      <nav className="nav">
        {navItems.map((item) => (
          <button
            key={item.id}
            className={`nav-btn ${tab === item.id ? "active" : ""}`}
            onClick={() => setTab(item.id)}
          >
            <span className="nav-icon">{item.icon}</span>
            <span className="nav-label">{item.label}</span>
            {Boolean(item.badge && item.badge > 0) && (
              <span className="nav-badge review">{item.badge}</span>
            )}
          </button>
        ))}
      </nav>

      <div className="sidebar-foot">
        <div className="engine-status">
          {vtMode === "live" ? (
            <span className="badge live">● {L("modeLive")}</span>
          ) : (
            <span className="badge degraded">● {L("modeDegraded")}</span>
          )}
        </div>

        <div className="sidebar-actions">
          <button
            className="foot-btn"
            title={theme === "dark" ? L("themeLight") : L("themeDark")}
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
          >
            {theme === "dark" ? <IconSun size={14} /> : <IconMoon size={14} />}
            <span>{theme === "dark" ? L("themeLight") : L("themeDark")}</span>
          </button>

          <button
            className="foot-btn"
            title="Toggle Language"
            onClick={() => setLang(lang === "en" ? "zh" : "en")}
          >
            <span className="lang-tag">{lang === "en" ? "中文" : "EN"}</span>
          </button>
        </div>

        <div className="ver">v0.1.0 · MCP + HTTP</div>
      </div>
    </aside>
  );
}
