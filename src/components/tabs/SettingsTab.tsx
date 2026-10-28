import React, { useState } from "react";
import type { EngineConfigView, SessionTrustEntry } from "../../lib/api";
import { t, type Lang } from "../../lib/i18n";
import { IconTrash } from "../Icons";

interface SettingsTabProps {
  lang: Lang;
  config: EngineConfigView;
  sessionTrust: SessionTrustEntry[];
  customBrandsText: string;
  setCustomBrandsText: (text: string) => void;
  onSave: (patch: Partial<EngineConfigView> & { vtApiKey?: string | null }) => Promise<void>;
  onUntrustDomain: (host: string) => Promise<void>;
  onClearSessionTrust: () => Promise<void>;
}

export function SettingsTab({
  lang,
  config: initialConfig,
  sessionTrust,
  customBrandsText,
  setCustomBrandsText,
  onSave,
  onUntrustDomain,
  onClearSessionTrust,
}: SettingsTabProps) {
  const L = (k: Parameters<typeof t>[1]) => t(lang, k);

  const [form, setForm] = useState<EngineConfigView>({ ...initialConfig });
  const [showKey, setShowKey] = useState(false);
  const [dirty, setDirty] = useState(false);

  function updateField<K extends keyof EngineConfigView>(key: K, val: EngineConfigView[K]) {
    setForm((prev) => ({ ...prev, [key]: val }));
    setDirty(true);
  }

  async function handleSave() {
    const brands = customBrandsText
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
      .filter((b) => b.host && b.brand);

    await onSave({
      vtApiKey: form.vtApiKey,
      policyMode: form.policyMode,
      language: form.language,
      enableRdap: form.enableRdap,
      allowlist: form.allowlist,
      denylist: form.denylist,
      soundEnabled: form.soundEnabled !== false,
      maxUploadBytes: form.maxUploadBytes ?? 33554432,
      customBrands: brands,
    });
    setDirty(false);
  }

  return (
    <div className="tab-container">
      <div className="page-header">
        <div>
          <h2>{L("settingsTitle")}</h2>
          <p className="sub">{L("settingsSub")}</p>
        </div>
        <div className="actions">
          <button
            className={`btn btn-primary ${dirty ? "btn-glow" : ""}`}
            onClick={handleSave}
          >
            {L("save")}
          </button>
        </div>
      </div>

      <div className="settings-layout">
        {/* Left Column: Core Engine Settings */}
        <section className="panel">
          <div className="panel-head">
            <h3>Threat Engine & VirusTotal</h3>
          </div>
          <div className="form-stack full">
            <div className="form-row">
              <label>{L("vtKey")}</label>
              <div className="split" style={{ gap: 8 }}>
                <input
                  className="input mono"
                  type={showKey ? "text" : "password"}
                  placeholder={form.hasVtKey ? "••••••••••••••••" : "Paste VT API key here"}
                  value={form.vtApiKey ?? ""}
                  onChange={(e) => updateField("vtApiKey", e.target.value || null)}
                />
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  onClick={() => setShowKey(!showKey)}
                >
                  {showKey ? "Hide" : "Show"}
                </button>
              </div>
              <div className="help">{L("vtKeyHelp")}</div>
            </div>

            <div className="form-grid-2 policy-row">
              <div className="form-row">
                <label>{L("policy")}</label>
                <select
                  className="input"
                  value={form.policyMode}
                  onChange={(e) =>
                    updateField("policyMode", e.target.value as EngineConfigView["policyMode"])
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
                  value={form.language}
                  onChange={(e) => updateField("language", e.target.value as Lang)}
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
                value={Math.round((form.maxUploadBytes ?? 33554432) / (1024 * 1024))}
                onChange={(e) => {
                  const mb = Math.min(64, Math.max(1, Number(e.target.value) || 32));
                  updateField("maxUploadBytes", mb * 1024 * 1024);
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
                type="button"
                className={`switch ${form.enableRdap ? "on" : ""}`}
                aria-label="RDAP Toggle"
                onClick={() => updateField("enableRdap", !form.enableRdap)}
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
                type="button"
                className={`switch ${form.soundEnabled !== false ? "on" : ""}`}
                aria-label="Sound Toggle"
                onClick={() => updateField("soundEnabled", form.soundEnabled === false)}
              />
            </div>
          </div>
        </section>

        {/* Right Column: Access Lists & Session Trust */}
        <section className="panel">
          <div className="panel-head">
            <h3>Domain Controls & Authority Rules</h3>
          </div>
          <div className="form-stack full">
            <div className="form-grid-2">
              <div className="form-row">
                <label>{L("allowlist")}</label>
                <textarea
                  className="input mono"
                  rows={4}
                  placeholder="corp.internal.net"
                  value={form.allowlist.join("\n")}
                  onChange={(e) =>
                    updateField(
                      "allowlist",
                      e.target.value.split("\n").map((s) => s.trim()).filter(Boolean),
                    )
                  }
                />
                <div className="help">{L("allowlistHelp")}</div>
              </div>

              <div className="form-row">
                <label>{L("denylist")}</label>
                <textarea
                  className="input mono"
                  rows={4}
                  placeholder="badsite.org"
                  value={form.denylist.join("\n")}
                  onChange={(e) =>
                    updateField(
                      "denylist",
                      e.target.value.split("\n").map((s) => s.trim()).filter(Boolean),
                    )
                  }
                />
                <div className="help">{L("denylistHelp")}</div>
              </div>
            </div>

            <div className="form-row">
              <label>{L("customBrands")}</label>
              <textarea
                className="input mono"
                rows={3}
                placeholder="intranet.corp.example | Acme | Acme Internal"
                value={customBrandsText}
                onChange={(e) => {
                  setCustomBrandsText(e.target.value);
                  setDirty(true);
                }}
              />
              <div className="help">{L("customBrandsHelp")}</div>
            </div>

            {/* Session Trust Entries */}
            <div className="form-row">
              <div className="split">
                <label>{L("sessionTrust")}</label>
                {sessionTrust.length > 0 && (
                  <button
                    type="button"
                    className="btn btn-ghost btn-xs deny-btn"
                    onClick={onClearSessionTrust}
                  >
                    <IconTrash size={11} style={{ marginRight: 4 }} />
                    {L("clearTrust")}
                  </button>
                )}
              </div>
              <div className="glass-soft" style={{ overflow: "hidden", maxHeight: 180, overflowY: "auto" }}>
                {sessionTrust.length === 0 ? (
                  <div className="empty" style={{ padding: 12 }}>
                    No active session trusts
                  </div>
                ) : (
                  sessionTrust.map((t) => (
                    <div className="trust-row" key={t.hostname}>
                      <code className="mono">{t.hostname}</code>
                      <span className="trust-badge">{t.source}</span>
                      <button
                        type="button"
                        className="btn btn-ghost btn-xs"
                        onClick={() => onUntrustDomain(t.hostname)}
                        title="Remove session trust"
                      >
                        ×
                      </button>
                    </div>
                  ))
                )}
              </div>
              <div className="help">{L("sessionTrustHelp")}</div>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
