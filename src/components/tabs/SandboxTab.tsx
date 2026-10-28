import React, { useState } from "react";
import {
  api,
  type InstallerAnalysis,
  type SandboxRunResult,
} from "../../lib/api";
import { t, type Lang } from "../../lib/i18n";
import {
  IconBox,
  IconTerminal,
  IconAlertTriangle,
  IconCheckCircle,
  IconCopy,
  IconCheck,
} from "../Icons";

interface SandboxTabProps {
  lang: Lang;
  onToast: (msg: string) => void;
  onError: (err: string) => void;
}

export function SandboxTab({ lang, onToast, onError }: SandboxTabProps) {
  const L = (k: Parameters<typeof t>[1]) => t(lang, k);

  const [activeSubTab, setActiveSubTab] = useState<"probe" | "sandbox">("probe");

  // Installer probe state
  const [filePath, setFilePath] = useState("");
  const [probeLoading, setProbeLoading] = useState(false);
  const [analysis, setAnalysis] = useState<InstallerAnalysis | null>(null);

  // Sandbox run state
  const [commandStr, setCommandStr] = useState("file --mime-type");
  const [targetPath, setTargetPath] = useState("");
  const [sandboxLoading, setSandboxLoading] = useState(false);
  const [sandboxResult, setSandboxResult] = useState<SandboxRunResult | null>(null);

  // Copied helper
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  async function copyText(key: string, text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
      onToast(L("copied"));
    } catch {
      onError("Failed to copy");
    }
  }

  // Run Static Probe
  async function runProbe() {
    if (!filePath.trim() || probeLoading) return;
    setProbeLoading(true);
    try {
      const res = await api.analyzeInstaller(filePath.trim());
      setAnalysis(res);
      onToast("Static analysis complete");
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setProbeLoading(false);
    }
  }

  // Run Sandbox Command
  async function runSandbox() {
    if (!commandStr.trim() || sandboxLoading) return;
    setSandboxLoading(true);
    try {
      let argv: string[] = [];
      const trimmed = commandStr.trim();
      if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
        argv = JSON.parse(trimmed) as string[];
      } else {
        argv = trimmed.split(/\s+/).filter(Boolean);
      }

      const res = await api.sandboxRun(argv, {
        target: targetPath.trim() || undefined,
        allowUnisolated: true,
      });
      setSandboxResult(res);
      onToast(`Execution finished (exit ${res.exitCode ?? 0})`);
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setSandboxLoading(false);
    }
  }

  return (
    <div className="tab-container">
      <div className="page-header">
        <div>
          <h2>{L("sandboxTitle")}</h2>
          <p className="sub">{L("sandboxSub")}</p>
        </div>
      </div>

      <div className="stack">
        {/* Sub-tab selection */}
        <div className="seg" role="tablist">
          <button
            type="button"
            className={`seg-item ${activeSubTab === "probe" ? "active" : ""}`}
            onClick={() => setActiveSubTab("probe")}
          >
            <IconBox size={14} style={{ marginRight: 6 }} />
            {L("openProbe")}
          </button>
          <button
            type="button"
            className={`seg-item ${activeSubTab === "sandbox" ? "active" : ""}`}
            onClick={() => setActiveSubTab("sandbox")}
          >
            <IconTerminal size={14} style={{ marginRight: 6 }} />
            {L("openSandbox")}
          </button>
        </div>

        {/* 1. Static Package / Installer Probe */}
        {activeSubTab === "probe" && (
          <>
            <section className="panel">
              <div className="panel-head">
                <h3>{L("analyzeInstallerTitle")}</h3>
              </div>
              <p className="help" style={{ margin: "0 0 12px" }}>
                {L("analyzeInstallerSub")}
              </p>
              <div className="check-row">
                <div className="field">
                  <input
                    className="input mono"
                    placeholder={L("installerPathPlaceholder")}
                    value={filePath}
                    onChange={(e) => setFilePath(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && runProbe()}
                  />
                </div>
                <button
                  className="btn btn-primary"
                  onClick={runProbe}
                  disabled={probeLoading || !filePath.trim()}
                >
                  {probeLoading ? L("analyzing") : L("analyzeBtn")}
                </button>
              </div>
            </section>

            {analysis && (
              <section className="panel result">
                <div className="result-head">
                  <div>
                    <div className="url mono">{analysis.fileName || analysis.path}</div>
                    <div className="sub">
                      {analysis.kind} · {(analysis.size / 1024).toFixed(1)} KB · MIME:{" "}
                      {analysis.mimeGuess}
                    </div>
                  </div>
                  <div className="split">
                    <span
                      className={`decision-pill ${analysis.riskFlags?.length ? "review" : "allow"}`}
                    >
                      {analysis.riskFlags?.length ? "SUSPICIOUS" : "CLEAN"}
                    </span>
                  </div>
                </div>

                {/* AI Brief Alert */}
                {analysis.aiBrief && (
                  <div className="ask-box" style={{ background: "rgba(59, 130, 246, 0.08)", borderColor: "rgba(59, 130, 246, 0.25)" }}>
                    <div className="ask-title" style={{ color: "#2563eb" }}>
                      {L("aiBrief")}
                    </div>
                    <p style={{ margin: "6px 0 0", fontSize: 13, lineHeight: 1.5 }}>
                      {analysis.aiBrief}
                    </p>
                  </div>
                )}

                {/* Hashes & Entropy Grid */}
                <div className="meta-grid cols-2" style={{ marginTop: 14 }}>
                  <div className="meta-item">
                    <div className="k">SHA-256 Hash</div>
                    <div className="v mono text-xs split">
                      <span className="truncate-cell">{analysis.hashes?.sha256}</span>
                      <button
                        className="btn btn-ghost btn-xs"
                        onClick={() => copyText("sha256", analysis.hashes?.sha256 || "")}
                      >
                        {copiedKey === "sha256" ? <IconCheck size={11} /> : <IconCopy size={11} />}
                      </button>
                    </div>
                  </div>
                  <div className="meta-item">
                    <div className="k">{L("entropy")} (Shannon)</div>
                    <div className="v">
                      <span className="font-semibold">{analysis.entropy?.toFixed(2)}</span> / 8.00
                      <span className="text-muted text-xs" style={{ marginLeft: 8 }}>
                        {analysis.entropy > 7.2
                          ? "High (likely packed / encrypted)"
                          : "Normal (standard binary / code)"}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Risk Flags */}
                {analysis.riskFlags && analysis.riskFlags.length > 0 && (
                  <div style={{ marginTop: 14 }}>
                    <div className="panel-head">
                      <h3>{L("riskFlags")}</h3>
                    </div>
                    <div className="reasons">
                      {analysis.riskFlags.map((flag, idx) => (
                        <div className="reason" key={idx}>
                          <span className="sev warn">flag</span>
                          <span className="reason-msg font-medium">{flag}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Suspicious Strings */}
                {analysis.suspiciousStrings && analysis.suspiciousStrings.length > 0 && (
                  <div style={{ marginTop: 14 }}>
                    <div className="panel-head">
                      <h3>Suspicious Strings Detected</h3>
                    </div>
                    <div className="code-block">
                      <pre className="code">{analysis.suspiciousStrings.join("\n")}</pre>
                    </div>
                  </div>
                )}

                {/* Embedded URLs & IPs */}
                {((analysis.urls && analysis.urls.length > 0) ||
                  (analysis.ips && analysis.ips.length > 0)) && (
                  <div style={{ marginTop: 14 }}>
                    <div className="panel-head">
                      <h3>{L("embeddedUrls")} & Network Targets</h3>
                    </div>
                    <ul className="tool-list">
                      {analysis.urls?.map((u, i) => (
                        <li key={`url-${i}`}>
                          <code className="mono">{u}</code>
                        </li>
                      ))}
                      {analysis.ips?.map((ip, i) => (
                        <li key={`ip-${i}`}>
                          <code className="mono">{ip}</code>
                          <span className="text-muted">IPv4 Address</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Archive Members */}
                {analysis.archiveMembers && analysis.archiveMembers.length > 0 && (
                  <div style={{ marginTop: 14 }}>
                    <div className="panel-head">
                      <h3>{L("archiveMembers")} ({analysis.archiveMembers.length})</h3>
                    </div>
                    <div className="code-block" style={{ maxHeight: 180, overflow: "auto" }}>
                      <pre className="code">{analysis.archiveMembers.join("\n")}</pre>
                    </div>
                  </div>
                )}
              </section>
            )}
          </>
        )}

        {/* 2. Sandbox Execution Tester */}
        {activeSubTab === "sandbox" && (
          <>
            <section className="panel">
              <div className="panel-head">
                <h3>Sandbox Execution Tester</h3>
              </div>
              <p className="help" style={{ margin: "0 0 12px" }}>
                Execute safe read-only inspection commands with zero network access and strict filesystem boundaries.
              </p>
              <div className="form-stack">
                <div className="form-row">
                  <label>{L("sandboxCommand")}</label>
                  <input
                    className="input mono"
                    placeholder="e.g. file --mime-type, ls -la, strings -n 8"
                    value={commandStr}
                    onChange={(e) => setCommandStr(e.target.value)}
                  />
                </div>
                <div className="form-row">
                  <label>Target Artifact Path (optional staging)</label>
                  <input
                    className="input mono"
                    placeholder="/path/to/downloaded/file to stage inside sandbox"
                    value={targetPath}
                    onChange={(e) => setTargetPath(e.target.value)}
                  />
                </div>
                <div>
                  <button
                    className="btn btn-primary"
                    onClick={runSandbox}
                    disabled={sandboxLoading || !commandStr.trim()}
                  >
                    {sandboxLoading ? L("sandboxRunning") : L("sandboxRunBtn")}
                  </button>
                </div>
              </div>
            </section>

            {sandboxResult && (
              <section className="panel result">
                <div className="result-head">
                  <div>
                    <div className="url mono">{sandboxResult.argv?.join(" ")}</div>
                    <div className="sub">
                      Mode: <span className="mono">{sandboxResult.mode}</span> · Duration:{" "}
                      {sandboxResult.durationMs}ms · Exit: {sandboxResult.exitCode ?? 0}
                    </div>
                  </div>
                  <div className="split">
                    {sandboxResult.isolated ? (
                      <span className="badge live">
                        <IconCheckCircle size={12} style={{ marginRight: 4 }} />
                        {L("sandboxIsolated")}
                      </span>
                    ) : (
                      <span className="badge degraded">
                        <IconAlertTriangle size={12} style={{ marginRight: 4 }} />
                        {L("sandboxRestricted")}
                      </span>
                    )}
                  </div>
                </div>

                {sandboxResult.warning && (
                  <div className="ask-box" style={{ background: "rgba(245, 158, 11, 0.08)", borderColor: "rgba(245, 158, 11, 0.3)" }}>
                    <div className="ask-title">{L("unisolatedWarning")}</div>
                    <p style={{ margin: "4px 0 0", fontSize: 12.5, lineHeight: 1.45 }}>
                      {sandboxResult.warning}
                    </p>
                  </div>
                )}

                <div className="panel-head" style={{ marginTop: 14 }}>
                  <h3>{L("sandboxOutput")} (stdout)</h3>
                </div>
                <div className="code-block">
                  <pre className="code">{sandboxResult.stdout || "(no stdout)"}</pre>
                </div>

                {sandboxResult.stderr && (
                  <div style={{ marginTop: 14 }}>
                    <div className="panel-head">
                      <h3>Standard Error (stderr)</h3>
                    </div>
                    <div className="code-block">
                      <pre className="code text-warn">{sandboxResult.stderr}</pre>
                    </div>
                  </div>
                )}
              </section>
            )}
          </>
        )}
      </div>
    </div>
  );
}
