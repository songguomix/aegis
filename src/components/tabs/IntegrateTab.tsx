import React, { useState } from "react";
import type { DeployBundle, IntegrationInfo } from "../../lib/api";
import { t, type Lang } from "../../lib/i18n";
import {
  IconCopy,
  IconCheck,
  IconDownload,
  IconTerminal,
  IconSearch,
} from "../Icons";

interface IntegrateTabProps {
  lang: Lang;
  integration: IntegrationInfo | null;
  deployBundle: DeployBundle | null;
  onDownloadZip: () => Promise<void>;
  onToast: (msg: string) => void;
  onError: (err: string) => void;
}

export function IntegrateTab({
  lang,
  integration,
  deployBundle,
  onDownloadZip,
  onToast,
  onError,
}: IntegrateTabProps) {
  const L = (k: Parameters<typeof t>[1]) => t(lang, k);

  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [toolSearch, setToolSearch] = useState("");

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

  const mcpJsonStr =
    deployBundle?.files.find((f) => f.filename === "mcp.claude.json")?.content ||
    (integration?.mcpConfig ? JSON.stringify(integration.mcpConfig, null, 2) : "");

  const mcpCommandStr = deployBundle?.mcpCommand || integration?.mcpCommand || "";

  const tools = integration?.tools ?? [];
  const filteredTools = tools.filter((tool) => {
    if (!toolSearch.trim()) return true;
    const q = toolSearch.trim().toLowerCase();
    return tool.name.toLowerCase().includes(q) || tool.description.toLowerCase().includes(q);
  });

  return (
    <div className="tab-container">
      <div className="page-header">
        <div>
          <h2>{L("integrateTitle")}</h2>
          <p className="sub">{L("integrateSub")}</p>
        </div>
      </div>

      <div className="stack">
        {/* Agent Guard Protocol Banner */}
        <section className="panel">
          <div className="panel-head">
            <h3>{L("agentGuard")}</h3>
          </div>
          <p className="help" style={{ margin: "0 0 12px" }}>
            {L("agentGuardSub")}
          </p>
          <ul className="tool-list">
            <li>
              <code className="protocol-code">preflight</code>
              <span>{L("agPreflight")}</span>
            </li>
            <li>
              <code className="protocol-code allow">allow</code>
              <span>{L("agAllow")}</span>
            </li>
            <li>
              <code className="protocol-code block">block</code>
              <span>{L("agBlock")}</span>
            </li>
            <li>
              <code className="protocol-code review">review</code>
              <span>{L("agReview")}</span>
            </li>
            <li>
              <code className="protocol-code">search</code>
              <span>{L("agSearch")}</span>
            </li>
            <li>
              <code className="protocol-code">files</code>
              <span>{L("agFiles")}</span>
            </li>
          </ul>
        </section>

        {/* One-click MCP Deploy Bundle */}
        <section className="panel">
          <div className="panel-head">
            <h3>{L("deployBundle")}</h3>
          </div>
          <p className="help" style={{ margin: "0 0 12px" }}>
            {L("deployBundleSub")}
          </p>

          <div className="code-block">
            <div className="code-block-head">
              <span>MCP CLI Command</span>
              <button
                className="btn btn-ghost btn-xs"
                onClick={() => copyText("deploy-cmd", mcpCommandStr)}
              >
                {copiedKey === "deploy-cmd" ? <IconCheck size={12} /> : <IconCopy size={12} />}
                <span style={{ marginLeft: 4 }}>
                  {copiedKey === "deploy-cmd" ? L("copied") : L("copy")}
                </span>
              </button>
            </div>
            <pre className="code">{mcpCommandStr || "node … --mcp"}</pre>
          </div>

          <div className="split" style={{ marginTop: 14, flexWrap: "wrap", gap: 10 }}>
            <button
              className="btn btn-primary"
              onClick={() => copyText("deploy-json", mcpJsonStr)}
            >
              <IconCopy size={14} style={{ marginRight: 6 }} />
              {L("copyMcpJson")}
            </button>
            <button
              className="btn btn-ghost"
              onClick={() => void onDownloadZip()}
            >
              <IconDownload size={14} style={{ marginRight: 6 }} />
              {L("downloadZip")}
            </button>
          </div>
          <p className="help" style={{ marginTop: 8 }}>
            {L("installHint")}
          </p>
        </section>

        {/* MCP Stdio Reference & Config */}
        <section className="panel">
          <div className="panel-head">
            <h3>{L("mcpSection")}</h3>
          </div>
          <p className="help" style={{ margin: "0 0 12px" }}>
            {L("mcpSub")}
          </p>

          <div className="code-block">
            <div className="code-block-head">
              <span>mcpServers JSON Config (Claude Desktop / Cursor)</span>
              <button
                className="btn btn-ghost btn-xs"
                onClick={() => copyText("mcp-config", mcpJsonStr)}
              >
                {copiedKey === "mcp-config" ? <IconCheck size={12} /> : <IconCopy size={12} />}
                <span style={{ marginLeft: 4 }}>
                  {copiedKey === "mcp-config" ? L("copied") : L("copy")}
                </span>
              </button>
            </div>
            <pre className="code">{mcpJsonStr || "{}"}</pre>
          </div>

          {/* Tools List with Live Filter */}
          <div className="panel-head" style={{ marginTop: 20 }}>
            <h3>
              {L("mcpTools")} ({tools.length})
            </h3>
            <div className="search-box" style={{ maxWidth: 220 }}>
              <IconSearch size={13} className="search-icon" />
              <input
                className="input input-sm search-input"
                placeholder="Filter tools..."
                value={toolSearch}
                onChange={(e) => setToolSearch(e.target.value)}
              />
            </div>
          </div>

          <ul className="tool-list">
            {filteredTools.map((tool) => (
              <li key={tool.name}>
                <code className="tool-tag">{tool.name}</code>
                <span className="tool-desc">{tool.description}</span>
                {tool.input.length > 0 && (
                  <em className="mono tool-params">({tool.input.join(", ")})</em>
                )}
              </li>
            ))}
          </ul>
        </section>

        {/* Direct HTTP API Section */}
        <section className="panel">
          <div className="panel-head">
            <h3>{L("httpSection")}</h3>
          </div>
          <p className="help" style={{ margin: "0 0 12px" }}>
            {L("httpSub")}
          </p>

          <div className="code-block">
            <div className="code-block-head">
              <span>{L("httpExample")} (curl)</span>
              <button
                className="btn btn-ghost btn-xs"
                onClick={() =>
                  copyText(
                    "curl",
                    `curl -sS ${integration?.http.checkUrl || "http://127.0.0.1:7832/api/v1/check"} \\\n  -H 'content-type: application/json' \\\n  -d '${JSON.stringify(
                      integration?.http.example.body || { url: "https://github.com/org/repo" },
                      null,
                      2,
                    )}'`,
                  )
                }
              >
                {copiedKey === "curl" ? <IconCheck size={12} /> : <IconCopy size={12} />}
                <span style={{ marginLeft: 4 }}>
                  {copiedKey === "curl" ? L("copied") : L("copy")}
                </span>
              </button>
            </div>
            <pre className="code">
              {integration
                ? `curl -sS ${integration.http.checkUrl} \\\n  -H 'content-type: application/json' \\\n  -d '${JSON.stringify(integration.http.example.body, null, 2)}'`
                : "curl -sS http://127.0.0.1:7832/api/v1/check -H 'content-type: application/json' -d '{\"url\":\"https://example.com\"}'"}
            </pre>
          </div>

          <ul className="tool-list endpoints" style={{ marginTop: 14 }}>
            <li>
              <code>POST {integration?.http.checkUrl ?? "/api/v1/check"}</code>
              <span>Check target URL before agent network access</span>
            </li>
            <li>
              <code>POST {`${integration?.http.base ?? "http://127.0.0.1:7832/api/v1"}/check-file`}</code>
              <span>VirusTotal file hash check</span>
            </li>
            <li>
              <code>POST {`${integration?.http.base ?? "http://127.0.0.1:7832/api/v1"}/upload-scan`}</code>
              <span>Upload small file (≤32MB) for immediate scan</span>
            </li>
            <li>
              <code>POST {`${integration?.http.base ?? "http://127.0.0.1:7832/api/v1"}/sandbox/run`}</code>
              <span>Kernel-isolated sandbox execution</span>
            </li>
            <li>
              <code>GET {integration?.http.statusUrl ?? "/api/v1/health"}</code>
              <span>Engine health, cache stats, and policy status</span>
            </li>
          </ul>
        </section>
      </div>
    </div>
  );
}
