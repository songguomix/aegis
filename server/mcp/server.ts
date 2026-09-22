import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { runGate } from "../services/gate.js";
import { runFileGate } from "../services/fileGate.js";
import { scanDownloadedFile } from "../services/fileUploadScan.js";
import { analyzeInstallerPath } from "../services/installerProbe.js";
import { runInSandbox, extractInSandbox, cleanupSandbox } from "../services/sandbox.js";
import { runUploadScan } from "../services/uploadScan.js";
import { getConfig, appendHistory, stats, updateConfig } from "../services/store.js";
import { lookupOfficial } from "../services/registry.js";
import {
  getReview,
  listReviews,
  resolveReview,
  reviewStats,
} from "../services/reviewQueue.js";
import {
  clearTrust,
  isTrusted,
  listTrust,
  trustDomain,
  untrustDomain,
  isValidHostname,
} from "../services/sessionTrust.js";
import { AGENT_GUARD_POLICY, policyText } from "../services/agentPolicy.js";
import { buildDeployBundle } from "../services/mcpDeploy.js";

export function createMcpServer(): McpServer {
  const server = new McpServer({
    name: "aegis",
    version: "0.1.0",
  });

  server.registerTool(
    "check_url",
    {
      title: "Check URL with Aegis gate",
      description:
        "Verify a URL before the agent visits or downloads from it. Returns allow/review/block with authority + VirusTotal + free intel. If decision=review, do NOT visit: ask the human operator, then call resolve_review (or wait until they approve in the Aegis app).",
      inputSchema: {
        url: z.string().describe("Full URL or hostname to check"),
        context: z.string().optional().describe("Why the agent wants this URL"),
      },
    },
    async ({ url, context }) => {
      const result = await runGate(url, getConfig(), context);
      appendHistory(result);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    },
  );

  server.registerTool(
    "check_urls_batch",
    {
      title: "Batch check URLs",
      description:
        "Check up to 20 URLs at once (e.g. search results). Returns per-URL decisions and an overall worst-case decision. Prefer scan_search_results as the Agent Guard name for SERP flows.",
      inputSchema: {
        urls: z.array(z.string()).min(1).max(20).describe("URLs to check"),
        context: z.string().optional(),
      },
    },
    async ({ urls, context }) => {
      const results = [];
      for (const url of urls) {
        const r = await runGate(url, getConfig(), context ?? "batch");
        results.push(r);
        appendHistory(r);
      }
      const allow = results.filter((r) => r.decision === "allow").length;
      const review = results.filter((r) => r.decision === "review").length;
      const block = results.filter((r) => r.decision === "block").length;
      const decision = block > 0 ? "block" : review > 0 ? "review" : "allow";
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({ decision, total: results.length, allow, review, block, results }, null, 2),
          },
        ],
      };
    },
  );

  server.registerTool(
    "scan_search_results",
    {
      title: "Scan search results (Agent Guard)",
      description:
        "Agent Guard: paste up to 20 URLs from search/chat. Only follow hosts with decision=allow or session trust. review → ask human; block → never open.",
      inputSchema: {
        urls: z.array(z.string()).min(1).max(20),
        context: z.string().optional(),
      },
    },
    async ({ urls, context }) => {
      const results = [];
      for (const url of urls) {
        const r = await runGate(url, getConfig(), context ?? "scan_search_results");
        results.push(r);
        appendHistory(r);
      }
      const allow = results.filter((r) => r.decision === "allow").length;
      const review = results.filter((r) => r.decision === "review").length;
      const block = results.filter((r) => r.decision === "block").length;
      const decision = block > 0 ? "block" : review > 0 ? "review" : "allow";
      const followable = results
        .filter((r) => r.decision === "allow")
        .map((r) => r.hostname);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              { decision, total: results.length, allow, review, block, followable, results },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  server.registerTool(
    "trust_domain",
    {
      title: "Session-trust a domain",
      description:
        "Agent Guard: after human allows a review, mark hostname session-trusted so later checks in this app session return allow (still blocked on malware/denylist). Not a permanent allowlist.",
      inputSchema: {
        hostname: z.string(),
        reason: z.string().optional(),
      },
    },
    async ({ hostname, reason }) => {
      if (!isValidHostname(hostname)) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: "invalid_hostname",
                hostname,
                hint: "Use a bare hostname like partner.example — no scheme or path.",
              }),
            },
          ],
          isError: true,
        };
      }
      const { detectLookalike } = await import("../services/lookalike.js");
      const { officialHostnames } = await import("../services/registry.js");
      const look = detectLookalike(hostname, officialHostnames());
      if (look.lookalikeOf && look.reason && look.reason !== "exact_official") {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: "lookalike_blocked",
                hostname,
                lookalikeOf: look.lookalikeOf,
                hint: "Session trust cannot override lookalike risk. Human must allowlist after review.",
              }),
            },
          ],
          isError: true,
        };
      }
      const entry = trustDomain(hostname, { reason, source: "agent" });
      return { content: [{ type: "text", text: JSON.stringify(entry, null, 2) }] };
    },
  );

  server.registerTool(
    "session_trust",
    {
      title: "List session-trusted domains",
      description: "Hostname allow-for-this-session list (from user UI or trust_domain).",
      inputSchema: {},
    },
    async () => {
      return {
        content: [
          { type: "text", text: JSON.stringify({ items: listTrust() }, null, 2) },
        ],
      };
    },
  );

  server.registerTool(
    "untrust_domain",
    {
      title: "Remove session trust",
      description: "Remove a hostname from session trust.",
      inputSchema: { hostname: z.string() },
    },
    async ({ hostname }) => {
      const ok = untrustDomain(hostname);
      return {
        content: [{ type: "text", text: JSON.stringify({ hostname, removed: ok }) }],
      };
    },
  );

  server.registerTool(
    "agent_guard_policy",
    {
      title: "Aegis Agent Guard policy",
      description: "Machine-readable + text protocol the agent harness must follow.",
      inputSchema: {},
    },
    async () => {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              { ...AGENT_GUARD_POLICY, text: policyText(), sessionTrusted: listTrust() },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  server.registerTool(
    "export_mcp_bundle",
    {
      title: "Export one-click MCP deploy bundle",
      description:
        "Return deploy files (mcp JSON, SKILL, README, install.sh) for Claude/Cursor. Does not write client configs unless the user runs install.sh.",
      inputSchema: {},
    },
    async () => {
      const bundle = buildDeployBundle();
      return {
        content: [{ type: "text", text: JSON.stringify(bundle, null, 2) }],
      };
    },
  );

  server.registerTool(
    "run_in_sandbox",
    {
      title: "Run command in strict sandbox (no network)",
      description:
        "Run an argv command in a hardened sandbox (macOS Seatbelt when available): deny network, write only sandbox temp, filter secrets from env. Use for static inspection of unpacked installers (file, ls, strings). Do NOT use to install or execute untrusted payloads on the real user system.",
      inputSchema: {
        argv: z.array(z.string()).min(1).max(32),
        timeoutMs: z.number().int().min(500).max(60000).optional(),
      },
    },
    async ({ argv, timeoutMs }) => {
      const result = await runInSandbox(argv, { timeoutMs });
      cleanupSandbox(result.sandboxRoot);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        isError: !result.ok,
      };
    },
  );

  server.registerTool(
    "extract_in_sandbox",
    {
      title: "Extract zip into sandbox (traversal-safe)",
      description:
        "Unpack a zip/jar/apk into a sandbox directory with path-traversal checks. Returns member names and risky executables for analyze_installer follow-up.",
      inputSchema: {
        path: z.string().describe("Absolute path to zip archive"),
      },
    },
    async ({ path: archive }) => {
      const result = await extractInSandbox(archive);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        isError: !result.ok,
      };
    },
  );

  server.registerTool(
    "analyze_installer",
    {
      title: "Static analysis of a suspicious installer/package",
      description:
        "When scan_downloaded_file / upload_scan_file returns review or block, analyze the local installer (dmg/pkg/exe/zip/…) WITHOUT executing it. Returns hashes, type, entropy, embedded URLs/strings, archive names, riskFlags and aiBrief for you to analyze and recommend user action.",
      inputSchema: {
        path: z.string().describe("Absolute path to installer/package"),
      },
    },
    async ({ path: p }) => {
      const analysis = analyzeInstallerPath(p);
      return {
        content: [{ type: "text", text: JSON.stringify(analysis, null, 2) }],
        isError: !analysis.ok,
      };
    },
  );

  server.registerTool(
    "scan_downloaded_file",
    {
      title: "Scan small downloaded file via VirusTotal",
      description:
        "Agent Guard: after download, scan a local file ≤32MB (free-tier). Computes SHA256, looks up VirusTotal, uploads unknown samples when API key is set, returns allow/review/block + verdict for the agent.",
      inputSchema: {
        path: z.string().describe("Absolute path of the downloaded file"),
        fileName: z.string().optional(),
      },
    },
    async ({ path: filePath, fileName }) => {
      const result = await scanDownloadedFile(filePath, getConfig(), { fileName });
      appendHistory({
        id: result.id,
        url: `file:${result.hash.slice(0, 12)}…`,
        hostname: fileName ?? result.hash.slice(0, 16),
        decision: result.decision,
        score: result.score,
        reasons: result.reasons,
        authority: {
          official: false,
          brand: null,
          subject: null,
          category: "file",
          rdap: { status: "skipped" as const, registrant: null, organization: null },
          lookalikeOf: null,
          punycode: false,
          mixedScript: false,
          allowlisted: false,
          denylisted: false,
        },
        virusTotal: result.virusTotal,
        checkedAt: result.checkedAt,
        kind: "file",
      });
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    },
  );

  server.registerTool(
    "check_file_hash",
    {
      title: "Check file hash with VirusTotal",
      description:
        "Verify a downloaded file by MD5/SHA1/SHA256 hash before the agent opens or executes it. Returns allow/review/block. Prefer check_url first for the download origin.",
      inputSchema: {
        hash: z.string().describe("MD5, SHA1, or SHA256 hex hash of the file"),
        fileName: z.string().optional().describe("Optional original file name"),
        context: z.string().optional(),
      },
    },
    async ({ hash, fileName, context }) => {
      const result = await runFileGate(hash, getConfig(), { fileName, context });
      appendHistory({
        id: result.id,
        url: `file:${result.hash.slice(0, 12)}…`,
        hostname: fileName ?? result.hash.slice(0, 16),
        decision: result.decision,
        score: result.score,
        reasons: result.reasons,
        authority: {
          official: false,
          brand: null,
          subject: null,
          category: "file",
          rdap: { status: "skipped" as const, registrant: null, organization: null },
          lookalikeOf: null,
          punycode: false,
          mixedScript: false,
          allowlisted: false,
          denylisted: false,
        },
        virusTotal: result.virusTotal,
        checkedAt: result.checkedAt,
        context: result.context,
        kind: "file",
      });
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    },
  );

  server.registerTool(
    "upload_scan_file",
    {
      title: "Upload small file to VirusTotal and return scan result",
      description:
        "Agent Guard: after downloading a small file (within maxUploadBytes, default 32MB), upload it to VirusTotal for scanning. Provide local path or base64+filename. Returns allow/review/block + VT stats. Do not open/execute files until allow.",
      inputSchema: {
        path: z.string().optional().describe("Absolute path to downloaded file"),
        filename: z.string().optional(),
        base64: z.string().optional().describe("Base64 file body if no path"),
        context: z.string().optional(),
      },
    },
    async ({ path: filePath, filename, base64, context }) => {
      const outcome = await runUploadScan(
        { path: filePath, filename, base64, context },
        getConfig(),
      );
      if (!outcome.ok) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: outcome.error,
                maxBytes: outcome.maxBytes,
                message: outcome.message,
              }),
            },
          ],
          isError: true,
        };
      }
      const result = outcome.result;
      appendHistory({
        id: result.id,
        url: `file:${(result.sha256 ?? result.hash).slice(0, 12)}…`,
        hostname: result.fileName ?? (result.sha256 ?? result.hash).slice(0, 16),
        decision: result.decision,
        score: result.score,
        reasons: result.reasons,
        authority: {
          official: false,
          brand: null,
          subject: null,
          category: "file-upload",
          rdap: { status: "skipped" as const, registrant: null, organization: null },
          lookalikeOf: null,
          punycode: false,
          mixedScript: false,
          allowlisted: false,
          denylisted: false,
        },
        virusTotal: result.virusTotal,
        checkedAt: result.checkedAt,
        context: result.context,
        kind: "file",
      });
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    },
  );

  server.registerTool(
    "verify_domain",
    {
      title: "Verify domain authenticity",
      description:
        "Authority-only check: official brand registry match, subject, lookalike signals. Prefer check_url when VirusTotal reputation is needed.",
      inputSchema: {
        domain: z.string().describe("Hostname or URL"),
      },
    },
    async ({ domain }) => {
      const result = await runGate(domain, getConfig(), {
        context: "verify_domain",
        skipVt: true,
      });
      const official = lookupOfficial(result.hostname);
      const payload = {
        hostname: result.hostname,
        decision: result.decision,
        authority: result.authority,
        officialMatch: official,
        reasons: result.reasons,
      };
      return {
        content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
      };
    },
  );

  server.registerTool(
    "get_gate_status",
    {
      title: "Aegis gate status",
      description: "Engine health, policy mode, VirusTotal mode, recent decision counts.",
      inputSchema: {},
    },
    async () => {
      const cfg = getConfig();
      const payload = {
        service: "aegis",
        version: "0.1.0",
        policyMode: cfg.policyMode,
        vtMode: cfg.vtApiKey ? "live" : "degraded",
        enableRdap: cfg.enableRdap,
        stats: stats(),
        reviews: reviewStats(),
      };
      return {
        content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
      };
    },
  );

  server.registerTool(
    "get_pending_reviews",
    {
      title: "List pending URL reviews",
      description:
        "List URLs waiting for human/agent approval (decision=review). Ask the user about these before continuing.",
      inputSchema: {},
    },
    async () => {
      const items = listReviews(false);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({ count: items.length, items }, null, 2),
          },
        ],
      };
    },
  );

  server.registerTool(
    "resolve_review",
    {
      title: "Resolve a pending review",
      description:
        "After explicit human confirmation, set a pending review to allow or block. Do not call this autonomously. alwaysAllow=true also writes the host to permanent allow/deny list.",
      inputSchema: {
        id: z.string().describe("Review id from check_url / get_pending_reviews"),
        decision: z.enum(["allow", "block"]),
        note: z.string().optional(),
        alwaysAllow: z
          .boolean()
          .optional()
          .describe("If true, persist host into allowlist or denylist"),
      },
    },
    async ({ id, decision, note, alwaysAllow }) => {
      const existing = getReview(id);
      if (!existing) {
        return {
          content: [{ type: "text", text: JSON.stringify({ error: "not_found", id }) }],
        };
      }
      const { item, changed } = resolveReview(id, decision, { by: "agent", note });
      if (!changed) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ error: "not_pending", review: item }),
            },
          ],
          isError: true,
        };
      }
      if (alwaysAllow && existing.hostname && isValidHostname(existing.hostname)) {
        const cfg = getConfig();
        const list = decision === "allow" ? cfg.allowlist : cfg.denylist;
        if (!list.includes(existing.hostname)) {
          updateConfig({
            [decision === "allow" ? "allowlist" : "denylist"]: [
              ...list,
              existing.hostname,
            ],
          });
        }
      }
      return {
        content: [{ type: "text", text: JSON.stringify(item, null, 2) }],
      };
    },
  );

  return server;
}

export async function startMcpStdio(): Promise<void> {
  const server = createMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[aegis] MCP stdio server ready");
}

// Allow `tsx server/mcp/server.ts` as standalone MCP entry
if (import.meta.url === `file://${process.argv[1]}`) {
  startMcpStdio().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
