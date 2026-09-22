import express from "express";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { runGate, parseUrl } from "../services/gate.js";
import { runFileGate } from "../services/fileGate.js";
import { scanDownloadedFile } from "../services/fileUploadScan.js";
import { analyzeInstallerPath } from "../services/installerProbe.js";
import { runInSandbox, extractInSandbox, cleanupSandbox } from "../services/sandbox.js";
import { runUploadScan } from "../services/uploadScan.js";
import {
  appendHistory,
  clearHistory,
  getConfig,
  getHistory,
  getLocalToken,
  getProjectRoot,
  readPortFile,
  stats,
  updateConfig,
} from "../services/store.js";
import { brandKeys, lookupOfficial } from "../services/registry.js";
import { vtCacheSize } from "../services/virustotal.js";
import { intelFeedStatus } from "../services/threatIntel.js";
import {
  getReview,
  listReviews,
  resolveReview,
  reviewStats,
} from "../services/reviewQueue.js";
import {
  clearTrust,
  listTrust,
  trustDomain,
  untrustDomain,
  isValidHostname,
} from "../services/sessionTrust.js";
import { AGENT_GUARD_POLICY, policyText } from "../services/agentPolicy.js";
import {
  buildDeployBundle,
  buildDeployZip,
  clientStatus,
} from "../services/mcpDeploy.js";

const checkSchema = z.object({
  url: z.string().min(1),
  context: z.string().optional(),
});

const configSchema = z.object({
  vtApiKey: z.string().nullable().optional(),
  policyMode: z.enum(["tri", "strict", "observe"]).optional(),
  language: z.enum(["en", "zh"]).optional(),
  enableRdap: z.boolean().optional(),
  allowlist: z.array(z.string()).optional(),
  denylist: z.array(z.string()).optional(),
  soundEnabled: z.boolean().optional(),
  customBrands: z
    .array(
      z.object({
        host: z.string().min(1).refine((h) => isValidHostname(h), "invalid_host"),
        brand: z.string().min(1),
        subject: z.string().optional().default(""),
      }),
    )
    .optional(),
});

function resolveMcpEntry(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.join(here, "..", "index.js"), // dist-server/routes → dist-server/index.js
    path.join(getProjectRoot(), "dist-server", "index.js"),
    path.join(getProjectRoot(), "server", "index.ts"),
  ];
  return candidates.find((p) => fs.existsSync(p)) ?? candidates[1];
}

export function createApiRouter(): express.Router {
  const router = express.Router();

  router.get("/health", (_req, res) => {
    const cfg = getConfig();
    res.json({
      ok: true,
      service: "aegis",
      version: "0.1.0",
      stats: stats(),
      reviews: reviewStats(),
      vtCache: vtCacheSize(),
      intelFeeds: intelFeedStatus(),
      policyMode: cfg.policyMode,
      soundEnabled: cfg.soundEnabled !== false,
    });
  });

  router.get("/reviews", (req, res) => {
    const includeResolved = String(req.query.all ?? "") === "1";
    res.json({ items: listReviews(includeResolved), stats: reviewStats() });
  });

  router.get("/reviews/:id", (req, res) => {
    const it = getReview(req.params.id);
    if (!it) {
      res.status(404).json({ error: "not_found" });
      return;
    }
    res.json(it);
  });

  router.post("/reviews/:id/resolve", (req, res) => {
    const parsed = z
      .object({
        decision: z.enum(["allow", "block"]),
        note: z.string().optional(),
        by: z.enum(["user", "agent"]).optional(),
        alwaysAllow: z.boolean().optional(),
        sessionTrust: z.boolean().optional(),
      })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid_request" });
      return;
    }
    const existing = getReview(req.params.id);
    if (!existing) {
      res.status(404).json({ error: "not_found" });
      return;
    }
    const { item, changed } = resolveReview(req.params.id, parsed.data.decision, {
      by: parsed.data.by ?? "user",
      note: parsed.data.note,
    });
    if (!changed) {
      res.status(409).json({ error: "not_pending", review: item });
      return;
    }
    if (parsed.data.decision === "allow" && parsed.data.alwaysAllow) {
      const cfg = getConfig();
      if (
        !cfg.allowlist.includes(existing.hostname) &&
        isValidHostname(existing.hostname)
      ) {
        updateConfig({ allowlist: [...cfg.allowlist, existing.hostname] });
      }
    }
    if (parsed.data.decision === "block" && parsed.data.alwaysAllow) {
      const cfg = getConfig();
      if (
        !cfg.denylist.includes(existing.hostname) &&
        isValidHostname(existing.hostname)
      ) {
        updateConfig({ denylist: [...cfg.denylist, existing.hostname] });
      }
    }
    if (parsed.data.decision === "allow" && parsed.data.sessionTrust !== false) {
      if (isValidHostname(existing.hostname)) {
        trustDomain(existing.hostname, {
          source: (parsed.data.by ?? "user") as "user" | "agent",
          reason: `review ${existing.id}`,
        });
      }
    }
    res.json(item);
  });

  router.get("/integration", (_req, res) => {
    const entry = resolveMcpEntry();
    const port = readPortFile() ?? getConfig().httpPort ?? 7832;
    const base = `http://127.0.0.1:${port}/api/v1`;
    const isTs = entry.endsWith(".ts");
    res.json({
      mcpCommand: isTs
        ? `npx tsx ${JSON.stringify(entry)} --mcp`
        : `node ${JSON.stringify(entry)} --mcp`,
      mcpConfig: {
        mcpServers: {
          aegis: {
            command: isTs ? "npx" : "node",
            args: isTs ? ["tsx", entry, "--mcp"] : [entry, "--mcp"],
            env: {
              AEGIS_DATA_DIR:
                process.env.AEGIS_DATA_DIR ?? path.join(getProjectRoot(), ".aegis"),
            },
          },
        },
      },
      tools: [
        {
          name: "agent_guard_policy",
          description: "Harness protocol text + MCP tool list. Read this first.",
          input: [],
        },
        {
          name: "check_url",
          description:
            "Agent Guard preflight. allow→go, block→stop, review→human then resolve_review / trust_domain.",
          input: ["url: string", "context?: string"],
        },
        {
          name: "scan_search_results",
          description: "Agent Guard: scan ≤20 search/chat URLs; only follow allow.",
          input: ["urls: string[]"],
        },
        {
          name: "check_urls_batch",
          description: "Batch URL check (same engine as scan_search_results).",
          input: ["urls: string[]"],
        },
        {
          name: "check_file_hash",
          description: "VT hash lookup before open/execute a download.",
          input: ["hash: string", "fileName?: string"],
        },
        {
          name: "trust_domain",
          description: "Session-trust hostname after human allow.",
          input: ["hostname: string", "reason?: string"],
        },
        {
          name: "session_trust",
          description: "List session-trusted hosts.",
          input: [],
        },
        {
          name: "untrust_domain",
          description: "Remove session trust for a host.",
          input: ["hostname: string"],
        },
        {
          name: "get_pending_reviews",
          description: "URLs waiting for approval.",
          input: [],
        },
        {
          name: "resolve_review",
          description: "Allow/block a pending review after confirmation.",
          input: ["id: string", "decision: allow|block", "alwaysAllow?: boolean"],
        },
        {
          name: "scan_downloaded_file",
          description:
            "After download: local path ≤ maxUploadBytes → VT upload/scan, returns allow/review/block for the agent.",
          input: ["path: string", "fileName?: string"],
        },
        {
          name: "upload_scan_file",
          description:
            "Upload small downloaded file (≤ maxUploadBytes) to VirusTotal; returns allow/review/block to the agent.",
          input: ["path?: string", "base64?: string", "filename?: string"],
        },
        {
          name: "verify_domain",
          description: "Authority-only domain verification.",
          input: ["domain: string"],
        },
        {
          name: "get_gate_status",
          description: "Engine health, policy, VT mode, counts, session trust size.",
          input: [],
        },
      ],
      http: {
        base,
        checkUrl: `${base}/check`,
        statusUrl: `${base}/health`,
        example: {
          method: "POST",
          url: `${base}/check`,
          body: {
            url: "https://github.com/modelcontextprotocol/servers",
            context: "download from search",
          },
        },
      },
      projectRoot: getProjectRoot(),
      mcpEntry: entry,
    });
  });

  router.get("/session-token", (req, res) => {
    const origin = req.headers.origin;
    if (origin && !/^https?:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(origin)) {
      res.status(403).json({ error: "forbidden" });
      return;
    }
    const token = getLocalToken();
    if (!token) {
      res.status(500).json({ error: "token_missing" });
      return;
    }
    res.json({ token });
  });

  router.get("/agent-policy", (_req, res) => {
    res.json({
      ...AGENT_GUARD_POLICY,
      text: policyText(),
      sessionTrusted: listTrust(),
      customBrands: getConfig().customBrands ?? [],
    });
  });

  router.get("/mcp-deploy/bundle", (req, res) => {
    const entry = req.query.entry ? String(req.query.entry) : undefined;
    res.json(buildDeployBundle(entry));
  });

  router.get("/mcp-deploy/bundle.zip", (req, res) => {
    const entry = req.query.entry ? String(req.query.entry) : undefined;
    const bundle = buildDeployBundle(entry);
    const zip = buildDeployZip(bundle);
    res.setHeader("Content-Type", "application/zip");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename=${bundle.name}.zip`,
    );
    res.send(zip);
  });

  router.get("/mcp-deploy/status", (_req, res) => {
    res.json({
      entry: buildDeployBundle().mcpEntry,
      command: buildDeployBundle().mcpCommand,
      clients: clientStatus(),
      note: "Export-only by design; install.sh is optional and backs up before merge.",
    });
  });

  router.get("/session-trust", (_req, res) => {
    res.json({ items: listTrust() });
  });

  router.post("/session-trust", (req, res) => {
    const parsed = z
      .object({
        hostname: z.string().min(1),
        reason: z.string().optional(),
        source: z.enum(["user", "agent", "resolve"]).optional(),
      })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid_request" });
      return;
    }
    if (!isValidHostname(parsed.data.hostname)) {
      res.status(400).json({ error: "invalid_hostname" });
      return;
    }
    try {
      const entry = trustDomain(parsed.data.hostname, {
        reason: parsed.data.reason,
        source: parsed.data.source ?? "user",
      });
      res.json(entry);
    } catch {
      res.status(400).json({ error: "invalid_hostname" });
    }
  });

  router.delete("/session-trust/:host", (req, res) => {
    const host = String(req.params.host ?? "");
    if (!host) {
      res.status(400).json({ error: "invalid_request" });
      return;
    }
    if (host === "*" || host === "%2A") {
      clearTrust();
      res.json({ ok: true, cleared: true });
      return;
    }
    const removed = untrustDomain(host);
    res.json({ ok: removed, removed });
  });

  router.post("/check", async (req, res) => {
    const parsed = checkSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid_request", details: parsed.error.flatten() });
      return;
    }
    const result = await runGate(parsed.data.url, getConfig(), parsed.data.context);
    appendHistory(result);
    res.json(result);
  });

  router.post("/upload-scan", async (req, res) => {
    const parsed = z
      .object({
        filename: z.string().optional(),
        base64: z.string().optional(),
        path: z.string().optional(),
        context: z.string().optional(),
      })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid_request" });
      return;
    }
    const outcome = await runUploadScan(parsed.data, getConfig());
    if (!outcome.ok) {
      const code =
        outcome.error === "file_too_large"
          ? 413
          : outcome.error === "vt_key_required"
            ? 400
            : outcome.error === "path_not_found" || outcome.error === "empty_file" || outcome.error === "invalid_input" || outcome.error === "invalid_base64"
              ? 400
              : 502;
      res.status(code).json({
        error: outcome.error,
        maxBytes: outcome.maxBytes,
        message: outcome.message,
      });
      return;
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
    res.json(result);
  });

  /** Small-file VirusTotal upload scan for agent downloads. */
  /** Strict sandbox: run argv only (no shell), deny network, write only sandbox root. */
  router.post("/sandbox/run", async (req, res) => {
    const parsed = z
      .object({
        argv: z.array(z.string().min(1)).min(1).max(32),
        timeoutMs: z.number().int().min(500).max(60000).optional(),
        cleanup: z.boolean().optional(),
      })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid_request" });
      return;
    }
    const result = await runInSandbox(parsed.data.argv, {
      timeoutMs: parsed.data.timeoutMs,
    });
    if (parsed.data.cleanup !== false) {
      cleanupSandbox(result.sandboxRoot);
    }
    res.json(result);
  });

  router.post("/sandbox/extract", async (req, res) => {
    const parsed = z
      .object({
        path: z.string().min(1),
        timeoutMs: z.number().int().min(500).max(60000).optional(),
      })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid_request" });
      return;
    }
    const result = await extractInSandbox(parsed.data.path, {
      timeoutMs: parsed.data.timeoutMs,
    });
    res.json(result);
  });

  router.post("/analyze-installer", (req, res) => {
    const parsed = z
      .object({
        path: z.string().min(1),
        context: z.string().optional(),
      })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid_request" });
      return;
    }
    const analysis = analyzeInstallerPath(parsed.data.path);
    if (!analysis.ok && (analysis.error === "file_not_found" || analysis.error === "not_a_file")) {
      res.status(404).json(analysis);
      return;
    }
    res.json(analysis);
  });

  router.post("/scan-file", async (req, res) => {
    const parsed = z
      .object({
        path: z.string().min(1),
        fileName: z.string().optional(),
      })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid_request" });
      return;
    }
    const result = await scanDownloadedFile(parsed.data.path, getConfig(), {
      fileName: parsed.data.fileName ?? null,
    });
    if (result.reasons.some((r) => r.code === "file_not_found")) {
      res.status(404).json(result);
      return;
    }
    if (result.reasons.some((r) => r.code === "file_too_large")) {
      res.status(400).json(result);
      return;
    }
    appendHistory({
      id: result.id,
      url: `file:${result.hash.slice(0, 12)}…`,
      hostname: result.fileName ?? result.hash.slice(0, 16),
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
    res.json(result);
  });

  router.post("/check-file", async (req, res) => {
    const parsed = z
      .object({
        hash: z.string().min(1),
        fileName: z.string().optional(),
        context: z.string().optional(),
      })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid_request" });
      return;
    }
    const result = await runFileGate(parsed.data.hash, getConfig(), {
      fileName: parsed.data.fileName ?? null,
      context: parsed.data.context,
    });
    appendHistory({
      id: result.id,
      url: `file:${result.hash.slice(0, 12)}…`,
      hostname: result.fileName ?? result.hash.slice(0, 16),
      decision: result.decision,
      score: result.score,
      reasons: result.reasons,
      authority: {
        official: false,
        brand: null,
        subject: null,
        category: "file",
        rdap: { status: "skipped", registrant: null, organization: null },
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
    res.json(result);
  });

  router.post("/check-batch", async (req, res) => {
    const parsed = z
      .object({
        urls: z.array(z.string().min(1)).min(1).max(20),
        context: z.string().optional(),
      })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid_request", details: parsed.error.flatten() });
      return;
    }
    const results = [];
    for (const url of parsed.data.urls) {
      const r = await runGate(url, getConfig(), parsed.data.context ?? "batch");
      results.push(r);
      appendHistory(r);
    }
    const allow = results.filter((r) => r.decision === "allow").length;
    const review = results.filter((r) => r.decision === "review").length;
    const block = results.filter((r) => r.decision === "block").length;
    // Worst-decision for the batch as a whole
    const decision = block > 0 ? "block" : review > 0 ? "review" : "allow";
    res.json({
      decision,
      total: results.length,
      allow,
      review,
      block,
      results,
    });
  });

  router.get("/history/export", (req, res) => {
    const format = String(req.query.format ?? "json").toLowerCase();
    const items = getHistory(500);
    if (format === "csv") {
      const header = [
        "checkedAt",
        "decision",
        "score",
        "hostname",
        "url",
        "vtStatus",
        "brand",
        "kind",
      ];
      const rows = items.map((h) =>
        [
          h.checkedAt,
          h.decision,
          h.score,
          `"${(h.hostname || "").replace(/"/g, '""')}"`,
          `"${(h.url || "").replace(/"/g, '""')}"`,
          h.virusTotal.status,
          h.authority.brand ?? "",
          h.kind ?? "url",
        ].join(","),
      );
      const csv = [header.join(","), ...rows].join("\n");
      res.setHeader("Content-Type", "text/csv; charset=utf-8");
      res.setHeader("Content-Disposition", "attachment; filename=aegis-history.csv");
      res.send(csv);
      return;
    }
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Content-Disposition", "attachment; filename=aegis-history.json");
    res.send(JSON.stringify({ exportedAt: new Date().toISOString(), items }, null, 2));
  });

  router.post("/verify-domain", async (req, res) => {
    const parsed = z.object({ domain: z.string().min(1) }).safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid_request" });
      return;
    }
    const host = parsed.data.domain
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .split("/")[0];
    const result = await runGate(host, getConfig(), "verify-domain");
    res.json(result);
  });

  router.get("/history", (req, res) => {
    const raw = Number(req.query.limit ?? 100);
    const limit = Number.isFinite(raw) ? Math.min(Math.max(raw, 1), 500) : 100;
    res.json({ items: getHistory(limit) });
  });

  router.delete("/history", (_req, res) => {
    clearHistory();
    res.json({ ok: true });
  });

  router.get("/config", (_req, res) => {
    const cfg = getConfig();
    res.json({
      ...cfg,
      vtApiKey: cfg.vtApiKey
        ? `${cfg.vtApiKey.slice(0, 4)}…${cfg.vtApiKey.slice(-2)}`
        : null,
      hasVtKey: Boolean(cfg.vtApiKey),
      soundEnabled: cfg.soundEnabled !== false,
    });
  });

  router.put("/config", (req, res) => {
    const parsed = configSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid_request", details: parsed.error.flatten() });
      return;
    }
    const patch = { ...parsed.data };
    if ("vtApiKey" in patch) {
      const k = patch.vtApiKey;
      patch.vtApiKey = k && k.length > 0 && !k.includes("…") ? k : getConfig().vtApiKey;
      if (k === null) patch.vtApiKey = null;
    }
    const cfg = updateConfig(patch);
    res.json({
      ...cfg,
      vtApiKey: cfg.vtApiKey
        ? `${cfg.vtApiKey.slice(0, 4)}…${cfg.vtApiKey.slice(-2)}`
        : null,
      hasVtKey: Boolean(cfg.vtApiKey),
      soundEnabled: cfg.soundEnabled !== false,
    });
  });

  router.get("/official-domains", (_req, res) => {
    res.json({ brands: brandKeys() });
  });

  router.get("/lookup-official", (req, res) => {
    const host = String(req.query.domain ?? "");
    const hit = lookupOfficial(host);
    res.json(hit);
  });

  router.get("/parse-url", (req, res) => {
    const raw = String(req.query.url ?? "");
    res.json(parseUrl(raw));
  });

  return router;
}
