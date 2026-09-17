import express from "express";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { runGate, parseUrl } from "../services/gate.js";
import { runFileGate } from "../services/fileGate.js";
import {
  appendHistory,
  clearHistory,
  getConfig,
  getHistory,
  getProjectRoot,
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
    res.json({
      ok: true,
      service: "aegis",
      version: "0.1.0",
      stats: stats(),
      reviews: reviewStats(),
      vtCache: vtCacheSize(),
      intelFeeds: intelFeedStatus(),
      policyMode: getConfig().policyMode,
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
    const item = resolveReview(req.params.id, parsed.data.decision, {
      by: parsed.data.by ?? "user",
      note: parsed.data.note,
    });
    if (parsed.data.decision === "allow" && parsed.data.alwaysAllow) {
      const cfg = getConfig();
      if (!cfg.allowlist.includes(existing.hostname)) {
        updateConfig({ allowlist: [...cfg.allowlist, existing.hostname] });
      }
    }
    if (parsed.data.decision === "block" && parsed.data.alwaysAllow) {
      const cfg = getConfig();
      if (!cfg.denylist.includes(existing.hostname)) {
        updateConfig({ denylist: [...cfg.denylist, existing.hostname] });
      }
    }
    res.json(item);
  });

  router.get("/integration", (_req, res) => {
    const entry = resolveMcpEntry();
    const port = getConfig().httpPort ?? 7832;
    const base = `http://127.0.0.1:${port}/api/v1`;
    const isTs = entry.endsWith(".ts");
    res.json({
      mcpCommand: isTs
        ? `npx tsx ${JSON.stringify(entry)} --mcp`
        : `node ${JSON.stringify(entry)} --mcp`,
      mcpConfig: {
        mcpServers: {
          aegis: isTs
            ? { command: "npx", args: ["tsx", entry, "--mcp"] }
            : { command: "node", args: [entry, "--mcp"] },
        },
      },
      tools: [
        {
          name: "check_url",
          description:
            "Verify a URL before the agent visits or downloads from it. Returns allow/review/block with authority + VirusTotal + free intel (URLhaus, ThreatFox, OpenPhish). If review, ask the human then resolve_review.",
          input: ["url: string", "context?: string"],
        },
        {
          name: "check_urls_batch",
          description:
            "Check up to 20 URLs (e.g. search results). Returns per-URL decisions and worst-case overall decision.",
          input: ["urls: string[]", "context?: string"],
        },
        {
          name: "check_file_hash",
          description:
            "VirusTotal lookup for MD5/SHA1/SHA256 of a downloaded file. Call before opening/executing.",
          input: ["hash: string", "fileName?: string", "context?: string"],
        },
        {
          name: "get_pending_reviews",
          description: "List URLs waiting for human/agent approval.",
          input: [],
        },
        {
          name: "resolve_review",
          description: "Allow or block a pending review after confirmation.",
          input: ["id: string", "decision: allow|block", "alwaysAllow?: boolean"],
        },
        {
          name: "verify_domain",
          description: "Authority-only domain verification (no VirusTotal lookup).",
          input: ["domain: string"],
        },
        {
          name: "get_gate_status",
          description: "Engine health, policy mode, VirusTotal mode, decision counts.",
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
