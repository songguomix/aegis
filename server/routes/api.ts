import express from "express";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { runGate, parseUrl } from "../services/gate.js";
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
      vtCache: vtCacheSize(),
      policyMode: getConfig().policyMode,
    });
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
            "Verify a URL before the agent visits or downloads from it. Returns allow/review/block with authority + VirusTotal evidence.",
          input: ["url: string", "context?: string"],
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
