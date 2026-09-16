import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { runGate } from "../services/gate.js";
import { runFileGate } from "../services/fileGate.js";
import { getConfig, appendHistory, stats } from "../services/store.js";
import { lookupOfficial } from "../services/registry.js";

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
        "Verify a URL before the agent visits or downloads from it. Runs domain authority checks (official registry, lookalike, RDAP) and VirusTotal. Returns allow/review/block with evidence.",
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
        "Check up to 20 URLs at once (e.g. search results). Returns per-URL decisions and an overall worst-case decision. Use before an agent follows many links from search.",
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
      };
      return {
        content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
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
