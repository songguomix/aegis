import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { runGate } from "../services/gate.js";
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
