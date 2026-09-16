import express from "express";
import { createApiRouter } from "./routes/api.js";
import { loadStore, getConfig } from "./services/store.js";
import { startMcpStdio } from "./mcp/server.js";

const MCP_ONLY = process.argv.includes("--mcp");

export async function startHttpServer(preferredPort?: number): Promise<{
  port: number;
  close: () => Promise<void>;
}> {
  loadStore();
  const app = express();
  app.use(express.json({ limit: "1mb" }));
  app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
    if (req.method === "OPTIONS") {
      res.sendStatus(204);
      return;
    }
    next();
  });
  app.use("/api/v1", createApiRouter());

  const base = preferredPort ?? getConfig().httpPort ?? 7832;
  let port = base;

  const listen = (): Promise<{ server: ReturnType<typeof app.listen>; port: number }> =>
    new Promise((resolve, reject) => {
      const tryPort = (p: number, attemptsLeft: number) => {
        const server = app.listen(p, "127.0.0.1", () => resolve({ server, port: p }));
        server.on("error", (err: NodeJS.ErrnoException) => {
          if (err.code === "EADDRINUSE" && attemptsLeft > 0) {
            tryPort(p + 1, attemptsLeft - 1);
          } else {
            reject(err);
          }
        });
      };
      tryPort(base, 10);
    });

  const { server, port: bound } = await listen();
  console.log(`[aegis] HTTP API on http://127.0.0.1:${bound}/api/v1`);
  console.log(`[aegis] Policy=${getConfig().policyMode} VT=${getConfig().vtApiKey ? "live" : "degraded"}`);

  return {
    port: bound,
    close: () =>
      new Promise((resolve) => {
        server.close(() => resolve());
      }),
  };
}

async function main() {
  loadStore();
  if (MCP_ONLY) {
    await startMcpStdio();
    return;
  }
  await startHttpServer();
}

main().catch((err) => {
  console.error("[aegis] fatal", err);
  process.exit(1);
});
