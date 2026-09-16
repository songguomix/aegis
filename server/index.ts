import express from "express";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { createApiRouter } from "./routes/api.js";
import { loadStore, getConfig, getLocalToken, ensureToken, writePortFile } from "./services/store.js";
import { startMcpStdio } from "./mcp/server.js";

const MCP_ONLY = process.argv.includes("--mcp");

const LOCAL_ORIGIN = /^https?:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/;

function isAllowedOrigin(origin: string): boolean {
  return LOCAL_ORIGIN.test(origin);
}

function isMutating(method: string): boolean {
  return method === "PUT" || method === "DELETE" || method === "PATCH";
}

export function createApp(): express.Express {
  loadStore();
  ensureToken();
  const app = express();
  app.use(express.json({ limit: "1mb" }));

  app.use((req, res, next) => {
    const origin = req.headers.origin;
    // Browser pages: only echo local console/dev origins. Never *.
    if (origin && isAllowedOrigin(origin)) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
      res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization,X-Aegis-Token");
    }

    if (req.method === "OPTIONS") {
      // Preflight without allowed origin → 403 so browsers never send the real request.
      if (origin && !isAllowedOrigin(origin)) {
        res.sendStatus(403);
        return;
      }
      res.sendStatus(204);
      return;
    }

    // Defense-in-depth for mutating routes: foreign browser origins are rejected
    // even if a client bypasses preflight. Allowed local console origins may
    // mutate; non-browser clients must present the local token.
    if (isMutating(req.method)) {
      if (origin && !isAllowedOrigin(origin)) {
        res.status(403).json({ error: "forbidden_origin" });
        return;
      }
      if (!origin) {
        const token = req.header("x-aegis-token") ?? "";
        const expected = getLocalToken();
        if (!expected || token !== expected) {
          res.status(401).json({
            error: "unauthorized",
            hint: "Send X-Aegis-Token from .aegis/token",
          });
          return;
        }
      }
    }

    next();
  });

  app.use("/api/v1", createApiRouter());

  // Production console is same-origin with the API (avoids file:// Origin: null).
  const distUi = new URL("../dist/", import.meta.url).pathname;
  if (existsSync(distUi)) {
    app.use(express.static(distUi));
    app.get("*", (req, res, next) => {
      if (req.path.startsWith("/api/")) return next();
      res.sendFile(join(distUi, "index.html"));
    });
  }
  return app;
}

export async function startHttpServer(preferredPort?: number): Promise<{
  port: number;
  close: () => Promise<void>;
}> {
  const app = createApp();
  const base = preferredPort ?? getConfig().httpPort ?? 7832;

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
  ensureToken();
  writePortFile(bound);

  console.log(`[aegis] HTTP API on http://127.0.0.1:${bound}/api/v1`);
  console.log(
    `[aegis] Policy=${getConfig().policyMode} VT=${getConfig().vtApiKey ? "live" : "degraded"} token=.aegis/token`,
  );

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
