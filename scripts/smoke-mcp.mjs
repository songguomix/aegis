import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

if (!process.env.AEGIS_DATA_DIR) {
  process.env.AEGIS_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-mcp-smoke-"));
}

const child = spawn("node", ["dist-server/index.js", "--mcp"], {
  env: { ...process.env, AEGIS_DATA_DIR: process.env.AEGIS_DATA_DIR },
  stdio: ["pipe", "pipe", "pipe"],
});

let buf = "";
const pending = new Map();
child.stdout.on("data", (d) => {
  buf += d.toString();
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!line) continue;
    try {
      const msg = JSON.parse(line);
      const r = pending.get(msg.id);
      if (r) {
        pending.delete(msg.id);
        r(msg);
      }
    } catch {
      /* ignore non-json */
    }
  }
});
child.stderr.on("data", (d) => process.stderr.write(`[mcp] ${d}`));

let id = 0;
function send(method, params) {
  const msgId = ++id;
  return new Promise((resolve) => {
    pending.set(msgId, resolve);
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: msgId, method, params })}\n`);
  });
}
function notify(method, params) {
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method, params })}\n`);
}

function textOf(res) {
  return res?.result?.content?.[0]?.text ?? JSON.stringify(res);
}

await new Promise((r) => setTimeout(r, 700));
const init = await send("initialize", {
  protocolVersion: "2024-11-05",
  capabilities: {},
  clientInfo: { name: "smoke", version: "1" },
});
console.log("initialize ok:", !!init.result);
notify("notifications/initialized", {});

const host = "mcp-smoke-partner.example";
const c1 = await send("tools/call", {
  name: "check_url",
  arguments: { url: `https://${host}/doc`, context: "smoke" },
});
const r1 = JSON.parse(textOf(c1));
console.log("1) check_url decision:", r1.decision, "reviewId:", r1.reviewId);

const pendingRes = await send("tools/call", { name: "get_pending_reviews", arguments: {} });
const p = JSON.parse(textOf(pendingRes));
const review = p.items.find((i) => i.hostname === host);
console.log("2) pending review found:", !!review);

const res = await send("tools/call", {
  name: "resolve_review",
  arguments: { id: review.id, decision: "allow" },
});
console.log("3) resolve_review:", JSON.parse(textOf(res)).status);

const c2 = await send("tools/call", {
  name: "check_url",
  arguments: { url: `https://${host}/doc`, context: "smoke" },
});
const r2 = JSON.parse(textOf(c2));
console.log("4) re-check decision:", r2.decision, "sessionTrusted:", r2.authority.sessionTrusted);

child.kill();
process.exit(r2.decision === "allow" && r2.authority.sessionTrusted === true ? 0 : 1);
