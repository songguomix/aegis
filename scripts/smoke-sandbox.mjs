import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

if (!process.env.AEGIS_DATA_DIR) {
  process.env.AEGIS_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-refuse-smoke-"));
}

const child = spawn("node", ["dist-server/index.js", "--mcp"], { stdio: ["pipe", "pipe", "pipe"] });
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
      if (r) { pending.delete(msg.id); r(msg); }
    } catch { /* ignore */ }
  }
});
child.stderr.on("data", (d) => process.stderr.write(`[mcp] ${d}`));

let id = 0;
const send = (method, params) =>
  new Promise((resolve) => {
    const msgId = ++id;
    pending.set(msgId, resolve);
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: msgId, method, params })}\n`);
  });
const notify = (method, params) =>
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method, params })}\n`);
const textOf = (res) => res?.result?.content?.[0]?.text ?? JSON.stringify(res);

await new Promise((r) => setTimeout(r, 700));
await send("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "smoke", version: "1" } });
notify("notifications/initialized", {});

// 1) 在有 seatbelt 的 macOS 上：正常执行
const okRes = await send("tools/call", { name: "run_in_sandbox", arguments: { argv: ["/bin/echo", "hello"] } });
const okPayload = JSON.parse(textOf(okRes));
console.log("1) macOS seatbelt → isError:", okRes.result.isError, "| stdout:", JSON.stringify(okPayload.stdout?.trim()), "| isolated:", okPayload.isolated);

// 2) 模拟 Windows（无内核隔离）：必须拒绝执行并给出原因
const platformProbe = await send("tools/call", { name: "run_in_sandbox", arguments: { argv: ["/bin/echo", "should-not-run"] } });
const p2 = JSON.parse(textOf(platformProbe));
console.log("2) 真实平台 → isError:", platformProbe.result.isError, "| error:", p2.error, "| stdout:", JSON.stringify(p2.stdout ?? ""));

child.kill();
process.exit(0);
