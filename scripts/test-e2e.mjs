import { spawn } from "node:child_process";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";

function request(method, path, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: 7832,
        path: `/api/v1${path}`,
        method,
        headers: {
          ...(data ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) } : {}),
          ...headers,
        },
      },
      (res) => {
        let respBody = "";
        res.on("data", (chunk) => (respBody += chunk));
        res.on("end", () => {
          try {
            resolve({ status: res.statusCode, data: JSON.parse(respBody) });
          } catch {
            resolve({ status: res.statusCode, raw: respBody });
          }
        });
      }
    );
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

async function run() {
  console.log("=== Aegis Full-Stack Functional Verification ===");

  // 1. Start Server
  const server = spawn("npx", ["tsx", "server/index.ts"], { stdio: "pipe" });
  server.stdout.on("data", (d) => process.stdout.write(`[core] ${d}`));
  server.stderr.on("data", (d) => process.stderr.write(`[core-err] ${d}`));

  // Wait for server ready
  await new Promise((r) => setTimeout(r, 2000));

  const results = [];

  try {
    // Test 1: Health
    const h = await request("GET", "/health");
    const hPass = h.status === 200 && h.data?.ok === true;
    results.push({ name: "Core Engine Health (/health)", pass: hPass, detail: `Policy: ${h.data?.policyMode}, VT: ${h.data?.stats?.vtMode}` });

    // Test 2: Local Session Token
    const tokRes = await request("GET", "/session-token", null, { Origin: "http://127.0.0.1:5173" });
    const token = tokRes.data?.token;
    const tokPass = tokRes.status === 200 && Boolean(token);
    results.push({ name: "CSRF Defense Session Token (/session-token)", pass: tokPass, detail: `Token present: ${Boolean(token)}` });

    const authHeaders = token ? { "X-Aegis-Token": token, Origin: "http://127.0.0.1:5173" } : { Origin: "http://127.0.0.1:5173" };

    // Test 3: Official Domain Check (GitHub)
    const gh = await request("POST", "/check", { url: "https://github.com/modelcontextprotocol/servers" }, authHeaders);
    const ghPass = gh.status === 200 && gh.data?.decision === "allow" && gh.data?.authority?.brand === "GitHub";
    results.push({ name: "Official Domain Gate Check (GitHub)", pass: ghPass, detail: `Decision: ${gh.data?.decision}, Brand: ${gh.data?.authority?.brand}` });

    // Test 4: Suspicious / Lookalike Domain Check (g1thub.com)
    const lookalike = await request("POST", "/check", { url: "https://g1thub.com/login" }, authHeaders);
    const lkPass = lookalike.status === 200 && (lookalike.data?.decision === "block" || lookalike.data?.decision === "review");
    results.push({ name: "Lookalike / Phishing Gate Check (g1thub.com)", pass: lkPass, detail: `Decision: ${lookalike.data?.decision}, Lookalike: ${lookalike.data?.authority?.lookalikeOf}` });

    // Test 5: Unknown Domain -> Review Queue
    const unk = await request("POST", "/check", { url: "https://unknown-security-agent-test.biz" }, authHeaders);
    const unkPass = unk.status === 200 && unk.data?.decision === "review" && Boolean(unk.data?.reviewId);
    results.push({ name: "Unknown Domain -> Review Queue Trigger", pass: unkPass, detail: `Decision: ${unk.data?.decision}, ReviewID: ${unk.data?.reviewId}` });

    // Test 6: Pending Reviews Query & Resolution
    let revPass = false;
    if (unk.data?.reviewId) {
      const revList = await request("GET", "/reviews", null, authHeaders);
      const hasReview = revList.data?.items?.some((r) => r.id === unk.data.reviewId);
      const resolveRes = await request("POST", `/reviews/${unk.data.reviewId}/resolve`, { decision: "allow", alwaysAllow: true, sessionTrust: true }, authHeaders);
      revPass = hasReview && resolveRes.status === 200 && resolveRes.data?.status === "allowed";
    }
    results.push({ name: "Review Queue Listing & Approval Resolution", pass: revPass, detail: `Approved and allowed` });

    // Test 7: Batch Check
    const batch = await request("POST", "/check-batch", { urls: ["https://github.com", "https://npmjs.com", "https://google.com"] }, authHeaders);
    const batchPass = batch.status === 200 && batch.data?.total === 3 && batch.data?.allow > 0;
    results.push({ name: "Batch URL Check (/check-batch)", pass: batchPass, detail: `Checked ${batch.data?.total} URLs, Allowed: ${batch.data?.allow}` });

    // Test 8: File Hash Check
    const fileCheck = await request("POST", "/check-file", { hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", fileName: "test.zip" }, authHeaders);
    const filePass = fileCheck.status === 200 && Boolean(fileCheck.data?.decision);
    results.push({ name: "File Hash Lookup (/check-file)", pass: filePass, detail: `Decision: ${fileCheck.data?.decision}` });

    // Test 9: Static Package & Binary Probe
    const probe = await request("POST", "/analyze-installer", { path: path.resolve("package.json") }, authHeaders);
    const probePass = probe.status === 200 && probe.data?.ok === true && typeof probe.data?.entropy === "number";
    results.push({ name: "Static Package Probe (/analyze-installer)", pass: probePass, detail: `Kind: ${probe.data?.kind}, Entropy: ${probe.data?.entropy?.toFixed(2)}, SHA256: ${probe.data?.hashes?.sha256?.slice(0, 12)}…` });

    // Test 10: Security Sandbox Execution
    const sandbox = await request("POST", "/sandbox/run", { argv: ["echo", "Aegis Sandbox Verified"] }, authHeaders);
    const sandboxPass = sandbox.status === 200 && sandbox.data?.ok === true && sandbox.data?.stdout?.includes("Aegis Sandbox Verified");
    results.push({ name: "OS-Level Sandbox Execution (/sandbox/run)", pass: sandboxPass, detail: `Mode: ${sandbox.data?.mode}, Isolated: ${sandbox.data?.isolated}, Output: ${sandbox.data?.stdout?.trim()}` });

    // Test 11: MCP Deploy Bundle Export
    const mcp = await request("GET", "/mcp-deploy/bundle", null, authHeaders);
    const mcpPass = mcp.status === 200 && Boolean(mcp.data?.mcpCommand) && mcp.data?.files?.length > 0;
    results.push({ name: "One-Click MCP Deploy Bundle Export", pass: mcpPass, detail: `Generated ${mcp.data?.files?.length} deployment files` });

    // Test 12: History Export
    const hist = await request("GET", "/history/export?format=json", null, authHeaders);
    const histPass = hist.status === 200 && Array.isArray(hist.data?.items);
    results.push({ name: "History Export Engine (/history/export)", pass: histPass, detail: `Records exported: ${hist.data?.items?.length}` });

  } finally {
    server.kill();
  }

  console.log("\n==================== TEST SUMMARY ====================");
  let allPassed = true;
  for (const r of results) {
    const symbol = r.pass ? "✅ PASS" : "❌ FAIL";
    console.log(`${symbol} | ${r.name}`);
    console.log(`       └─ ${r.detail}`);
    if (!r.pass) allPassed = false;
  }
  console.log("======================================================");
  process.exit(allPassed ? 0 : 1);
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
