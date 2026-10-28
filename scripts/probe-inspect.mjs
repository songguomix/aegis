import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  runInSandbox,
  cleanupSandbox,
  checkUnisolatedArgv,
} from "../dist-server/services/sandbox.js";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-inspect-probe-"));
const artifact = path.join(tmp, "sample.bin");
fs.writeFileSync(artifact, "MZ\u0000\u0001SECRET-PAYLOAD-MARKER strings here\n");

console.log("=== A) seatbelt 沙箱：暂存目标文件后能否读到 ===");
const a = await runInSandbox(["/usr/bin/strings", artifact], { targetPath: artifact });
console.log("ok:", a.ok, "| mode:", a.mode, "| isolated:", a.isolated);
console.log("stdout:", JSON.stringify(a.stdout.trim()));
console.log("stderr:", a.stderr.slice(0, 120));
cleanupSandbox(a.sandboxRoot);

console.log("\n=== B) seatbelt 沙箱：不暂存、直接读原路径（应读不到）===");
const b = await runInSandbox(["/usr/bin/strings", artifact]);
console.log("ok:", b.ok, "| stdout:", JSON.stringify(b.stdout.trim()), "| stderr:", b.stderr.slice(0, 90));
cleanupSandbox(b.sandboxRoot);

console.log("\n=== C) 白名单校验 ===");
const cases = [
  ["/usr/bin/strings", "sample.bin"],
  ["strings", "sample.bin"],
  ["file", "sample.bin"],
  ["/bin/sh", "-c", "echo hi"],
  ["python3", "x.py"],
  ["/usr/bin/curl", "https://example.com"],
  ["/usr/bin/strings", "/etc/passwd"],
  ["/usr/bin/strings", "~/.ssh/id_rsa"],
  ["/usr/bin/strings", "../../etc/passwd"],
  ["/usr/bin/env"],
];
for (const c of cases) {
  const v = checkUnisolatedArgv(c);
  console.log(`  ${v.ok ? "ALLOW" : "DENY "}  ${JSON.stringify(c)}${v.ok ? "" : "  → " + v.reason.slice(0, 80)}`);
}

console.log("\n=== D) restricted 平台 + allowUnisolated ===");
const realPlatform = process.platform;
const realExists = fs.existsSync;
Object.defineProperty(process, "platform", { value: "win32", configurable: true });
fs.existsSync = (p) => realExists(p) && !String(p).includes("sandbox-exec") && !String(p).includes("bwrap");

const d1 = await runInSandbox(["/usr/bin/strings", artifact], { targetPath: artifact });
console.log("D1 未 opt-in → ok:", d1.ok, "| error:", d1.error);
console.log("   reason:", d1.reason?.slice(0, 110));

const d2 = await runInSandbox(["/usr/bin/strings", artifact], {
  targetPath: artifact,
  allowUnisolated: true,
});
console.log("D2 opt-in + 可信工具 → ok:", d2.ok, "| isolated:", d2.isolated, "| stdout:", JSON.stringify(d2.stdout.trim()));

const d3 = await runInSandbox(["/bin/sh", "-c", "cat ~/.ssh/id_rsa"], { allowUnisolated: true });
console.log("D3 opt-in + 不可信工具 → ok:", d3.ok, "| error:", d3.error);
console.log("   reason:", d3.reason?.slice(0, 110));

const d4 = await runInSandbox(["/usr/bin/strings", "/etc/passwd"], { allowUnisolated: true });
console.log("D4 opt-in + 越界路径 → ok:", d4.ok, "| error:", d4.error);
console.log("   reason:", d4.reason?.slice(0, 110));

fs.existsSync = realExists;
Object.defineProperty(process, "platform", { value: realPlatform, configurable: true });
fs.rmSync(tmp, { recursive: true, force: true });
process.exit(0);
