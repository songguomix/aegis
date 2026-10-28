/**
 * Manual probe: shows how much isolation the sandbox actually enforces on this
 * machine. Not part of the test suite (it touches the real ~/.ssh, ~/.aws and
 * the network).
 *
 *   npm run build:server && node scripts/probe-sandbox.mjs [native|restricted]
 *
 * "restricted" simulates a platform without seatbelt/bwrap (Windows).
 */
import { runInSandbox, cleanupSandbox } from "../dist-server/services/sandbox.js";

const probe = [
  "/bin/sh",
  "-c",
  [
    'echo "HOME=$HOME"',
    'if head -c 40 "$HOME/.ssh/id_rsa" 2>/dev/null; then echo "SECRET_READ=YES"; else echo "SECRET_READ=NO"; fi',
    'if ls "$HOME/.aws" >/dev/null 2>&1; then echo "AWS_DIR=YES"; else echo "AWS_DIR=NO"; fi',
    'if /usr/bin/curl -s -m 3 -o /dev/null https://example.com; then echo "NETWORK=YES"; else echo "NETWORK=NO"; fi',
    'if echo "leak" > /tmp/aegis-sandbox-escape.txt 2>/dev/null; then echo "WRITE_OUTSIDE=YES"; else echo "WRITE_OUTSIDE=NO"; fi',
  ].join("; "),
];

const mode = process.argv[2] ?? "native";
if (mode === "restricted") {
  // Simulate a platform without seatbelt/bwrap (Windows / unsupported Linux).
  Object.defineProperty(process, "platform", { value: "win32" });
}

const r = await runInSandbox(probe, { timeoutMs: 12000 });
console.log(`--- mode requested: ${mode} | backend: ${r.mode} | degraded: ${r.degraded} ---`);
console.log(r.stdout.trim());
if (r.stderr.trim()) console.log("stderr:", r.stderr.trim().slice(0, 300));
cleanupSandbox(r.sandboxRoot);
process.exit(0);
