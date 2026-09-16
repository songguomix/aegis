import { cpSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const src = join(root, "server", "data");
const dest = join(root, "dist-server", "data");

mkdirSync(dirname(dest), { recursive: true });
if (!existsSync(src)) {
  console.error("[aegis] missing server/data");
  process.exit(1);
}
cpSync(src, dest, { recursive: true });
console.log("[aegis] copied server/data → dist-server/data");
