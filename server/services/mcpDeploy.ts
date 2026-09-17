import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

export interface DeployFile {
  filename: string;
  content: string;
  mediaType: string;
}

export interface DeployBundle {
  name: string;
  generatedAt: string;
  mcpEntry: string;
  mcpCommand: string;
  mcpConfig: { mcpServers: Record<string, { command: string; args: string[] }> };
  files: DeployFile[];
}

export interface ClientStatus {
  id: string;
  label: string;
  configPath: string;
  exists: boolean;
  hasAegis: boolean;
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function resolveMcpEntry(): string {
  const candidates = [
    path.join(__dirname, "..", "index.js"),
    path.join(process.cwd(), "dist-server", "index.js"),
    path.join(process.cwd(), "server", "index.ts"),
  ];
  return candidates.find((p) => fs.existsSync(p)) ?? candidates[1];
}

function mcpConfigJson(entry: string): string {
  const isTs = entry.endsWith(".ts");
  const config = {
    mcpServers: {
      aegis: isTs
        ? { command: "npx", args: ["tsx", entry, "--mcp"] }
        : { command: "node", args: [entry, "--mcp"] },
    },
  };
  return JSON.stringify(config, null, 2) + "\n";
}

function skillMd(): string {
  return `# Aegis Agent Guard (MCP)

Before any network access:

1. Call \`check_url\`.
2. \`allow\` → continue.
3. \`block\` → stop; report evidence.
4. \`review\` → do NOT visit; ask human; then \`resolve_review\` / \`trust_domain\`.
5. Search lists → \`scan_search_results\` (≤20).
6. Downloads → \`check_file_hash\` before open/execute.

Full policy via MCP \`agent_guard_policy\`.
`;
}

function readmeMd(entry: string): string {
  return `# Aegis MCP Deploy Bundle

Generated locally. MCP server entry:

\`\`\`
${entry} --mcp
\`\`\`

## Claude Desktop / Cursor / other JSON clients

Merge into your client MCP settings:

\`\`\`json
${mcpConfigJson(entry).trim()}
\`\`\`

Or copy \`mcp.claude.json\` and paste the \`mcpServers\` block.

## Optional installer

\`\`\`bash
bash install.sh
\`\`\`

Creates \`.aegis.bak\` backups and merges \`mcpServers.aegis\` into detected clients. Restart the client afterward.

## HTTP fallback

\`\`\`bash
curl -sS ${"http://127.0.0.1:7832/api/v1"}/agent-policy
\`\`\`

See also Agent Guard rules in \`SKILL.md\`.
`;
}

function installSh(entry: string): string {
  return `#!/usr/bin/env bash
set -euo pipefail
ENTRY="${entry}"
AEGIS_ROOT="$(cd "$(dirname "$0")" && pwd)"
CFG_JSON='{"mcpServers":{"aegis":{"command":"node","args":["'"$ENTRY"'","--mcp"]}}}'

merge_one() {
  local file="$1"
  local label="$2"
  if [ ! -f "$file" ]; then
    echo "[skip] $label — config not found ($file)"
    return 0
  fi
  cp "$file" "$file.aegis.bak.$(date +%Y%m%d%H%M%S)"
  node -e '
    const fs = require("fs");
    const file = process.argv[1];
    const raw = fs.readFileSync(file, "utf8");
    let data;
    try { data = JSON.parse(raw); } catch (e) {
      console.error("[fail] invalid JSON:", file, e.message);
      process.exit(2);
    }
    data.mcpServers = data.mcpServers || {};
    data.mcpServers.aegis = {
      command: "node",
      args: [process.argv[2], "--mcp"],
    };
    fs.writeFileSync(file, JSON.stringify(data, null, 2) + "\\n");
    console.log("[ok] merged aegis into", file);
  ' "$file" "$ENTRY"
}

CLAUDE="\${CLAUDE_CONFIG:-$HOME/Library/Application Support/Claude/claude_desktop_config.json}"
CURSOR="\${CURSOR_CONFIG:-$HOME/.cursor/mcp.json}"

merge_one "$CLAUDE" "Claude Desktop"
merge_one "$CURSOR" "Cursor"

echo "Done. Restart Claude Desktop / Cursor if configs were written."
echo "Bundle dir: $AEGIS_ROOT"
`;
}

export function buildDeployBundle(entryOverride?: string): DeployBundle {
  const entry = entryOverride && entryOverride.length > 0 ? entryOverride : resolveMcpEntry();
  const config = mcpConfigJson(entry);
  const files: DeployFile[] = [
    {
      filename: "mcp.claude.json",
      content: config,
      mediaType: "application/json",
    },
    {
      filename: "mcp.config.json",
      content: config,
      mediaType: "application/json",
    },
    {
      filename: "SKILL.md",
      content: skillMd(),
      mediaType: "text/markdown",
    },
    {
      filename: "README.md",
      content: readmeMd(entry),
      mediaType: "text/markdown",
    },
    {
      filename: "install.sh",
      content: installSh(entry),
      mediaType: "text/x-shellscript",
    },
  ];
  return {
    name: "aegis-mcp-deploy",
    generatedAt: new Date().toISOString(),
    mcpEntry: entry,
    mcpCommand: entry.endsWith(".ts")
      ? `npx tsx "${entry}" --mcp`
      : `node "${entry}" --mcp`,
    mcpConfig: JSON.parse(config) as DeployBundle["mcpConfig"],
    files,
  };
}

export function clientStatus(): ClientStatus[] {
  const entry = resolveMcpEntry();
  const targets: ClientStatus[] = [
    {
      id: "claude-desktop",
      label: "Claude Desktop",
      configPath:
        process.env.CLAUDE_CONFIG ??
        path.join(
          os.homedir(),
          "Library",
          "Application Support",
          "Claude",
          "claude_desktop_config.json",
        ),
      exists: false,
      hasAegis: false,
    },
    {
      id: "cursor",
      label: "Cursor",
      configPath: process.env.CURSOR_CONFIG ?? path.join(os.homedir(), ".cursor", "mcp.json"),
      exists: false,
      hasAegis: false,
    },
  ];
  for (const t of targets) {
    t.exists = fs.existsSync(t.configPath);
    if (t.exists) {
      try {
        const raw = fs.readFileSync(t.configPath, "utf8");
        t.hasAegis = /"aegis"\s*:/.test(raw) || raw.includes(entry);
      } catch {
        t.hasAegis = false;
      }
    }
  }
  return targets;
}

/** Minimal ZIP (store, no compression) for one-click download. */
export function buildDeployZip(bundle: DeployBundle): Buffer {
  const files = bundle.files.map((f) => ({
    name: `${bundle.name}/${f.filename}`,
    data: Buffer.from(f.content, "utf8"),
  }));
  const chunks: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;

  const crcTable = (() => {
    const t = new Int32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      t[n] = c;
    }
    return t;
  })();

  function crc32(buf: Buffer): number {
    let c = -1;
    for (let i = 0; i < buf.length; i++) {
      c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
    }
    return (c ^ -1) >>> 0;
  }

  for (const f of files) {
    const nameBuf = Buffer.from(f.name, "utf8");
    const crc = crc32(f.data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8); // store
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(0, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(f.data.length, 18);
    local.writeUInt32LE(f.data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28);
    chunks.push(local, nameBuf, f.data);

    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0);
    cen.writeUInt16LE(20, 4);
    cen.writeUInt16LE(20, 6);
    cen.writeUInt16LE(0, 8);
    cen.writeUInt16LE(0, 10);
    cen.writeUInt16LE(0, 12);
    cen.writeUInt16LE(0, 14);
    cen.writeUInt32LE(crc, 16);
    cen.writeUInt32LE(f.data.length, 20);
    cen.writeUInt32LE(f.data.length, 24);
    cen.writeUInt16LE(nameBuf.length, 28);
    cen.writeUInt16LE(0, 30);
    cen.writeUInt16LE(0, 32);
    cen.writeUInt16LE(0, 34);
    cen.writeUInt16LE(0, 36);
    cen.writeUInt32LE(0, 38);
    cen.writeUInt32LE(offset, 42);
    central.push(cen, nameBuf);
    offset += local.length + nameBuf.length + f.data.length;
  }

  const centralBuf = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(centralBuf.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);

  return Buffer.concat([...chunks, centralBuf, end]);
}
