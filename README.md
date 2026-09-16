# Aegis

Truth before trust — local network security gateway for AI agents.

## What it does

Before an AI agent visits a URL, **Aegis** verifies:

1. **Domain authority** — official brand registry (GitHub, npm, PyPI, cloud consoles…), RDAP subject, lookalike/typosquat/homograph signals
2. **VirusTotal reputation** — automatic domain lookup (API key optional; degrades gracefully)
3. **Tri-state gate** — `allow` / `review` / `block` with evidence for the agent and operator

Integrates via **HTTP API** and **MCP** (`check_url`, `verify_domain`, `get_gate_status`).

## Quick start

```bash
npm install
npm test
```

### Desktop app (recommended)

```bash
npm run pack:app
# 产物：
#   release/mac-arm64/Aegis.app
#   release/Aegis-0.1.0-arm64.dmg
open release/mac-arm64/Aegis.app
# 或打开 DMG 安装到「应用程序」
```

开发模式：

```bash
npm run dev                 # server + UI + Electron
# 或分开：
npm run dev:server
npm run dev:ui
npm run start               # electron .
```

### 仅 HTTP / MCP（无桌面壳）

```bash
npm run dev:server          # http://127.0.0.1:7832/api/v1
npx tsx server/index.ts --mcp
```

Example MCP client config: `examples/mcp.config.json`

```bash
curl -s http://127.0.0.1:7832/api/v1/check \
  -H 'content-type: application/json' \
  -d '{"url":"https://github.com/modelcontextprotocol/servers"}'
```

## Settings

Open the console → **Settings**:

- VirusTotal API key (local only)
- Policy mode: tri-state / strict / observe
- Allowlist / denylist
- Language: English / 中文
- RDAP toggle

Dev config persists in `.aegis/`. Packaged app data lives in
`~/Library/Application Support/Aegis/`.
