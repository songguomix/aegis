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
npm run dev:server          # HTTP API on http://127.0.0.1:7832/api/v1
# another terminal
npm run dev:ui              # Liquid-glass console on http://localhost:5173
```

Desktop shell:

```bash
npm run dev                 # server + UI + Electron together
```

MCP (stdio):

```bash
npx tsx server/index.ts --mcp
```

Example MCP client config:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "npx",
      "args": ["tsx", "/absolute/path/to/server/index.ts", "--mcp"]
    }
  }
}
```

## HTTP check example

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

Config persists in `.aegis/config.json`.
