# Aegis Agent Guard

Harness 在每次出网前必须遵守的协议（v1.0）。

## 1. 挂载 MCP

```json
{
  "mcpServers": {
    "aegis": {
      "command": "node",
      "args": [
        "/Users/pinecones/Desktop/Cybersecurity For AI Agents/dist-server/index.js",
        "--mcp"
      ]
    }
  }
}
```

## 2. 协议摘要

| 规则 | 行为 |
|------|------|
| preflight | 访问/下载/信任 URL 前调用 `check_url` |
| allow | 可继续 |
| block | 停止，不绕过 |
| review | **禁止访问**；人类确认后 `resolve_review`；可选 `trust_domain` |
| search | `scan_search_results`（≤20）只跟进 allow |
| files | 下载后 `check_file_hash`；block → 隔离 |

完整策略：MCP `agent_guard_policy` 或 `GET /api/v1/agent-policy`。

## 3. 会话信任

- `trust_domain({ hostname })` — 本会话放行（非永久）
- `session_trust()` / `untrust_domain({ hostname })`
- HTTP：`GET/POST /api/v1/session-trust`，`DELETE /api/v1/session-trust/:host`

## 4. curl 示例

```bash
BASE=http://127.0.0.1:7832/api/v1

# 门禁
curl -sS $BASE/check -H 'content-type: application/json' \
  -d '{"url":"https://github.com"}'

# 搜索结果批量
curl -sS $BASE/check-batch -H 'content-type: application/json' \
  -d '{"urls":["https://a.example","https://b.example"]}'

# 协议
curl -sS $BASE/agent-policy
```
