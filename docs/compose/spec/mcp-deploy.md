---
feature: mcp-deploy
status: designed
updated: 2026-09-17
branch: feat/mcp-deploy
commits: 5ffc9d1..pending
---

# 一键导出 MCP 配置包

## Report

## [S1] Problem

Aegis 已具备 MCP 服务与协议说明，但接入仍需用户手抄路径、拼 JSON。需要**一键导出**可直接使用的 MCP 部署配置包（默认**不**改写本机客户端配置，只导出/复制/下载）。

## [S2] Design

### 交付物（配置包）

由服务端按本机 `mcpEntry` 绝对路径生成：

| 文件 | 内容 |
|------|------|
| `mcp.claude.json` | Claude Desktop / Cursor 等 `mcpServers.aegis` |
| `mcp.config.json` | 同上（兼容名） |
| `SKILL.md` | Agent Guard 协议摘要（给 harness） |
| `README.md` | 如何粘贴到各客户端 + HTTP 备用 |
| `install.sh` | **可选**：检测 Claude/Cursor 等并合并写入（先 `.bak` 备份）；默认不自动执行 |

### HTTP

- `GET /api/v1/mcp-deploy/bundle` → `{ name, generatedAt, mcpEntry, mcpCommand, files: [{ filename, content, mediaType }] }`
- `GET /api/v1/mcp-deploy/bundle.zip` → `application/zip`（Node 内存 zip 或 store 逐文件下载包）
- `GET /api/v1/mcp-deploy/status` → 探测常见客户端配置路径是否存在、是否已含 `aegis`

### MCP

- 工具 `export_mcp_bundle` → 返回 JSON 文件列表（与 bundle 相同）

### 控制台

- **接入**页：「一键导出 MCP 配置包」
  - 复制 `mcp.claude.json`
  - 下载 zip / 逐文件下载
  - 展示 `install.sh` 说明（可选执行）
- 显示本机 MCP command 路径

### install.sh（可选工具，默认用户手动跑）

- 探测路径：Claude Desktop、Cursor、VS Code Claude 等；**不**默认写 MiMoCode（本机已存在配置，避免误合并）
- 写入前 `cp config config.aegis.bak`
- 用 node/python 合并 `mcpServers.aegis`
- 打印需重启客户端的提示

## [S3] Out of Scope

- 静默改写本机 MCP 客户端配置（UI 一键只导出）
- 系统托盘安装器 / 签名分发

## Tasks

- [ ] T1: Spec 本文件 — acceptance: 契约完整 (covers: S2)
- [ ] T2: bundle 生成器 + HTTP 导出 — acceptance: GET bundle 含 mcp json/SKILL/README/install.sh；zip 可下载 (covers: S2)
- [ ] T3: MCP export_mcp_bundle + status 探测 — acceptance: tools/list 含 export_mcp_bundle (covers: S2)
- [ ] T4: 接入页一键导出 UI — acceptance: 可复制 JSON、下载 zip (covers: S2)
- [ ] T5: Verify + review + finalize — acceptance: test/typecheck/build PASS；评审通过 (covers: S2)
