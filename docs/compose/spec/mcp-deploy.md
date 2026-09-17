---
feature: mcp-deploy
status: delivered
updated: 2026-09-17
branch: feat/mcp-deploy
commits: 5ffc9d1..15fb9ca
---

# 一键导出 MCP 配置包

## Report

**What was built** — Aegis「一键导出 MCP 配置包」：在 **接入** 页一键复制本机 `mcp.claude.json`、下载 `aegis-mcp-deploy.zip`。配置包含 `mcp.claude.json` / `mcp.config.json`、`SKILL.md`、`README.md` 与可选 `install.sh`。按用户选择为**仅导出**，不会静默改写 Claude/Cursor 等客户端配置；若手动执行 `install.sh`，会先备份再合并 `mcpServers.aegis`，且 command 与 JSON 使用同一 `mcpServerEntry`（node / npx tsx）。HTTP：`GET /api/v1/mcp-deploy/bundle|bundle.zip|status`；MCP：`export_mcp_bundle`。

**Verification** — `npm run typecheck` PASS；`npm test` **36/36**（含 install.sh 与 JSON command 一致性、ZIP PK 头）；`npm run build` PASS；bundle 五文件齐全；zip HTTP 200 且为合法 store ZIP；status 探测 Claude/Cursor 路径；MCP `export_mcp_bundle` 可用。首轮 REQUEST_CHANGES（install.sh 与 JSON 命令不一致、UI 复制优先级）已修复，复审 **APPROVE**。

**Journey log** —
1. 一键导出 ≠ 静默安装：默认只打包，安装脚本可选且写前备份。
2. JSON 与 install.sh 必须共用 `mcpServerEntry()`，避免 dev 为 `.ts` 时脚本写成 `node *.ts`。
3. UI `a ?? b ? c : d` 会因运算符优先级变成 `(a ?? b) ? c : d`；复制逻辑先取 bundle 文件再回退。
4. 纯 Node store ZIP 可零依赖导出；路径含空格的项目用 `fileURLToPath` 更稳。
5. `install.sh` 合并前 `cp …aegis.bak`，且不默认触碰 MiMoCode 配置。

## [S1] Problem

Aegis 已具备 MCP 服务与协议说明，但接入仍需用户手抄路径、拼 JSON。需要**一键导出**可直接使用的 MCP 部署配置包（默认**不**改写本机客户端配置，只导出/复制/下载）。

## [S2] Design

### 交付物（配置包）

由服务端按本机 `mcpEntry` 绝对路径生成：

| 文件 | 内容 |
|------|------|
| `mcp.claude.json` | `mcpServers.aegis`（node 或 npx tsx） |
| `mcp.config.json` | 同上（兼容名） |
| `SKILL.md` | Agent Guard 协议摘要 |
| `README.md` | 粘贴到各客户端 + HTTP 备用 |
| `install.sh` | 可选：探测 Claude/Cursor 并合并（先 `.bak` 备份）；command 与 JSON 一致 |

### HTTP / MCP

- `GET /api/v1/mcp-deploy/bundle` → 文件列表 + mcpCommand
- `GET /api/v1/mcp-deploy/bundle.zip` → zip
- `GET /api/v1/mcp-deploy/status` → 客户端配置是否已含 aegis
- MCP `export_mcp_bundle` → 同 bundle JSON

### 控制台

- 接入页：复制 MCP JSON、下载 ZIP、展示 command 与 install 提示

## [S3] Out of Scope

- 静默改写本机 MCP 客户端配置
- 安装器/签名分发/VS Code 路径自动写入

## Tasks

- [x] T1: Spec — acceptance: 契约完整 (covers: S2)
- [x] T2: bundle + zip + status HTTP — acceptance: 导出五文件与合法 zip (covers: S2)
- [x] T3: MCP export_mcp_bundle — acceptance: tools/list 与调用成功 (covers: S2)
- [x] T4: 接入页一键导出 — acceptance: 复制 JSON / 下载 ZIP (covers: S2)
- [x] T5: Verify + review + finalize — acceptance: 36 tests；复审 APPROVE (covers: S2)
