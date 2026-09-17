---
feature: agent-guard
status: delivered
updated: 2026-09-17
branch: feat/agent-guard
commits: 8a37f73..c011696
---

# Agent Guard — 接入协议 + 会话信任

## Report

**What was built** — Aegis Agent Guard v1.0 定义 Harness 出网前的强制协议（preflight / allow / block / review / search / files），并通过 MCP 与 HTTP 提供 `agent_guard_policy`、`scan_search_results`、`trust_domain`、`session_trust` 等工具。待审通过后可写入**会话信任**（非永久白名单），门禁在 denylist / VT malicious / 威胁情报 LISTED 等硬危险信号之后，才对 session-trusted 主机放行。操作者可在 Settings 配置 **customBrands**（私有官方域名主体），并维护会话信任列表；接入页展示协议步骤，`examples/agent-guard` 提供 MCP 配置与 SKILL 片段。

**Verification** — `npm run typecheck` PASS；`npm test` **32/32** PASS（含 session trust allow、denylist/malicious 仍 block、非法 hostname、custom brand）；`npm run build` PASS；`GET /api/v1/agent-policy` 返回 Aegis Agent Guard 1.0；POST 非法 hostname → 400；无 Origin 的 session-trust POST 无 token → 401；`DELETE /session-trust/%2A` 可清空；MCP tools/list 含 `scan_search_results` / `trust_domain` / `agent_guard_policy`。首轮评审 REQUEST_CHANGES，修复后复审 **APPROVE**。

**Journey log** —
1. 会话信任 ≠ 永久 allowlist；硬危险（denylist / VT malicious / intel listed）优先于信任。
2. 本地安全 POST（session-trust、reviews resolve）在无浏览器 Origin 时需 `X-Aegis-Token`，控制台同源不受影响。
3. 服务数据目录统一：`AEGIS_DATA_DIR` 或模块相对 `ROOT/.aegis`（store / trust / reviews / VT / intel）。
4. 自定义品牌合并进权威库，并参与仿冒检测基线；同主机 custom 覆盖 builtin。
5. 审计工具不可完全依赖 MCP 描述做权限；`resolve_review` 文案要求「显式人类确认」。

## [S1] Problem

Aegis 已能对 URL 做三态门禁，但 **Agent Harness 缺少强制接入约定**：何时必须核查、如何把搜索结果批量送审、待审通过后本会话如何复用、如何把公司私有域名并入权威库。没有这套协议，Agent 仍可能跳过门禁或每次重复问询。

## [S2] Design

### Agent Guard 协议（Harness 必须遵守）

1. **出网前**：Agent 访问 / 下载 / 粘贴来自任一 URL 前，先调用 `check_url`。
2. **`decision=allow`** → 可继续。
3. **`decision=block`** → 停止，不得绕过。
4. **`decision=review`** → **不得访问**；向人类展示域名与证据；等用户在悬浮窗/控制台批准，或 Agent 调用 `resolve_review`（需人类确认）。成功后可调用 `trust_domain` 写入**会话信任**。
5. **搜索结果**：对候选链接列表调用 `scan_search_results`（≤20 条），仅跟进 `allow` 或已会话信任的项。
6. **下载后**：对文件哈希调用 `check_file_hash`，`block` 则删除/隔离且不执行。

### 会话信任（Session Trust）

- 本地持久化：`hostname` → { addedAt, reason, source }
- 来源：`user` / `agent` / `resolve`
- 应用重启保留；不等于永久 allowlist；可一键清空
- 门禁顺序：denylist → allowlist(永久) → **session trust**（仅当无硬危险）  
  - session trust + VT/intel 无高危 → `allow`
  - denylist / VT malicious / intel listed → 仍 `block`
- hostname 校验：非法（含 scheme/路径/空格）→ HTTP 400 / MCP error

### 自定义权威域名

- `EngineConfig.customBrands`: `[{ host, brand, subject }]`
- 查找顺序：内置 official-domains.json → customBrands（同 host 可覆盖）
- Settings 可编辑；`PUT /api/v1/config`

### MCP / HTTP 契约

| 工具 / 接口 | 作用 |
|-------------|------|
| `agent_guard_policy` / `GET /agent-policy` | 协议文本与规则 |
| `check_url` | 门禁；review 时带 reviewId + 协议提示 |
| `scan_search_results` / `check_urls_batch` | 批量核查 + worst-case |
| `check_file_hash` | 下载文件哈希 |
| `trust_domain` / `POST /session-trust` | 会话信任（校验 hostname） |
| `session_trust` / `GET /session-trust` | 列表 |
| `untrust_domain` / `DELETE /session-trust/:host` | 移除 |
| `DELETE /session-trust/%2A` | 清空 |
| `get_pending_reviews` / `resolve_review` | 待审（resolve 需人类确认文案） |
| `verify_domain` / `get_gate_status` | 原有能力 |

安全：无浏览器 `Origin` 时，`POST /session-trust`、`POST /reviews/*`、`DELETE/PATCH` 等变更接口要求 `X-Aegis-Token`（`.aegis/token`）。

### 控制台

- **设置**：customBrands 文本行、会话信任列表与清空、提示音、策略等
- **接入**：Agent Guard 协议步骤 + MCP/HTTP 说明

## [S3] Out of Scope

- 系统级进程网络钩子 / MITM
- 云端多租户策略同步
- 服务端强制 MCP resolve 前的二次人类确认（协议约定 + UI/悬浮窗承担）

## Tasks

- [x] T1: Spec `docs/compose/spec/agent-guard.md` — acceptance: 协议与契约齐备 (covers: S2)
- [x] T2: Session trust store + gate 接入 — acceptance: trust 后未知域名 allow；denylist/VT malicious 仍 block (covers: S2)
- [x] T3: customBrands 注册表 + config API — acceptance: PUT 后 lookup 命中自定义品牌 (covers: S2)
- [x] T4: MCP tools + HTTP session-trust/agent-policy — acceptance: tools 与 /agent-policy 可用 (covers: S2)
- [x] T5: Settings / 接入页 UI — acceptance: customBrands 与 session trust 可管理 (covers: S2)
- [x] T6: examples/agent-guard — acceptance: MCP + 协议 README + SKILL (covers: S2)
- [x] T7: Verify + review + finalize — acceptance: typecheck/test/build PASS；评审 APPROVE；Report 完成 (covers: S2)
