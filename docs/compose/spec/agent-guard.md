---
feature: agent-guard
status: designed
updated: 2026-09-17
branch: feat/agent-guard
commits: 8a37f73..pending
---

# Agent Guard — 接入协议 + 会话信任

## Report

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

- 内存 + 本地持久化：`hostname` → { addedAt, reason, source }
- 来源：`user`（控制台）、`agent`（MCP）、`resolve`
- 默认 TTL：会话有效（应用重启保留，可手动清除）；不等于永久 allowlist
- 门禁顺序：denylist → allowlist(永久) → **session trust** → 永久 policy  
  - session trust + VT/intel 无高危 → `allow`（不 enqueue review）
  - session trust + VT malicious / intel listed / denylist → 仍 `block`

### 自定义权威域名

- `EngineConfig.customBrands`: `[{ host, brand, subject }]`
- 注册表查找顺序：内置 official-domains.json → customBrands
- Settings 可编辑；`GET/PUT /api/v1/config`

### MCP / HTTP 契约

| 工具 / 接口 | 作用 |
|-------------|------|
| `check_url` | 门禁；review 时带 `reviewId` + 协议提示 |
| `scan_search_results({ urls })` | 批量核查（alias of check_urls_batch） |
| `check_urls_batch` | 原批量工具保留 |
| `trust_domain({ hostname, reason? })` | 会话信任 |
| `session_trust()` | 列出会话信任 |
| `untrust_domain({ hostname })` | 移除 |
| `agent_guard_policy()` | 返回协议文本与当前策略摘要 |
| `GET /session-trust` / `POST /session-trust` / `DELETE /session-trust/:host` | HTTP 同源能力 |
| `GET /agent-policy` | 协议 JSON |

### 控制台

- **设置**：自定义权威域名 textarea（`host | brand | subject` 每行）
- **设置/总览**：会话信任列表 + 清除
- **接入**：Agent Guard 协议步骤 + MCP 工具列表更新

### 错误行为

- trust 非法 hostname → 400
- trust 的 host 在 denylist → 仍 block
- scan 结果 `decision` 取 worst-case（同 batch）

## [S3] Out of Scope

- 系统级进程网络钩子 / MITM
- 云端多租户策略同步
- 永久自动学习误报改阈值（可后续迭代）

## Tasks

- [ ] T1: Spec `docs/compose/spec/agent-guard.md` — acceptance: 本文件含协议与契约 (covers: S2)
- [ ] T2: Session trust store + gate 接入 — acceptance: 单测：trust 后未知域名 allow；malicious 仍 block (covers: S2)
- [ ] T3: customBrands 注册表 + config API — acceptance: PUT config 后 lookup 命中自定义品牌 (covers: S2)
- [ ] T4: MCP tools + HTTP session-trust/agent-policy — acceptance: tools/list 含 scan_search_results / trust_domain / agent_guard_policy；curl /agent-policy 返回协议 (covers: S2)
- [ ] T5: Settings / 接入页 UI — acceptance: 可编辑 customBrands 与查看/清除 session trust (covers: S2)
- [ ] T6: examples/agent-guard — acceptance: MCP 配置 + 协议 README + curl 示例可复制 (covers: S2)
- [ ] T7: Verify + review + finalize — acceptance: typecheck/test/build PASS；独立评审通过；Report 填写 (covers: S2)
