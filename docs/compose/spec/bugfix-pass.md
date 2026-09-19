---
feature: bugfix-pass
status: delivered
updated: 2026-09-18
branch: fix/bugfix-pass
commits: e7e9bb7..7cc1b84
---

# Bugfix pass — 自主检测与修复

## Report

**What was built** — 自主巡检（服务端 + UI/Electron）后集中修复安全与正确性问题：变更接口一律校验 `X-Aegis-Token`（同源控制台经 `GET /session-token` 取 token，允许无 Origin；拒绝外站 Origin）；待审 `resolve` 非 pending 返回 409 且不写永久名单；自定义权威域名不覆盖内置库且校验主机名；会话信任不再豁免仿冒硬拦截；MCP 配置注入 `AEGIS_DATA_DIR`；`?entry=` 防 shell 注入；设置表单 dirty 防轮询覆盖；悬浮窗审批带 token 并检查 HTTP 状态；放行默认写会话信任；Electron 打包 `NODE_PATH`、macOS 关窗不杀服务；配置文件 merge + chmod 0600。

**Verification** — `npm run typecheck` PASS；`npm test` **39/39**；`npm run build` PASS；`POST /check` 无 token → 401；`GET /session-token` 无 Origin → 200，外站 Origin → 403；integration `mcpConfig` 含 `AEGIS_DATA_DIR`；lookalike + session trust 仍 block（单测）。首轮复审 REQUEST_CHANGES 后已修 token/合并/dirty/env 等，关键路径可验证。

**Journey log** —
1. 浏览器同源 GET 往往不带 `Origin`；token 引导接口不能要求 Origin（服务已绑 127.0.0.1）。
2. `writeFileSync` 的 `mode` 只影响新建文件，已有配置要 `chmodSync`。
3. 配置合并应 `{...disk, ...patch}`，不能用全量内存覆盖并发写入。
4. 自定义品牌必须 builtin 优先，否则 lookalike 可被“官方化”。
5. UI `settingsDirty` 必须覆盖所有可编辑字段，且成功保存后再清除。

## [S1] Problem

自动巡检发现门禁链路存在安全与正确性缺陷：本地 CSRF 可改策略、待审 no-op 仍写名单、自定义域名覆盖权威库、会话信任绕过仿冒拦截、打包数据目录/依赖问题、悬浮窗假成功、设置被轮询覆盖等。

## [S2] Design

见任务表与代码；核心契约：
- 变更 API：`X-Aegis-Token` 必填；`GET /api/v1/session-token` 同源控制台可用
- `POST /reviews/:id/resolve`：非 pending → 409；allow 默认 session trust
- customBrands 不覆盖 builtin；lookalike 不因 session trust 放行
- MCP 导出配置带 `env.AEGIS_DATA_DIR`

## [S3] Out of Scope

- HTTP 侧 MCP 客户端进程改造
- 公共后缀 eTLD+1 完整列表
- VS Code 自动写入

## Tasks

- [x] T1: Spec (covers: S2)
- [x] T2: Server B1–B10, B14, B17 + 回归测试 (covers: S2)
- [x] T3: Electron/UI B11–B13, B15, B16, B18 (covers: S2)
- [x] T4: Verify + review + finalize (covers: S2)
