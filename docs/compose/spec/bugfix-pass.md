---
feature: bugfix-pass
status: designed
updated: 2026-09-18
branch: fix/bugfix-pass
commits: e7e9bb7..pending
---

# Bugfix pass — 自主检测与修复

## Report

## [S1] Problem

自动巡检发现 Aegis 门禁链路存在安全与正确性缺陷：本地 CSRF 可改策略、待审 no-op 仍写永久名单、自定义域名覆盖内置权威库、会话信任绕过仿冒硬拦截、打包应用 Node 依赖/数据目录分裂、悬浮窗审批假成功、设置表单被轮询覆盖等。

## [S2] Design

### 修复清单（本轮必做）

| ID | 问题 | 修复 |
|----|------|------|
| B1 | 变更接口仅在无 Origin 时要 token | 变更接口**始终**要 `X-Aegis-Token`；同源控制台经 `GET /api/v1/session-token`（仅 localhost Origin）取 token；Electron preload IPC 读 `.aegis/token` |
| B2 | resolve 非 pending 仍 alwaysAllow | `resolveReview` 返回 `{changed}`；仅 changed 且状态匹配时写名单；否则 409 |
| B3 | customBrands 覆盖 builtin | builtin 优先；custom 仅作补充；host 校验 `isValidHostname` |
| B4 | session trust 豁免 lookalike 硬拦截 | lookalike 始终硬 block（除非 allowlist）；trust 不再覆盖 lookalike |
| B5 | `?entry=` 注入 install.sh | entry 必须存在且位于项目根；拒绝 `$` ` ` 引号换行 |
| B6 | MCP 配置缺 AEGIS_DATA_DIR | 导出 MCP config 带 `env.AEGIS_DATA_DIR`（项目 `.aegis` 或现有 env） |
| B7 | 状态整文件覆盖 | persist 前 `load()` 合并（最小竞态修复） |
| B8 | allowlist 后缀过宽 | 列表项校验 hostname，≥2 标签 |
| B9 | VT 并发踩限流 | promise 串行 mutex |
| B10 | file observe 下 VT error→allow | error/degraded/unknown → review |
| B11 | 悬浮窗审批假成功 | 带 token；`!res.ok` 抛错；放行写 session trust |
| B12 | 一次性「放行」不生效 | 人工 allow 默认 `trustDomain`（永久用「放行·永久」） |
| B13 | 设置表单被 8s 刷新覆盖 | settings 且 dirty 时不重载 config 表单字段 |
| B14 | integration 报告错误 port | 使用 `readPortFile()` 实际端口 |
| B15 | 打包 Node 找不到 express | spawn 时 `NODE_PATH=…/app.asar/node_modules` + `ELECTRON_RUN_AS_NODE` |
| B16 | history 导出/渲染 | optional chaining；export 不用坏 href |
| B17 | config.json 权限 | 写入 mode 0600 |
| B18 | macOS 关窗杀服务 | darwin 关窗不 kill；before-quit 才 kill |

### 不在本轮

- HTTP MCP 远程代替 stdio 全面改造
- VS Code 客户端自动写入
- 复杂 eTLD+1 公共后缀列表

## [S3] Out of Scope

见上「不在本轮」。

## Tasks

- [ ] T1: Spec 本文件 (covers: S2)
- [ ] T2: Server 安全/正确性 B1–B10,B14,B17 + 回归测试 (covers: S2)
- [ ] T3: Electron/UI B11–B13,B15,B16,B18 (covers: S2)
- [ ] T4: Verify + review + finalize (covers: S2)
