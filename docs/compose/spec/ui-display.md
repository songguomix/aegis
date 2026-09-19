---
feature: ui-display
status: delivered
updated: 2026-09-18
branch: fix/ui-display
commits: 0e4e06a..b4b91d3
---

# UI display polish

## Report

**What was built** — 修复控制台与悬浮条显示问题：历史表 Decision 列不再抢占整行宽度（URL 表单独 `.cols-url`）；域名单元格省略号；会话信任容器边框；Toast 最大宽度与错误/信息错位；设置策略/语言改为全宽，避免下拉截断；接入页 Agent Guard 文案中英 i18n；悬浮条展开加宽至约 500px，review 时压缩计数，按钮随系统语言。

**Verification** — `npm run typecheck` PASS；`npm test` 39/39；`npm run build` UI/CSS 产出正常。

**Journey log** —
1. 通用 `td:nth-child(2){width:100%}` 会破坏多列表格，必须按表类名作用域。
2. Toast 与 error 共用定位时要错位并限制 `max-width`。
3. 悬浮条 review 模式应压缩计数，优先展示域名。

## [S1] Problem

界面显示：列宽失衡、Toast 重叠、设置截断、中英混排、悬浮条域名过窄。

## [S2] Design

见 Report；CSS + App + floating.html 本地修复。

## [S3] Out of Scope

全面重设计、功能变更。

## Tasks

- [x] T1: Spec
- [x] T2: CSS + App + float 修复
- [x] T3: Verify + merge
