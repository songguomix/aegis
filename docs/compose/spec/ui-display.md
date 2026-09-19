---
feature: ui-display
status: designed
updated: 2026-09-18
branch: fix/ui-display
commits: 0e4e06a..pending
---

# UI display polish

## Report

## [S1] Problem

控制台与悬浮条存在显示问题：历史表列宽失衡、会话信任框无边框、Toast 重叠溢出、悬浮条待审时域名过窄且中英混排、设置下拉截断、接入页英文界面下中文协议文案、历史域名无省略。

## [S2] Design

| ID | 修复 |
|----|------|
| U1 | 表格列宽：URL 表单独类；历史用 hostname 列弹性 + 省略 |
| U2 | 会话信任容器补边框样式 `.glass-soft` |
| U3 | Toast `max-width` + 错误提示错位 |
| U4 | 悬浮条展开约 480px；review 时压缩计数 |
| U5 | 悬浮条按钮随语言（en/zh） |
| U6 | 设置策略/语言改为全宽行 |
| U7 | Agent Guard 文案 i18n |
| U8 | `.table td.mono` 省略 + title |

## [S3] Out of Scope

- 全面视觉重设计
- 非本 issue 的功能改动

## Tasks

- [ ] T1: Spec
- [ ] T2: CSS + App + float 修复 (covers: S2)
- [ ] T3: Verify + merge (covers: S2)
