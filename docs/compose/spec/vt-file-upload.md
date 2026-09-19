---
feature: vt-file-upload
status: delivered
updated: 2026-09-18
branch: feat/vt-file-upload
commits: 8d26d53..2fcf3a3
---

# VirusTotal 小文件上传扫描（回传 AI）

## Report

**What was built** — Agent 下载小文件（默认 ≤32MB，`maxUploadBytes` 可配）后可调用 MCP `scan_downloaded_file` / `upload_scan_file`，或 HTTP `POST /api/v1/scan-file`（本地 path 或 base64）。服务端校验大小与路径，计算哈希，VirusTotal 查询；配置 API Key 且样本未知时**主动上传**并有限次轮询分析（约 2 次，避免无限等待），将 `decision`（allow/review/block）、VT 统计、permalink、scan meta **返回给 AI**。无 Key / 超限 / 路径无效返回明确错误或 review，不执行文件。

**Verification** — `npm run typecheck` PASS；`npm test` **48/48**；live：`POST /scan-file` 对小文件上传 VT 后返回 `decision=allow` + permalink。MCP 含 `scan_downloaded_file` 与 `upload_scan_file`。

**Journey log** —
1. VT 免费档上传约 32MB；超限不得排队阻塞 Agent。
2. 默认 poll 15 次会挂死 HTTP/MCP；改为 2 次并返回 pending 结果。
3. 无 Key 时 `vt_key_required`，Agent 应回退 `check_file_hash` 或提示配置。
4. 结果 JSON 需含 hash/decision/permalink，Agent 才能继续或隔离。

## [S1] Problem

新下载文件 VT 常无哈希记录，需要上传扫描并把结论回传给 AI。

## [S2] Design

见 Report；工具：`scan_downloaded_file` / `upload_scan_file`；HTTP：`/scan-file`；配置：`maxUploadBytes`。

## [S3] Out of Scope

商业多引擎、自动隔离目录、超大文件分片。

## Tasks

- [x] T1: Spec
- [x] T2: scan service + HTTP + MCP
- [x] T3: 测试 + 协议文案
- [x] T4: Verify + merge
