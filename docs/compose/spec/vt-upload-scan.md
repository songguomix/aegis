---
feature: vt-upload-scan
status: designed
updated: 2026-09-18
branch: feat/vt-upload-scan
commits: 8d26d53..pending
---

# VT 小文件上传扫描（回传 AI）

## Report

## [S1] Problem

Agent 下载的文件目前只能按哈希查 VirusTotal（需先有本地哈希且 VT 已收录）。对于 **VT 可接受的小体积文件**（公开 API 默认 ≤32MB），应主动 **上传扫描**，并把分析结果 **同步返还给 AI**，作为继续执行/打开的依据。

## [S2] Design

### 限制

- 最大上传 `maxUploadBytes`（默认 **32MB**，配置可调 1–64MB）
- 超限或无 VT Key → 明确错误/降级，**不**上传
- 公开 API 限速：上传后轮询分析（默认最多 ~15 次 × 2s）

### 流程

```
AI 调用 upload_scan_file({ path | filename, base64 | bytes })
  → 校验体积 / 解码
  → 算 SHA256 → 若 VT 已有报告可直接返回（缓存）
  → 否则 POST /files 上传
  → 轮询 /analyses/{id}
  → mapStats → FileGateResult 同构 decision + reasons + permalink
  → appendHistory(kind=file)
  → 返回 JSON 给 AI
```

### 契约

#### HTTP

- `POST /api/v1/upload-scan`
  - JSON: `{ "filename": "a.zip", "base64": "...", "context"?: "..." }`
  - 或 multipart `file` + optional `context`（需 token，同变更/敏感）
  - 响应：`FileGateResult` + `{ analysisId, uploaded: true|false, sha256, bytes, permalink }`
- 超限：`413 { error: "file_too_large", maxBytes }`
- 无 Key：`400 { error: "vt_key_required" }`

#### MCP

- `upload_scan_file({ path? , filename?, base64?, context? })`
  - 优先 `path`（服务器本机路径，Agent 下载目录）
  - 或 `base64` + `filename`
  - 返回与 HTTP 相同 JSON（文字）

#### Agent Guard

- 下载后：文件 ≤ maxUploadBytes 时调用 `upload_scan_file`
- `decision=block` → 删除/隔离，不执行
- `review`/`degraded` → 人类确认前不执行

### UI（最小）

- 设置：`maxUploadMB` 展示与保存（config `maxUploadBytes`）
- 实时核查·文件哈希页可提示：更小文件可用 MCP/HTTP 上传扫描

## [S3] Out of Scope

- 大文件分片/私有 API
- 自动钩子扫描 Agent 任意下载目录（协议由 Harness 调用）
- 多引擎（仅 VT）

## Tasks

- [ ] T1: Spec
- [ ] T2: virustotal upload + analyze 服务 — acceptance: 单测 mock 上传/轮询/map 结果 (covers: S2)
- [ ] T3: HTTP upload-scan + MCP upload_scan_file — acceptance: 无 Key 400；超限 413；有 Key mock 返回 decision+permalink (covers: S2)
- [ ] T4: 设置 maxUploadMB + 协议文档 — acceptance: config 可读写；Integrate/README 补充 (covers: S2)
- [ ] T5: Verify + review + finalize (covers: S2)
