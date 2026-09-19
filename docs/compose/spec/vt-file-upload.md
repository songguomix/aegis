---
feature: vt-file-upload
status: designed
updated: 2026-09-18
branch: feat/vt-file-upload
commits: 8d26d53..pending
---

# VirusTotal 小文件上传扫描（回传 AI）

## Report

## [S1] Problem

Agent 下载文件后目前仅能用哈希查 VirusTotal；**新样本**往往无记录。需要对 VT 免费档可承受的小文件（默认 ≤32MB）**主动上传扫描**，并把分析结果返回给 AI，形成下载后闭环。

## [S2] Design

### 行为

1. Agent 调用 MCP `scan_downloaded_file({ path })` 或 HTTP `POST /api/v1/scan-file`
2. 服务端校验路径存在、常规文件、大小 ≤ `maxUploadBytes`（默认 32MB，可配置）
3. 计算 SHA256 → `lookupFileVt`；若已有结果直接返回
4. 无 API Key → `vtStatus=degraded`，仍返回哈希与 decision（偏 review）
5. 有 Key 且未知 → `POST https://www.virustotal.com/api/v3/files`（multipart `file`）上传；再查分析；短暂等待后轮询（最多 N 次）；仍未知则返回 `unknown` + analysis_id
6. 决策：与 `fileGate` 一致（malicious→block；clean→allow；其余 tri-state→review）
7. 结果 JSON 含 `scan: { uploaded, analysisId, sha256, size, path }` 供 AI 继续执行/隔离

### 安全

- 路径必须 `fs.realpath` 后为常规文件；拒绝目录、设备文件
- 大小超限 → 400 `file_too_large`，不上传
- 变更接口 token 规则：`POST /scan-file` 为检测 POST，**不**改策略，允许调用；仍建议带 token（文档说明）
- 不自动执行/打开文件

### MCP

- `scan_downloaded_file({ path, fileName? })` → FileGateResult + scan meta
- Agent Guard 文档增加：下载后调用本工具；block 则隔离

## [S3] Out of Scope

- 多引擎商业 API
- 自动移动到隔离区（仅返回 decision）
- 超大文件分片上传（VT 免费档限制）

## Tasks

- [ ] T1: Spec
- [ ] T2: scan service + HTTP + MCP (covers: S2)
- [ ] T3: 测试 + UI/协议文案 (covers: S2)
- [ ] T4: Verify + review + merge (covers: S2)
