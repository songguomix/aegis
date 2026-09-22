---
feature: analyze-installer
status: delivered
updated: 2026-09-19
branch: feat/analyze-installer
commits: 4a178b0..43693c5
---

# 有问题时让 AI 分析安装包

## Report

**What was built** — 扫描结果为 review/block 时，MCP `analyze_installer` 与 `POST /api/v1/analyze-installer` 对本地安装包做**只读静态取证**（哈希、类型魔数、熵、嵌入 URL/IP、可疑字符串、压缩包成员、riskFlags），并生成 `aiBrief` 分析提纲回传 AI，由 Agent 总结风险并建议用户放行/隔离/删除。不执行文件。

**Verification** — typecheck PASS；npm test 51/51；HTTP/MCP 实测返回 pe-exe、riskFlags、aiBrief。

**Journey log** —
1. 疑似安装包优先静态线索（类型/字符串/熵），避免沙箱复杂度。
2. `aiBrief` 明确分析任务列表，便于 LLM 输出可执行建议。
3. zip 本地头扫描即可列成员名，无需完整解压。


## [S1] Problem

小文件上传 VT 后若为 `review` / `block`，Agent 只有分数与引擎计数，缺少**安装包/文件本体**的静态线索，难以向用户解释或做处置建议。需要在可疑时对本地安装包做取证摘要，回传给 AI 继续分析。

## [S2] Design

### MCP `analyze_installer({ path })`

对路径做只读静态分析，**不执行**文件：

1. 路径/类型/大小/SHA256/SHA1/MD5
2. 文件类型嗅探（扩展名 + 魔数）：dmg/pkg/mpkg/msi/exe/dll/zip/jar/apk/deb/appimage/…
3. 签名线索（macOS codesign 仅探测字符串/结构；PE 版本资源若易得则跳过）
4. 字符串启发式：可疑 URL/IP、`curl|wget|bash -c`、加密勒索词、`LaunchAgent`、`sudo`、隐私路径
5. 压缩包成员列表（zip/jar/apk）条数与危险成员名（.js/.vbs/.exe/.sh）
6. 熵值（高熵 → 加壳/加密嫌疑）
7. 汇总 `riskFlags` + `aiBrief`（给 Agent 的分析提纲）

### HTTP `POST /api/v1/analyze-installer` `{ path }`

同 MCP 输出；token 规则同 scan-file（检测类 POST）。

### 协议

Agent Guard：`scan_*` 得 review/block 后调用 `analyze_installer`，把 `aiBrief` + scan 结果作为分析上下文，再建议用户隔离/删除/放弃安装。

## [S3] Out of Scope

- 反病毒引擎仿真 / 沙箱执行
- 二进制反汇编与签名密码学校验
- UI 深度取证编辑器

## Tasks

- [x] T1: Spec
- [x] T2: installerProbe 服务 + HTTP/MCP (covers: S2)
- [x] T3: 测试 + Agent Guard 文案 (covers: S2)
- [x] T4: Verify + merge (covers: S2)
