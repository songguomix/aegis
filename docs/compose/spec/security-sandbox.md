---
feature: security-sandbox
status: designed
updated: 2026-09-19
branch: feat/security-sandbox
commits: 59ee348..pending
---

# 严格信息安全沙箱

## Report

## [S1] Problem

AI 分析可疑安装包/解压内容时若直接解压或运行，会污染本机（写用户目录、外联、执行 payload）。需要**默认拒绝**的本地沙箱：仅允许写隔离工作区，禁止网络与敏感目录访问，把取证输出限制在可控范围。

## [S2] Design

### 沙箱运行时（macOS 优先）

- `server/services/sandbox.ts`
- 创建 `AEGIS_SANDBOX_ROOT`（默认 `os.tmpdir()/aegis-sandbox-<id>` 或 userData 下）
- 生成 Seatbelt 配置 `deny(default)`；允许读 `/usr /bin /sbin /lib /System /Library /private/var/db` 等系统只读；**允许写**仅 `sandbox root` 与 `/tmp/aegis-sandbox-*`；**禁止**读 `~/.ssh`、`~/.aws`、Keychain、`~/.config`；**禁止**网络（`deny network*`）
- 执行：`sandbox-exec -f profile -- command`（超时 kill）；无 `sandbox-exec` 时降级：仅在空目录 + 清理环境变量 + 无 shell 注入 argv 执行，并标记 `degraded: true`
- 后端判定：`detectSandboxBackend()` → `seatbelt`(macOS) | `bwrap`(Linux) | `restricted`(其余，含 Windows)

### 隔离强度声明（`isolated` 字段）

`runInSandbox` / `extractInSandbox` 的返回值带 `isolated: boolean`：

- `isolated: true` — seatbelt / bwrap 生效：**网络拒绝**、**写仅沙箱根**、**敏感目录禁读**均成立
- `isolated: false` — `restricted` 后端（Windows / 无 bwrap）

### 无内核隔离时：拒绝执行，而不是"假沙箱"

`restricted` 后端下 **`runInSandbox` 默认直接拒绝**（不 spawn、不产生任何副作用）：

```
ok: false, error: "no_os_sandbox", isolated: false, degraded: true
reason: <拒绝原因 + 可执行的替代路径>
```

`reason` 是写给模型看的，包含：为何拒绝（将以用户完整权限运行，网络 / `~/.ssh` / `~/.aws` / 越界写入都不会被拦截）、**不要用更弱的命令重试**、以及四条不执行任何东西的替代路径：

1. `analyze_installer(path)` — 纯静态分析（哈希、类型、熵、内嵌 URL/字符串、压缩包成员、风险标记）
2. `extract_in_sandbox(path)` — 用 Node 解压到临时目录（防路径穿越，不执行）
3. `check_file_hash(hash)` / `upload_scan_file(path)` — VirusTotal 判定
4. 请用户人工检查并回报

MCP 工具以 `isError: true` 返回该 payload，HTTP `POST /sandbox/run` 返回 `501`。

### 目标文件暂存（`target`）

沙箱按设计**读不到工作目录**（只有沙箱根与少量系统路径可读）。因此检查目标必须由 Aegis 拷进沙箱：

- `run_in_sandbox { argv, target: "/abs/path/artifact" }` → Aegis 把 `target` 复制到沙箱根（`0600`），并把 argv 中指向它的参数改写为副本路径
- 副本路径在沙箱内可读（seatbelt profile 允许沙箱根），因此 `file` / `strings` / `shasum` / `codesign` 等只读工具可正常取证
- 不传 `target` 时，工具只能看到沙箱根内的相对路径

> seatbelt profile 必须使用**解析后**的沙箱路径（`realpath`）：macOS 的 `os.tmpdir()` 是 `/var/folders/...`，真实路径是 `/private/var/folders/...`，用未解析路径会让沙箱连自己的目录都读不了。

### 受限模式的白名单通道（`allowUnisolated`，显式 opt-in）

`allowUnisolated: true` 时允许在**无内核隔离**下运行，但必须同时满足：

1. 可执行文件在受信任的只读检查工具白名单内（`file` / `ls` / `stat` / `strings` / `xxd` / `od` / `wc` / `head` / `tail` / `shasum` / `sha256sum` / `md5` / `cksum` / `cmp` / `diff` / `grep` / `codesign` / `otool` / `plutil` / `nm` / `objdump` / `readelf` / `pdfinfo` / `findstr`）—— 能执行任意代码的一律排除（`sh` / `python` / `node` / `perl` / `env` / `curl` / `xargs` …）
2. 工具从固定目录解析（`/usr/bin`、`/bin`、`/usr/sbin`、`/sbin`），不走调用方 PATH
3. 所有路径参数必须落在沙箱根内：`~` 展开、`..` 跨目录、沙箱外的绝对路径一律拒绝

结果仍带 `isolated: false` + `warning`，模型不会误以为有隔离。违反任一条 → `error: unisolated_not_allowed` 并给出原因。

> 解压路径（`extract_in_sandbox`）不受此限制：Node 解压不执行任何东西，在所有平台可用；系统 `unzip` 仅在沙箱内作兜底，不再在宿主机裸跑。

### API / MCP

| 接口 | 作用 |
|------|------|
| `POST /api/v1/sandbox/run` | `{ argv[] }` 或 `{ shell? }`（默认禁止任意 shell，仅 argv）在沙箱跑，默认超时 5s |
| `POST /api/v1/sandbox/extract` | 解压 zip/tar 到沙箱（zip **用 Node 解压**：store/deflate，仅写沙箱根，拒绝路径穿越与符号链接；非 zip 才回落 `unzip` 在沙箱内） |
| MCP `run_in_sandbox` | 同 run |
| MCP `extract_in_sandbox` | 同 extract + 成员列表/风险名 |
| MCP `analyze_installer` | 可选增强：对 zip 自动 extract_in_sandbox 再摘要（保持只读） |

### 安全约束（按后端条件化）

1. 不继承 MCP 无关环境中的密钥（过滤 `TOKEN|KEY|SECRET|PASSWORD`）— **全部后端成立**
2. 工作目录固定为 sandbox root；命令 argv 数组传递，**不经 `/bin/sh -c`** — **全部后端成立**
3. 网络拒绝；写操作仅 sandbox root — **仅 `isolated: true`（seatbelt/bwrap）成立**；`restricted` 下不成立且结果显式告警
4. 输出 stdout/stderr 限长（默认 64KB）— 全部后端成立
5. 结束后可选清理 sandbox root — 全部后端成立
6. zip 解压：路径穿越（`..`、绝对路径、盘符）、符号链接条目一律拒绝；总解压体积与条目数有上限（防 zip bomb）

## [S3] Out of Scope

- 虚拟机 / Hypervisor 隔离
- Windows AppContainer、Linux user namespace 全量封装
- 对 GUI 安装器的仿真安装

## Tasks

- [ ] T1: Spec
- [ ] T2: sandbox.ts + profile + run/extract (covers: S2)
- [ ] T3: HTTP + MCP + 测试 (covers: S2)
- [ ] T4: Verify + merge (covers: S2)
