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

### API / MCP

| 接口 | 作用 |
|------|------|
| `POST /api/v1/sandbox/run` | `{ argv[] }` 或 `{ shell? }`（默认禁止任意 shell，仅 argv）在沙箱跑，默认超时 5s |
| `POST /api/v1/sandbox/extract` | 解压 zip/tar 到沙箱（zip 用 Node 解压仅 store/无路径穿越；失败则 `unzip` 在沙箱内） |
| MCP `run_in_sandbox` | 同 run |
| MCP `extract_in_sandbox` | 同 extract + 成员列表/风险名 |
| MCP `analyze_installer` | 可选增强：对 zip 自动 extract_in_sandbox 再摘要（保持只读） |

### 安全约束（硬保证）

1. 不继承 MCP 无关环境中的密钥（过滤 `TOKEN|KEY|SECRET|PASSWORD`）
2. 工作目录固定为 sandbox root；命令 argv 数组传递，**不经 `/bin/sh -c`**
3. 网络拒绝；写操作仅 sandbox root
4. 输出 stdout/stderr 限长（默认 64KB）
5. 结束后可选清理 sandbox root

## [S3] Out of Scope

- 虚拟机 / Hypervisor 隔离
- Windows AppContainer、Linux user namespace 全量封装
- 对 GUI 安装器的仿真安装

## Tasks

- [ ] T1: Spec
- [ ] T2: sandbox.ts + profile + run/extract (covers: S2)
- [ ] T3: HTTP + MCP + 测试 (covers: S2)
- [ ] T4: Verify + merge (covers: S2)
