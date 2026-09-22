---
feature: cross-platform
status: delivered
updated: 2026-09-19
branch: feat/cross-platform
commits: 82986b9..23c87ed
---

# 三端兼容（Windows / macOS / Linux）

## Report

**What was built** — Windows / macOS / Linux 三端兼容：核心门禁、MCP/HTTP、上传扫描与取证在三端一致。沙箱按平台选择 `seatbelt`（macOS）/ `bwrap`（Linux，无网络）/ `restricted`（Win 或缺 bwrap：隔离目录+过滤环境，`degraded` 明示）。Electron：`vibrancy` 仅 macOS；`electron-builder` 增加 `pack:win` / `pack:linux` / `pack:all`（NSIS、AppImage、deb）。

**Verification** — typecheck PASS；npm test 56/56；本机 smoke `mode=seatbelt platform=darwin`；打包脚本已挂到 package.json（Windows/Linux 需在对应系统执行）。

**Journey log** —
1. 三端不能写死 unix 路径与 Seatbelt；用 `detectSandboxBackend()` 分支。
2. 无内核隔离时必须 `degraded=true`，避免假安全。
3. 打包用 electron-builder 多 target；签名/公证仍按平台单独配置。


## [S1] Problem

Aegis 主要在 macOS 验证；沙箱依赖 `sandbox-exec`，打包仅 mac。需 **Windows / macOS / Linux** 三端：核心门禁与 MCP/HTTP 一致可用，沙箱按平台降级策略明确，Electron 可出三端包。

## [S2] Design

### 平台矩阵

| 能力 | macOS | Linux | Windows |
|------|-------|-------|---------|
| 门禁 / VT / 情报 / MCP / HTTP | ✓ | ✓ | ✓ |
| 沙箱 | Seatbelt `sandbox-exec` | `bwrap`（优先）否则受限 env | 受限 env + 临时目录（无内核隔离时 `degraded`） |
| 桌面壳 | Electron .app/.dmg | .AppImage / deb | NSIS .exe |
| 悬浮窗 | ✓ | ✓ | ✓（无 vibrancy） |
| 提示音 | WebAudio | ✓ | ✓ |

### 沙箱适配（`sandbox.ts`）

- `detectSandboxBackend()`: `seatbelt` | `bwrap` | `restricted`
- Linux `bwrap`: `--unshare-net --unshare-all --die-with-parent --ro-bind /usr /usr --bind sandboxRoot sandboxRoot …`
- Windows/`restricted`: 清理环境变量、cwd=沙箱目录、argv spawn；**degraded=true** 并在结果中说明
- `runInSandbox` / `extractInSandbox` 返回 `mode` 与 `platform`

### Electron

- `main.cjs`：`process.platform` 分支路径分隔符；`window-all-closed` 非 mac 才 quit（已有）；去掉 mac-only `vibrancy` 在非 darwin
- `electron-builder.yml`：`win` + `linux` + `mac` targets；`asarUnpack` 公共

### 测试

- 单测不绑死 seatbelt：断言 `mode ∈ {seatbelt,bwrap,restricted}` 且 `platform` 正确
- Windows CI 可跑 restricted 路径

## [S3] Out of Scope

- Windows Sandbox / Hyper-V 隔离
- 代码签名与自动更新通道
- Android / iOS

## Tasks

- [x] T1: Spec
- [x] T2: sandbox backends + tests (covers: S2)
- [x] T3: electron-builder 三端 + electron 主进程兼容 (covers: S2)
- [x] T4: Verify + merge (covers: S2)
