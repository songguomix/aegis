---
feature: aegis-mvp
status: delivered
updated: 2026-09-16
branch: feat/aegis-mvp
commits: 5d06de1..3db4557
---

# Aegis MVP — AI Agent Network Security Gateway

## Report

**What was built** — Aegis is a local AI-agent network security gateway. Before an agent visits a URL it runs a tri-state gate (`allow` / `review` / `block`) over an embedded official-domain authority registry (brand + subject), lookalike/typosquat/homograph detection, optional RDAP subject checks, and VirusTotal reputation (API key optional; degrades to authority-only). Integrations are HTTP (`POST /api/v1/check`) and MCP (`check_url`, `verify_domain`, `get_gate_status`). An Electron + React console with liquid-glass UI provides Dashboard, Live Check, History, and Settings (VT key, policy mode, allow/deny lists, EN/中文). Localhost trust boundary: bind `127.0.0.1`, origin-allowlist CORS (never `*`), token-gated mutations without Origin, production UI served same-origin from Express.

**Verification** — `npm test` 19/19 PASS; `npm run typecheck` PASS; `npm run build` PASS (`dist/` + `dist-server/data`); live HTTP smoke: github.com→allow, guthub.com→block (typosquat), unknown→review; MCP stdio tools list + `check_url` PASS; compiled `node dist-server/index.js` boots, serves UI 200, registry lookup works; security checks: foreign Origin PUT→403, no-token mutate→401, local Origin→200, evil preflight→403. First review REQUEST_CHANGES (CORS `*`, missing dist registry); both criticals fixed and re-review APPROVE.

**Journey log** —
1. Greenfield empty folder → in-place feature branch (no nested worktree) so Desktop path *is* the product.
2. Electron binary skipped at install (`ELECTRON_SKIP_BINARY_DOWNLOAD=1`) for speed; shell code is wired, binary install left to user (`npx electron` / normal install).
3. Review caught open CORS on a loopback security API — treat localhost browsers as attackers; origin allowlist + mutating token.
4. `tsc` does not copy JSON assets; build now has `scripts/copy-server-assets.mjs`. Path with spaces requires `fileURLToPath`, not `URL.pathname`.
5. VT rate limit was capped at 2s (ineffective); now full 16s interval + 60s 429 backoff + disk cache under `.aegis/vt-cache.json`.

## [S1] Problem

AI agents routinely fetch URLs discovered from search, docs, or tool output. Attackers host lookalike domains, typosquats, and malware download pages that agents treat as authoritative. A single wrong download or credential paste can cause real loss. Agents lack a built-in gate that verifies **domain authenticity** (who is the subject / registrant / brand owner) and **reputation** (VirusTotal) before allowing the agent to continue.

## [S2] Design

### Product shape

**Aegis** is a local desktop security gateway for AI Agent Harnesses:

| Layer | Responsibility |
|-------|----------------|
| Core Engine (Node/TS) | Domain authority, VirusTotal, tri-state gate, audit log |
| HTTP API | `POST /api/v1/check` and config/history for any harness |
| MCP Server | Tools: `check_url`, `verify_domain`, `get_gate_status` |
| Electron shell | Hosts core + opens console |
| React console | Liquid-glass UI: Dashboard, Live Check, History, Settings |

Workspace override: greenfield product folder is the delivery root; work proceeds on feature branch `feat/aegis-mvp` in-place (no nested worktree) so the user's project directory *is* the product.

### Decision model (tri-state)

```
BLOCK  — VT malicious/suspicious-high, critical-brand lookalike, explicit denylist
ALLOW  — official/trusted subject match AND (VT clean OR VT unavailable + trusted)
REVIEW — everything else: unknown domain, new/weak authority, VT suspicious,
         RDAP subject mismatch, degraded VT mode for non-trusted hosts
```

Default posture is fail-closed on clear danger, fail-watch on uncertainty.

### Domain Authority Registry

1. **Embedded official brand map** (`server/data/official-domains.json`): hostname → { brand, subject, category } for major software/cloud/code hosts (GitHub, Google, Microsoft, Apple, OpenAI, Anthropic, npm, PyPI, Docker Hub, etc.).
2. **RDAP subject lookup** (best-effort, cached, optional network): registrant name/org for comparison.
3. **Lookalike engine**: punycode/homograph flags, mixed-script, Levenshtein distance vs official brands, suspicious TLD heuristics.
4. **Operator allow/deny lists** persisted in local config.

### VirusTotal

- Config: API key in Settings; free-tier friendly rate limit (~4/min enforced) + disk/memory cache (TTL 6h).
- Domain report → `last_analysis_stats` + categories + reputation.
- No key or network fail → `vtStatus: "degraded"`; gate still runs authority checks; non-trusted domains stay REVIEW.
- 429 → 60s backoff, subsequent lookups degrade until backoff expires.
- MCP `verify_domain` skips VT (`skipVt`) so authority-only checks do not burn quota.

### Local trust boundary (post-review hardening)

- HTTP server binds `127.0.0.1` only.
- CORS never uses `*`. Origins are accepted only if they match `http(s)://(127.0.0.1|localhost)(:port)?`.
- Foreign browser origins: preflight and mutating requests → 403.
- Mutating methods (`PUT`/`PATCH`/`DELETE`) without `Origin` require `X-Aegis-Token` (file `.aegis/token`, mode 0600).
- Production console is served from the same Express process (`dist/`), so Electron loads `http://127.0.0.1:<port>/` (same-origin).
- Bound port is written to `.aegis/port` for Electron discovery (7832–7842 fallback).

### Contracts

#### HTTP `POST /api/v1/check`

```json
// request
{ "url": "https://github.com/example/repo", "context": "optional agent note" }

// response
{
  "id": "chk_...",
  "url": "https://github.com/example/repo",
  "hostname": "github.com",
  "decision": "allow" | "review" | "block",
  "score": 0-100,
  "reasons": [{ "code": "...", "severity": "info|warn|critical", "message": "..." }],
  "authority": {
    "official": true,
    "brand": "GitHub",
    "subject": "GitHub, Inc.",
    "rdap": { "status": "ok|skipped|error", "registrant": "..." },
    "lookalikeOf": null | "github.com",
    "punycode": false
  },
  "virusTotal": {
    "status": "clean|malicious|suspicious|unknown|degraded|error",
    "malicious": 0,
    "suspicious": 0,
    "harmless": 0,
    "cached": false
  },
  "checkedAt": "ISO-8601"
}
```

Invalid URL returns HTTP 200 with `decision: "block"` and reason `invalid_url` (schema-invalid JSON bodies still return HTTP 400).

#### MCP tools

- `check_url({ url })` → same gate result (stringified JSON for agents)
- `verify_domain({ domain })` → authority-only report (no VT force)
- `get_gate_status()` → engine health, VT mode, policy, counts

### Electron + Console UI

- Liquid glass: frosted translucent panels, layered depth, soft luminous accents.
- Palette: ink `#070b14`, surface glass `rgba(255,255,255,0.06)`, accent cyan `#5EEAD4`, violet `#A78BFA`; allow emerald, review amber, block rose.
- Type: Inter / system-ui; large display numerals for stats.
- Screens: **Dashboard** (recent decisions, counters), **Live Check** (URL input + evidence cards), **History**, **Settings** (VT key, policy mode, allow/deny lists, language EN/中文).
- Language: default English, toggle to Chinese in Settings.

### Error behavior

- Invalid URL → decision `block` with reason `invalid_url` (HTTP 200 body; not a transport error).
- VT 429 → backoff, mark degraded for that lookup, do not crash gate.
- RDAP timeout (3s) → skip, continue with static authority + lookalike only.
- Core port busy → try next port in 7832–7842 range; port file + Electron discovery.

## [S3] Out of Scope (MVP)

- Real TLS MITM proxy / transparent interception
- File/content download scanning (hash → VT)
- Cloud multi-tenant SaaS
- Signed auto-updates
- Browser extension packaging
- Paid threat intel beyond VirusTotal

## Tasks

- [x] T1: Workspace git init + feature branch + toolchain — acceptance: repo on `feat/aegis-mvp`, Node/npm available
- [x] T2: Spec document `docs/compose/spec/aegis-mvp.md` — acceptance: this file exists with settled contracts
- [x] T3: Core engine (authority registry, lookalike, VT client with cache/degrade, tri-state gate) — acceptance: unit tests pass for allow/review/block paths offline
- [x] T4: HTTP API + MCP server exposing `check_url` — acceptance: `POST /api/v1/check` returns contract; MCP tools registered
- [x] T5: Electron shell + liquid-glass React console — acceptance: UI renders Dashboard/Live Check/History/Settings; check from UI hits API (Vite build + same-origin serve verified; Electron binary not downloaded in this environment)
- [x] T6: Verification — acceptance: `npm test` and `npm run build` succeed; server boots
- [x] T7: Review + finalize spec — acceptance: independent review passes; Report filled; status delivered
- [x] T8: Post-review critical fixes (CORS/token + dist registry copy + path spaces) — acceptance: re-review APPROVE
