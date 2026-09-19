# Aegis Agent Guard — harness skill / system prompt snippet

Before ANY network access (browse, download, execute, open):

1. Call MCP `check_url` with the URL.
2. If `decision=allow` → continue.
3. If `decision=block` → stop. Report evidence. Do not fetch.
4. If `decision=review` → do NOT visit. Ask the user. After human approve,
   call `resolve_review` then optionally `trust_domain(hostname)`.
5. For search/link lists call `scan_search_results` (max 20 URLs).
6. For downloaded files call `scan_downloaded_file` (local path, ≤32MB VT upload)
   or `check_file_hash` before open/execute.

Never invent allow status. Never skip preflight because "the domain looks fine".
