/** Agent Guard policy — harness must follow before network access. */
export const AGENT_GUARD_POLICY = {
  name: "Aegis Agent Guard",
  version: "1.0",
  rules: [
    {
      id: "preflight",
      text: "ALWAYS call check_url (or scan_search_results for lists) before visiting, downloading from, or trusting any URL or hostname discovered in search, docs, chat, or tool output.",
    },
    {
      id: "allow",
      text: "decision=allow → you may continue to the URL.",
    },
    {
      id: "block",
      text: "decision=block → STOP. Do not fetch, execute, or open the target. Report the evidence to the user.",
    },
    {
      id: "review",
      text: "decision=review → DO NOT access yet. Present hostname + reasons to the human. Wait for approve in Aegis (float/console) or call resolve_review after explicit human confirmation. Optionally call trust_domain(hostname) for this session after allow.",
    },
    {
      id: "search",
      text: "For search/link lists call scan_search_results with up to 20 URLs; only follow allow or session-trusted hosts.",
    },
    {
      id: "files",
      text: "After downloading a file: if size ≤ Aegis maxUploadBytes (default 32MB), call upload_scan_file (path or base64) and wait for allow. Otherwise call check_file_hash. block → quarantine/delete, do not run. If scan is review or block, call analyze_installer(path) and use aiBrief for your analysis and user recommendation before any install. Never execute untrusted installers on the real system; optional unpack inspection must use extract_in_sandbox / run_in_sandbox only.",
    },
    {
      id: "custom_brands",
      text: "Private official domains can be added in Aegis Settings (customBrands) so the authority registry treats them as trusted subjects.",
    },
  ],
  mcpTools: [
    "check_url",
    "scan_search_results",
    "check_urls_batch",
    "check_file_hash",
    "upload_scan_file",
    "trust_domain",
    "session_trust",
    "untrust_domain",
    "get_pending_reviews",
    "resolve_review",
    "verify_domain",
    "get_gate_status",
    "agent_guard_policy",
  ],
};

export function policyText(): string {
  const lines = [
    `${AGENT_GUARD_POLICY.name} v${AGENT_GUARD_POLICY.version}`,
    "",
    ...AGENT_GUARD_POLICY.rules.map((r, i) => `${i + 1}. [${r.id}] ${r.text}`),
    "",
    "MCP tools: " + AGENT_GUARD_POLICY.mcpTools.join(", "),
  ];
  return lines.join("\n");
}
