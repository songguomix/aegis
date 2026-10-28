import React from "react";
import type { GateResult } from "../lib/api";

function SourceRow({
  name,
  status,
  detail,
  level,
}: {
  name: string;
  status: string;
  detail?: string;
  level: "ok" | "warn" | "bad" | "muted";
}) {
  return (
    <div className={`source-row ${level}`}>
      <span className="source-name">{name}</span>
      <span className="source-status">{status}</span>
      {detail ? <span className="source-detail" title={detail}>{detail}</span> : null}
    </div>
  );
}

export function DataSources({ result }: { result: GateResult }) {
  const intel = result.threatIntel;
  const vt = result.virusTotal;
  const auth = result.authority;

  const vtLevel: "ok" | "warn" | "bad" | "muted" =
    vt.status === "malicious"
      ? "bad"
      : vt.status === "suspicious"
        ? "warn"
        : vt.status === "clean"
          ? "ok"
          : "muted";

  return (
    <div className="sources">
      <div className="panel-head" style={{ marginBottom: 0 }}>
        <h3>Data Sources & Threat Feeds</h3>
      </div>
      <SourceRow
        name="Official registry"
        status={auth.official ? auth.brand ?? "match" : "no match"}
        detail={auth.subject ?? auth.category ?? undefined}
        level={auth.official ? "ok" : "muted"}
      />
      <SourceRow
        name="Lookalike"
        status={auth.lookalikeOf ? "suspicious" : "ok"}
        detail={auth.lookalikeOf ? `→ ${auth.lookalikeOf}` : undefined}
        level={auth.lookalikeOf ? "bad" : "ok"}
      />
      <SourceRow
        name="RDAP"
        status={auth.rdap.status}
        detail={auth.rdap.organization || auth.rdap.registrant || undefined}
        level={auth.rdap.status === "ok" ? "ok" : "muted"}
      />
      <SourceRow
        name="VirusTotal"
        status={vt.status}
        detail={`mal ${vt.malicious} · sus ${vt.suspicious} · harm ${vt.harmless}${vt.cached ? " · cache" : ""}`}
        level={vtLevel}
      />
      {(intel?.sources ?? []).map((s) => (
        <SourceRow
          key={s.source}
          name={s.source}
          status={s.listed ? "LISTED" : "clear"}
          detail={s.detail}
          level={
            s.listed
              ? "bad"
              : String(s.detail ?? "").includes("fail") || String(s.detail ?? "").startsWith("http_")
                ? "muted"
                : "ok"
          }
        />
      ))}
      {intel && (
        <SourceRow
          name="Intel overall"
          status={intel.status}
          detail={
            intel.listedBy.length
              ? intel.listedBy.join(", ")
              : intel.status === "unknown"
                ? "partial feeds"
                : undefined
          }
          level={
            intel.status === "listed"
              ? "bad"
              : intel.status === "clean"
                ? "ok"
                : intel.status === "unknown"
                  ? "warn"
                  : "muted"
          }
        />
      )}
    </div>
  );
}
