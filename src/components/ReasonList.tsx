import React from "react";
import type { Reason } from "../lib/api";

export function ReasonList({ reasons }: { reasons: Reason[] }) {
  if (!reasons || reasons.length === 0) return null;

  return (
    <div className="reasons">
      {reasons.map((r, i) => (
        <div className="reason" key={`${r.code}-${i}`}>
          <span className={`sev ${r.severity}`}>{r.severity}</span>
          <span className="reason-code mono">{r.code}</span>
          <span className="reason-msg">{r.message}</span>
        </div>
      ))}
    </div>
  );
}
