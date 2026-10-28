import React from "react";
import type { Decision } from "../lib/api";
import { IconCheck, IconAlertTriangle, IconX } from "./Icons";

interface Props {
  decision: Decision | string;
  score?: number;
  className?: string;
}

export function DecisionPill({ decision, score, className = "" }: Props) {
  const norm = decision.toLowerCase() as Decision;

  return (
    <span className={`decision-pill ${norm} ${className}`}>
      <span className="pill-icon">
        {norm === "allow" && <IconCheck size={11} />}
        {norm === "review" && <IconAlertTriangle size={11} />}
        {norm === "block" && <IconX size={11} />}
      </span>
      <span className="pill-text">{norm}</span>
      {typeof score === "number" && (
        <span className="pill-score" title={`Score: ${score}`}>
          {score}
        </span>
      )}
    </span>
  );
}
