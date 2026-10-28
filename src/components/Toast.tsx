import React from "react";
import { IconCheckCircle, IconAlertTriangle, IconX } from "./Icons";

export interface ToastMessage {
  id: string;
  type: "info" | "success" | "error";
  text: string;
}

interface ToastProps {
  toasts: ToastMessage[];
  onDismiss: (id: string) => void;
}

export function Toast({ toasts, onDismiss }: ToastProps) {
  if (toasts.length === 0) return null;

  return (
    <div className="toast-container">
      {toasts.map((t) => (
        <div key={t.id} className={`toast-item ${t.type}`}>
          <span className="toast-icon">
            {t.type === "success" && <IconCheckCircle size={15} />}
            {t.type === "error" && <IconAlertTriangle size={15} />}
            {t.type === "info" && <IconCheckCircle size={15} />}
          </span>
          <span className="toast-text">{t.text}</span>
          <button
            className="toast-close"
            onClick={() => onDismiss(t.id)}
            title="Dismiss"
          >
            <IconX size={12} />
          </button>
        </div>
      ))}
    </div>
  );
}
