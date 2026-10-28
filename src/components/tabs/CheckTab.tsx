import React, { useState, useRef } from "react";
import {
  api,
  type BatchResult,
  type FileGateResult,
  type GateResult,
} from "../../lib/api";
import { t, type Lang } from "../../lib/i18n";
import { DecisionPill } from "../DecisionPill";
import { DataSources } from "../DataSources";
import { ReasonList } from "../ReasonList";
import {
  IconSearch,
  IconFile,
  IconUpload,
  IconCheck,
  IconExternalLink,
} from "../Icons";

export type CheckMode = "url" | "file" | "batch";

interface CheckTabProps {
  lang: Lang;
  maxUploadBytes: number;
  onRefresh: () => Promise<void>;
  onToast: (msg: string) => void;
  onError: (err: string) => void;
}

export function CheckTab({
  lang,
  maxUploadBytes,
  onRefresh,
  onToast,
  onError,
}: CheckTabProps) {
  const L = (k: Parameters<typeof t>[1]) => t(lang, k);

  const [mode, setMode] = useState<CheckMode>("url");
  const [url, setUrl] = useState("");
  const [context, setContext] = useState("");
  const [hash, setHash] = useState("");
  const [fileName, setFileName] = useState("");
  const [batchText, setBatchText] = useState("");

  // File drag & drop state
  const [droppedFile, setDroppedFile] = useState<File | null>(null);
  const [fileHashCalculating, setFileHashCalculating] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Results
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<GateResult | null>(null);
  const [fileResult, setFileResult] = useState<FileGateResult | null>(null);
  const [batchResult, setBatchResult] = useState<BatchResult | null>(null);

  // Calculate SHA256 of selected file
  async function processSelectedFile(file: File) {
    setDroppedFile(file);
    setFileName(file.name);
    setFileHashCalculating(true);
    try {
      const buffer = await file.arrayBuffer();
      const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
      setHash(hashHex);
      onToast(`Computed SHA-256: ${hashHex.slice(0, 16)}…`);
    } catch (e) {
      onError(`Failed to hash file: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setFileHashCalculating(false);
    }
  }

  function handleDrop(e: React.DragEvent) {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      void processSelectedFile(e.dataTransfer.files[0]);
    }
  }

  // Run Check
  async function runCheck() {
    setLoading(true);
    try {
      if (mode === "file") {
        if (!hash.trim()) return;
        const r = await api.checkFile(
          hash.trim(),
          fileName.trim() || undefined,
          context.trim() || undefined,
        );
        setFileResult(r);
        setResult(null);
        setBatchResult(null);
        onToast(L("fileChecked"));
      } else if (mode === "batch") {
        const urls = batchText
          .split(/[\n\s,]+/)
          .map((s) => s.trim())
          .filter(Boolean)
          .slice(0, 20);
        if (!urls.length) return;
        const r = await api.checkBatch(urls, context.trim() || undefined);
        setBatchResult(r);
        setResult(null);
        setFileResult(null);
        onToast(`${L("batchDone")} · ${r.total}`);
      } else {
        if (!url.trim()) return;
        const r = await api.check(url.trim(), context.trim() || undefined);
        setResult(r);
        setFileResult(null);
        setBatchResult(null);
      }
      await onRefresh();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  // Direct File Upload Scan
  async function runDirectUploadScan() {
    if (!droppedFile) return;
    if (droppedFile.size > maxUploadBytes) {
      onError(`${L("fileTooLarge")} (${(maxUploadBytes / (1024 * 1024)).toFixed(0)} MB)`);
      return;
    }
    setLoading(true);
    try {
      const buffer = await droppedFile.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      let binary = "";
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      const base64 = btoa(binary);

      const res = await api.uploadScan({
        filename: droppedFile.name,
        base64,
        context: context.trim() || "web-upload",
      });

      setResult(res);
      setFileResult(null);
      setBatchResult(null);
      onToast(`Uploaded & scanned: ${droppedFile.name}`);
      await onRefresh();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  async function resolvePending(
    id: string,
    decision: "allow" | "block",
    alwaysAllow = false,
  ) {
    try {
      await api.resolveReview(id, decision, {
        alwaysAllow,
        by: "user",
        sessionTrust: decision === "allow",
      });
      onToast(decision === "allow" ? "Allowed" : "Blocked");
      await onRefresh();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  }

  const canRun = (): boolean => {
    if (loading || fileHashCalculating) return false;
    if (mode === "file") return Boolean(hash.trim());
    if (mode === "batch") return Boolean(batchText.trim());
    return Boolean(url.trim());
  };

  return (
    <div className="tab-container">
      <div className="page-header">
        <div>
          <h2>{L("checkTitle")}</h2>
          <p className="sub">{L("checkSub")}</p>
        </div>
      </div>

      <div className="stack">
        <section className="panel check-hero">
          {/* Mode Selector */}
          <div className="seg" role="tablist">
            <button
              type="button"
              className={`seg-item ${mode === "url" ? "active" : ""}`}
              onClick={() => setMode("url")}
            >
              <IconSearch size={14} style={{ marginRight: 6 }} />
              {L("modeUrl")}
            </button>
            <button
              type="button"
              className={`seg-item ${mode === "file" ? "active" : ""}`}
              onClick={() => setMode("file")}
            >
              <IconFile size={14} style={{ marginRight: 6 }} />
              {L("modeFile")}
            </button>
            <button
              type="button"
              className={`seg-item ${mode === "batch" ? "active" : ""}`}
              onClick={() => setMode("batch")}
            >
              <IconUpload size={14} style={{ marginRight: 6 }} />
              {L("modeBatch")}
            </button>
          </div>

          {/* URL Mode */}
          {mode === "url" && (
            <div className="check-row" style={{ marginTop: 14 }}>
              <div className="field">
                <input
                  className="input"
                  placeholder={L("urlPlaceholder")}
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && canRun() && runCheck()}
                  autoFocus
                />
              </div>
              <button
                className="btn btn-primary"
                onClick={runCheck}
                disabled={!canRun()}
              >
                {loading ? L("checking") : L("runCheck")}
              </button>
            </div>
          )}

          {/* File Mode (with Drag & Drop + Direct Scan) */}
          {mode === "file" && (
            <div className="file-mode-container" style={{ marginTop: 14 }}>
              <div
                className={`dropzone ${isDragOver ? "dragover" : ""} ${droppedFile ? "has-file" : ""}`}
                onDragOver={(e) => {
                  e.preventDefault();
                  setIsDragOver(true);
                }}
                onDragLeave={() => setIsDragOver(false)}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
              >
                <input
                  type="file"
                  ref={fileInputRef}
                  style={{ display: "none" }}
                  onChange={(e) => {
                    if (e.target.files && e.target.files.length > 0) {
                      void processSelectedFile(e.target.files[0]);
                    }
                  }}
                />
                <IconFile size={28} className="dropzone-icon" />
                <div className="dropzone-title">
                  {droppedFile ? droppedFile.name : L("dropFileHere")}
                </div>
                <div className="dropzone-sub">
                  {droppedFile
                    ? `${(droppedFile.size / 1024).toFixed(1)} KB · ${droppedFile.type || "binary"}`
                    : L("dragOrClick")}
                </div>
              </div>

              {/* Hash and filename manual row */}
              <div className="check-row" style={{ marginTop: 12 }}>
                <div className="field">
                  <input
                    className="input mono"
                    placeholder={fileHashCalculating ? L("hashing") : L("hashPlaceholder")}
                    value={hash}
                    onChange={(e) => setHash(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && canRun() && runCheck()}
                  />
                </div>
                <div className="field" style={{ maxWidth: 220 }}>
                  <input
                    className="input"
                    placeholder={L("fileNamePlaceholder")}
                    value={fileName}
                    onChange={(e) => setFileName(e.target.value)}
                  />
                </div>
                <button
                  className="btn btn-primary"
                  onClick={runCheck}
                  disabled={!canRun()}
                >
                  {loading ? L("checking") : L("runCheck")}
                </button>
                {droppedFile && droppedFile.size <= maxUploadBytes && (
                  <button
                    className="btn btn-ghost"
                    onClick={runDirectUploadScan}
                    disabled={loading || fileHashCalculating}
                    title="Upload to VirusTotal for direct scan"
                  >
                    <IconUpload size={14} style={{ marginRight: 6 }} />
                    {L("directScanBtn")}
                  </button>
                )}
              </div>
            </div>
          )}

          {/* Batch Mode */}
          {mode === "batch" && (
            <div style={{ marginTop: 14 }}>
              <textarea
                className="input"
                style={{ minHeight: 120 }}
                placeholder={L("batchPlaceholder")}
                value={batchText}
                onChange={(e) => setBatchText(e.target.value)}
              />
              <div className="check-row" style={{ marginTop: 10 }}>
                <button
                  className="btn btn-primary"
                  onClick={runCheck}
                  disabled={!canRun()}
                >
                  {loading ? L("checking") : L("runCheck")}
                </button>
              </div>
            </div>
          )}

          {/* Context input */}
          <div className="field context" style={{ marginTop: 12 }}>
            <input
              className="input input-sm"
              placeholder={L("contextPlaceholder")}
              value={context}
              onChange={(e) => setContext(e.target.value)}
            />
          </div>
        </section>

        {/* File Result */}
        {fileResult && (
          <section className="panel result">
            <div className="result-head">
              <div>
                <div className="url mono">{fileResult.fileName || fileResult.hash}</div>
                <div className="sub">
                  {fileResult.hashType} · {fileResult.hash} · {new Date(fileResult.checkedAt).toLocaleString()}
                </div>
              </div>
              <div className="split">
                <span className="score">{fileResult.score}</span>
                <DecisionPill decision={fileResult.decision} />
              </div>
            </div>
            <div className="meta-grid cols-2">
              <div className="meta-item">
                <div className="k">{L("vt")}</div>
                <div className="v">
                  {fileResult.virusTotal.status} · mal {fileResult.virusTotal.malicious} ·
                  sus {fileResult.virusTotal.suspicious} · harm {fileResult.virusTotal.harmless}
                  {fileResult.virusTotal.cached ? " (cached)" : ""}
                </div>
              </div>
              <div className="meta-item">
                <div className="k">{L("decision")}</div>
                <div className="v font-semibold">{fileResult.decision.toUpperCase()}</div>
              </div>
            </div>
            <div className="panel-head" style={{ marginTop: 16 }}>
              <h3>{L("reasons")}</h3>
            </div>
            <ReasonList reasons={fileResult.reasons} />
          </section>
        )}

        {/* Batch Result */}
        {batchResult && (
          <section className="panel">
            <div className="panel-head">
              <h3>
                Batch Summary · {batchResult.total} checked (Allow: {batchResult.allow} · Review:{" "}
                {batchResult.review} · Block: {batchResult.block})
              </h3>
              <DecisionPill decision={batchResult.decision} />
            </div>
            <div className="list-scroll">
              <table className="table">
                <thead>
                  <tr>
                    <th>{L("decision")}</th>
                    <th>{L("hostname")}</th>
                    <th>{L("vt")}</th>
                    <th style={{ textAlign: "right" }}>{L("score")}</th>
                  </tr>
                </thead>
                <tbody>
                  {batchResult.results.map((item) => (
                    <tr key={item.id}>
                      <td>
                        <DecisionPill decision={item.decision} />
                      </td>
                      <td className="mono truncate-cell" title={item.hostname}>
                        {item.hostname}
                      </td>
                      <td>{item.virusTotal?.status ?? "—"}</td>
                      <td style={{ textAlign: "right" }}>
                        <span className="score-num">{item.score}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {/* URL Result */}
        {result && (
          <section className="panel result">
            <div className="result-head">
              <div>
                <div className="url">{result.url}</div>
                <div className="sub">
                  {result.hostname} · {new Date(result.checkedAt).toLocaleString()}
                </div>
              </div>
              <div className="split">
                <span className="score">{result.score}</span>
                <DecisionPill decision={result.decision} />
              </div>
            </div>

            <div className="result-body">
              <div className="meta-grid cols-2">
                <div className="meta-item">
                  <div className="k">{L("brand")}</div>
                  <div className="v">{result.authority.brand ?? "—"}</div>
                </div>
                <div className="meta-item">
                  <div className="k">{L("subject")}</div>
                  <div className="v">{result.authority.subject ?? "—"}</div>
                </div>
                <div className="meta-item">
                  <div className="k">{L("rdap")}</div>
                  <div className="v">
                    {result.authority.rdap.status}
                    {result.authority.rdap.organization
                      ? ` · ${result.authority.rdap.organization}`
                      : ""}
                  </div>
                </div>
                <div className="meta-item">
                  <div className="k">{L("lookalike")}</div>
                  <div className="v">{result.authority.lookalikeOf ?? "—"}</div>
                </div>
              </div>

              <DataSources result={result} />
            </div>

            <div className="panel-head" style={{ marginTop: 14 }}>
              <h3>{L("reasons")}</h3>
            </div>
            <ReasonList reasons={result.reasons} />

            {/* Pending review action bar */}
            {result.decision === "review" && result.reviewId && (
              <div className="ask-box">
                <div className="ask-title">{L("askUser")}</div>
                <p className="help" style={{ margin: "4px 0 10px" }}>
                  {L("askUserHelp")} · <code>{result.reviewId}</code>
                </p>
                <div className="pending-actions" style={{ flexDirection: "row" }}>
                  <button
                    className="btn btn-sm btn-allow"
                    onClick={() => resolvePending(result.reviewId!, "allow", true)}
                  >
                    <IconCheck size={13} style={{ marginRight: 4 }} />
                    {L("approve")} · {L("alwaysAllow")}
                  </button>
                  <button
                    className="btn btn-sm btn-ghost"
                    onClick={() => resolvePending(result.reviewId!, "allow", false)}
                  >
                    {L("approve")}
                  </button>
                  <button
                    className="btn btn-sm btn-ghost deny-btn"
                    onClick={() => resolvePending(result.reviewId!, "block", false)}
                  >
                    {L("deny")}
                  </button>
                </div>
              </div>
            )}
          </section>
        )}
      </div>
    </div>
  );
}
