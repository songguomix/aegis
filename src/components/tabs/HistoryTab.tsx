import React, { useState, useMemo } from "react";
import type { GateResult } from "../../lib/api";
import { t, type Lang } from "../../lib/i18n";
import { DecisionPill } from "../DecisionPill";
import { DataSources } from "../DataSources";
import { ReasonList } from "../ReasonList";
import {
  IconSearch,
  IconDownload,
  IconTrash,
  IconX,
  IconFile,
} from "../Icons";

interface HistoryTabProps {
  lang: Lang;
  history: GateResult[];
  onExport: (format: "csv" | "json") => Promise<void>;
  onClearHistory: () => Promise<void>;
  selectedItem?: GateResult | null;
  onSelectItem?: (item: GateResult | null) => void;
}

type FilterKind = "all" | "allow" | "review" | "block" | "file";

export function HistoryTab({
  lang,
  history,
  onExport,
  onClearHistory,
  selectedItem: controlledSelected,
  onSelectItem,
}: HistoryTabProps) {
  const L = (k: Parameters<typeof t>[1]) => t(lang, k);

  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<FilterKind>("all");
  const [internalSelected, setInternalSelected] = useState<GateResult | null>(null);

  const selected = controlledSelected !== undefined ? controlledSelected : internalSelected;
  const setSelected = onSelectItem || setInternalSelected;

  const counts = useMemo(() => {
    return {
      all: history.length,
      allow: history.filter((h) => h.decision === "allow").length,
      review: history.filter((h) => h.decision === "review").length,
      block: history.filter((h) => h.decision === "block").length,
      file: history.filter((h) => h.kind === "file" || h.url?.startsWith("file:")).length,
    };
  }, [history]);

  const filtered = useMemo(() => {
    return history.filter((item) => {
      // Filter by kind
      if (filter === "allow" && item.decision !== "allow") return false;
      if (filter === "review" && item.decision !== "review") return false;
      if (filter === "block" && item.decision !== "block") return false;
      if (filter === "file" && item.kind !== "file" && !item.url?.startsWith("file:")) return false;

      // Filter by search text
      if (search.trim()) {
        const q = search.trim().toLowerCase();
        const host = (item.hostname || "").toLowerCase();
        const url = (item.url || "").toLowerCase();
        const brand = (item.authority?.brand || "").toLowerCase();
        return host.includes(q) || url.includes(q) || brand.includes(q);
      }
      return true;
    });
  }, [history, filter, search]);

  return (
    <div className="tab-container">
      <div className="page-header">
        <div>
          <h2>{L("history")}</h2>
          <p className="sub">
            {filtered.length} of {history.length} records shown
          </p>
        </div>
        <div className="actions">
          <button
            className="btn btn-ghost"
            onClick={() => void onExport("csv")}
            title="Export CSV"
          >
            <IconDownload size={13} style={{ marginRight: 5 }} />
            CSV
          </button>
          <button
            className="btn btn-ghost"
            onClick={() => void onExport("json")}
            title="Export JSON"
          >
            <IconDownload size={13} style={{ marginRight: 5 }} />
            JSON
          </button>
          <button
            className="btn btn-ghost deny-btn"
            onClick={() => {
              if (window.confirm("Clear all gateway history records?")) {
                void onClearHistory();
              }
            }}
            title={L("clearHistory")}
          >
            <IconTrash size={13} style={{ marginRight: 5 }} />
            {L("clearHistory")}
          </button>
        </div>
      </div>

      <div className="stack">
        {/* Controls: Filter Pills & Search */}
        <div className="history-controls">
          <div className="filter-pills">
            <button
              className={`pill-btn ${filter === "all" ? "active" : ""}`}
              onClick={() => setFilter("all")}
            >
              {L("filterAll")} <span className="pill-count">{counts.all}</span>
            </button>
            <button
              className={`pill-btn allow ${filter === "allow" ? "active" : ""}`}
              onClick={() => setFilter("allow")}
            >
              {L("filterAllow")} <span className="pill-count">{counts.allow}</span>
            </button>
            <button
              className={`pill-btn review ${filter === "review" ? "active" : ""}`}
              onClick={() => setFilter("review")}
            >
              {L("filterReview")} <span className="pill-count">{counts.review}</span>
            </button>
            <button
              className={`pill-btn block ${filter === "block" ? "active" : ""}`}
              onClick={() => setFilter("block")}
            >
              {L("filterBlock")} <span className="pill-count">{counts.block}</span>
            </button>
            <button
              className={`pill-btn ${filter === "file" ? "active" : ""}`}
              onClick={() => setFilter("file")}
            >
              <IconFile size={12} style={{ marginRight: 4 }} />
              {L("filterFiles")} <span className="pill-count">{counts.file}</span>
            </button>
          </div>

          <div className="search-box">
            <IconSearch size={14} className="search-icon" />
            <input
              className="input input-sm search-input"
              placeholder={L("searchHistoryPlaceholder")}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            {search && (
              <button
                className="clear-search"
                onClick={() => setSearch("")}
                title="Clear search"
              >
                <IconX size={12} />
              </button>
            )}
          </div>
        </div>

        {/* History Table */}
        <section className="panel" style={{ padding: 0, overflow: "hidden" }}>
          {filtered.length === 0 ? (
            <div className="empty" style={{ padding: 48 }}>
              {search || filter !== "all" ? "No matching records found" : L("noResults")}
            </div>
          ) : (
            <div className="history-scroll">
              <table className="table table-hover">
                <thead>
                  <tr>
                    <th style={{ width: 90 }}>{L("time")}</th>
                    <th style={{ width: 100 }}>{L("decision")}</th>
                    <th>{L("hostname")}</th>
                    <th style={{ width: 80, textAlign: "right" }}>{L("score")}</th>
                    <th style={{ width: 110 }}>{L("vt")}</th>
                    <th style={{ width: 140 }}>{L("official")}</th>
                    <th style={{ width: 80, textAlign: "right" }}>{L("details")}</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((item) => {
                    const isSelected = selected?.id === item.id;
                    return (
                      <tr
                        key={item.id}
                        className={`clickable-row ${isSelected ? "selected-row" : ""}`}
                        onClick={() => setSelected(isSelected ? null : item)}
                      >
                        <td className="mono text-muted text-xs">
                          {new Date(item.checkedAt).toLocaleTimeString()}
                        </td>
                        <td>
                          <DecisionPill decision={item.decision} />
                        </td>
                        <td className="mono font-medium truncate-cell" title={item.hostname || item.url}>
                          {item.kind === "file" || item.url?.startsWith("file:") ? (
                            <span className="file-tag">
                              <IconFile size={11} style={{ marginRight: 4 }} />
                              {item.hostname || item.url}
                            </span>
                          ) : (
                            item.hostname || item.url
                          )}
                        </td>
                        <td style={{ textAlign: "right" }}>
                          <span className="score-num">{item.score}</span>
                        </td>
                        <td>
                          <span className={`vt-chip ${item.virusTotal?.status}`}>
                            {item.virusTotal?.status ?? "—"}
                          </span>
                        </td>
                        <td className="truncate-cell text-muted">
                          {item.authority?.brand ?? "—"}
                        </td>
                        <td style={{ textAlign: "right" }}>
                          <button
                            className="btn btn-xs btn-ghost"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelected(isSelected ? null : item);
                            }}
                          >
                            {isSelected ? L("closeDetail") : L("details")}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* Selected Record Drawer / Detail Inspector */}
        {selected && (
          <section className="panel record-drawer">
            <div className="panel-head">
              <div>
                <span className="sub hint" style={{ textTransform: "uppercase", fontSize: 10 }}>
                  Diagnostic Report · {selected.id}
                </span>
                <h3 className="mono" style={{ fontSize: 15, marginTop: 2 }}>
                  {selected.hostname || selected.url}
                </h3>
              </div>
              <div className="split">
                <span className="score">{selected.score}</span>
                <DecisionPill decision={selected.decision} />
                <button
                  className="btn btn-ghost btn-sm"
                  onClick={() => setSelected(null)}
                  title={L("closeDetail")}
                >
                  <IconX size={14} />
                </button>
              </div>
            </div>

            <div className="result-body" style={{ marginTop: 14 }}>
              <div className="meta-grid cols-2">
                <div className="meta-item">
                  <div className="k">{L("url")}</div>
                  <div className="v mono text-xs">{selected.url}</div>
                </div>
                <div className="meta-item">
                  <div className="k">{L("time")}</div>
                  <div className="v text-xs">{new Date(selected.checkedAt).toLocaleString()}</div>
                </div>
                <div className="meta-item">
                  <div className="k">{L("brand")}</div>
                  <div className="v">{selected.authority?.brand ?? "—"}</div>
                </div>
                <div className="meta-item">
                  <div className="k">{L("lookalike")}</div>
                  <div className="v">{selected.authority?.lookalikeOf ?? "—"}</div>
                </div>
              </div>

              <DataSources result={selected} />
            </div>

            <div className="panel-head" style={{ marginTop: 14 }}>
              <h3>Evidence & Rule Triggers</h3>
            </div>
            <ReasonList reasons={selected.reasons} />
          </section>
        )}
      </div>
    </div>
  );
}
