import { useMemo, useState, useEffect, useRef, useCallback } from "react";

const COLUMNS = [
  { id: "detected", label: "Detected", color: "border-gray-500", bg: "bg-gray-800/50" },
  { id: "fixing", label: "Fixing", color: "border-amber-500", bg: "bg-amber-900/20" },
  { id: "reviewing", label: "Reviewing", color: "border-purple-500", bg: "bg-purple-900/20" },
  { id: "deployed", label: "Deployed", color: "border-green-500", bg: "bg-green-900/20" },
];

const DETECTED_WINDOW_OPTIONS = [
  { label: "2m", seconds: 120 },
  { label: "5m", seconds: 300 },
  { label: "15m", seconds: 900 },
  { label: "All", seconds: 0 },
];

const SEVERITY_BADGE = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-600 text-white",
  medium: "bg-amber-600 text-black",
  low: "bg-yellow-600 text-black",
  info: "bg-gray-600 text-gray-200",
};

export default function KanbanBoard({ tickets = [], audit, patches }) {
  const [selected, setSelected] = useState(null);
  const [panelWidth, setPanelWidth] = useState(() => {
    return Number(localStorage.getItem("pipeline_panel_width")) || 384;
  });
  const dragging = useRef(false);
  const dragStartX = useRef(0);
  const dragStartWidth = useRef(0);

  const onDragStart = useCallback((e) => {
    dragging.current = true;
    dragStartX.current = e.clientX;
    dragStartWidth.current = panelWidth;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";

    const onMouseMove = (e) => {
      if (!dragging.current) return;
      const delta = dragStartX.current - e.clientX;
      const newWidth = Math.max(280, Math.min(800, dragStartWidth.current + delta));
      setPanelWidth(newWidth);
    };
    const onMouseUp = () => {
      dragging.current = false;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      document.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("mouseup", onMouseUp);
      setPanelWidth(w => { localStorage.setItem("pipeline_panel_width", w); return w; });
    };
    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
  }, [panelWidth]);

  const [detectedWindow, setDetectedWindow] = useState(() => {
    return Number(localStorage.getItem("detected_window")) || 300;
  });
  const [now, setNow] = useState(Date.now() / 1000);

  // Tick every 10s to expire old detected tickets
  useEffect(() => {
    const interval = setInterval(() => setNow(Date.now() / 1000), 10000);
    return () => clearInterval(interval);
  }, []);

  // Map ticket statuses to kanban columns
  const STATUS_TO_COLUMN = {
    detected: "detected",
    queued: "fixing",          // queued for fixer → Fixing column
    fixing: "fixing",          // fixer actively working → Fixing column
    pending_review: "reviewing", // queued for reviewer → Reviewing column
    reviewing: "reviewing",    // reviewer actively working → Reviewing column
    deployed: "deployed",
  };

  const columns = useMemo(() => {
    const grouped = {};
    for (const col of COLUMNS) grouped[col.id] = [];

    for (const ticket of tickets) {
      const colId = STATUS_TO_COLUMN[ticket.status] || "detected";
      // Apply rolling window to detected column only
      if (colId === "detected" && detectedWindow > 0) {
        const age = now - (ticket.updated_at || ticket.created_at || 0);
        if (age > detectedWindow) continue;
      }
      if (grouped[colId]) {
        grouped[colId].push(ticket);
      } else {
        grouped["detected"].push(ticket);
      }
    }
    return grouped;
  }, [tickets, detectedWindow, now]);

  // Get audit trail for selected ticket
  const selectedAudit = useMemo(() => {
    if (!selected) return [];
    return audit
      .filter(a => a.event_id === selected.id)
      .sort((a, b) => a.timestamp - b.timestamp);
  }, [selected, audit]);

  const selectedPatch = useMemo(() => {
    if (!selected || !selected.patch_id) return null;
    return patches.find(p => p.patch_id === selected.patch_id);
  }, [selected, patches]);

  return (
    <div className="h-full flex">
      {/* Kanban columns */}
      <div className={`flex gap-2 p-3 overflow-x-auto overflow-y-auto ${selected ? "flex-1" : "flex-1"}`}>
        {COLUMNS.map(col => (
          <div key={col.id} className="flex flex-col w-56 shrink-0">
            {/* Column header */}
            <div className={`flex items-center justify-between px-3 py-2 rounded-t border-t-2 ${col.color} ${col.bg}`}>
              <span className="text-sm font-medium text-gray-200">{col.label}</span>
              {col.id === "detected" && (
                <div className="flex gap-0.5 mr-2">
                  {DETECTED_WINDOW_OPTIONS.map(opt => (
                    <button
                      key={opt.seconds}
                      onClick={() => { setDetectedWindow(opt.seconds); localStorage.setItem("detected_window", opt.seconds); }}
                      className={`px-1.5 py-0.5 text-[9px] rounded ${
                        detectedWindow === opt.seconds
                          ? "bg-gray-600 text-white"
                          : "text-gray-500 hover:text-gray-300"
                      }`}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              )}
              <span className="text-xs text-gray-500 font-mono">{columns[col.id].length}</span>
            </div>

            {/* Cards */}
            <div className="flex-1 overflow-y-auto space-y-1.5 p-1.5 bg-gray-900/30 rounded-b">
              {columns[col.id].map(ticket => {
                const isSelected = selected?.id === ticket.id;
                const isActive = ticket.status === "fixing" || ticket.status === "reviewing";
                return (
                  <div
                    key={ticket.id}
                    onClick={() => setSelected(isSelected ? null : ticket)}
                    className={`kanban-card p-2.5 rounded cursor-pointer border ${
                      isSelected && isActive
                        ? "border-blue-400 bg-amber-950/40 ring-1 ring-blue-500/40"
                        : isSelected
                          ? "border-blue-500 bg-blue-950/30"
                          : isActive
                            ? "border-amber-500/70 bg-amber-950/30 ring-1 ring-amber-500/30"
                            : "border-gray-700/50 bg-gray-800/80 hover:border-gray-600"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-1">
                      <span className="text-[10px] font-mono text-gray-500 truncate">
                        {ticket.id?.slice(0, 16)}
                      </span>
                      <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold shrink-0 ${
                        SEVERITY_BADGE[ticket.severity] || SEVERITY_BADGE.info
                      }`}>
                        {(ticket.severity || "").slice(0, 4).toUpperCase()}
                      </span>
                    </div>
                    <div className="mt-1 text-xs text-gray-300 font-medium truncate">
                      {ticket.type}{ticket.endpoint ? ` — ${ticket.endpoint}` : ""}
                    </div>
                    {ticket.agent && (
                      <span className="text-[9px] text-gray-500 mt-0.5 block">{ticket.agent}</span>
                    )}
                    {ticket.retry_count > 0 && ticket.status !== "deployed" && (
                      <span className="text-[9px] text-red-400 mt-0.5 block">
                        retry #{ticket.retry_count}
                      </span>
                    )}
                    {isActive && (
                      <span className="text-[9px] text-amber-400 mt-0.5 flex items-center gap-1">
                        <span className="inline-block w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
                        in progress
                      </span>
                    )}
                    <div className="text-[10px] text-gray-600 mt-1">
                      {ticket.created_at ? new Date(ticket.created_at * 1000).toLocaleTimeString() : ""}
                    </div>
                  </div>
                );
              })}
              {columns[col.id].length === 0 && (
                <div className="text-center text-gray-700 text-xs py-4">Empty</div>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Detail panel — right sidebar */}
      {selected && (
        <div className="shrink-0 flex" style={{ width: panelWidth }}>
          {/* Drag handle */}
          <div
            onMouseDown={onDragStart}
            className="w-1 shrink-0 bg-gray-800 hover:bg-blue-500 cursor-col-resize transition-colors"
          />
          <div className="flex-1 overflow-y-auto bg-gray-900">
          <div className="flex items-center justify-between px-4 py-2 border-b border-gray-800 sticky top-0 bg-gray-900 z-10">
            <h3 className="text-sm font-bold text-white truncate">
              {selected.type}
            </h3>
            <button onClick={() => setSelected(null)} className="text-gray-500 hover:text-white text-lg leading-none ml-2">&times;</button>
          </div>

          <div className="p-4 space-y-4">
            <div className="text-[10px] text-gray-500 font-mono">{selected.id}</div>

            {/* Evidence */}
            <div>
              <h4 className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Evidence</h4>
              <pre className="text-[11px] text-gray-300 bg-gray-950 rounded p-2 max-h-48 overflow-auto whitespace-pre-wrap break-words">
                {selected.evidence}
              </pre>
            </div>

            {/* Patch info */}
            {(selected.patch_id || selectedPatch) && (() => {
              const status = selected.status;
              const label = status === "deployed" ? "Patch Deployed" :
                            (status === "reviewing" || status === "pending_review") ? "Patch Under Review" :
                            (status === "queued" && selected.retry_count > 0) ? "Patch Rejected — Retrying" :
                            "Patch Proposed";
              const borderColor = status === "deployed" ? "border-green-800" :
                                  (status === "reviewing" || status === "pending_review") ? "border-purple-800" :
                                  selected.retry_count > 0 ? "border-red-800" : "border-amber-800";
              const bgColor = status === "deployed" ? "bg-green-950/30" :
                              (status === "reviewing" || status === "pending_review") ? "bg-purple-950/30" :
                              selected.retry_count > 0 ? "bg-red-950/30" : "bg-amber-950/30";
              const labelColor = status === "deployed" ? "text-green-400" :
                                 (status === "reviewing" || status === "pending_review") ? "text-purple-400" :
                                 selected.retry_count > 0 ? "text-red-400" : "text-amber-400";

              return (
                <div className={`p-2 rounded ${bgColor} border ${borderColor}`}>
                  <div className={`text-[10px] uppercase font-bold ${labelColor}`}>{label}</div>
                  {(selected.patch_description || selectedPatch?.description) && (
                    <div className="text-xs text-gray-300 mt-1">
                      {selected.patch_description || selectedPatch?.description}
                    </div>
                  )}
                  {(selected.patch_files?.length > 0 || selectedPatch?.files_modified?.length > 0) && (
                    <div className="text-[10px] text-gray-500 mt-1">
                      Files: {(selected.patch_files || selectedPatch?.files_modified)?.join(", ")}
                    </div>
                  )}
                </div>
              );
            })()}

            {/* Timeline */}
            <div>
              <h4 className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Timeline</h4>
              <div className="space-y-1">
                {selectedAudit.map((a, i) => (
                  <div key={i} className="flex gap-2 text-[11px]">
                    <span className="text-gray-600 shrink-0">
                      {new Date(a.timestamp * 1000).toLocaleTimeString()}
                    </span>
                    <span className={`shrink-0 font-medium ${
                      a.action === "deployed" ? "text-green-400" :
                      a.action === "review_rejected" ? "text-red-400" :
                      a.action.includes("patch") ? "text-amber-400" :
                      a.action === "tool_call" ? "text-gray-600" :
                      "text-gray-400"
                    }`}>
                      {a.agent}
                    </span>
                    <span className="text-gray-300 break-words min-w-0">{a.detail}</span>
                  </div>
                ))}
                {selectedAudit.length === 0 && (
                  <div className="text-gray-600 text-xs">No audit entries yet</div>
                )}
              </div>
            </div>
          </div>
          </div>
        </div>
      )}
    </div>
  );
}
