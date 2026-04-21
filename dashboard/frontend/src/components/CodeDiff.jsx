import { useState, useMemo, useRef, useCallback } from "react";

export default function CodeDiff({ patches, audit, pipelineTickets = [] }) {
  const [selected, setSelected] = useState(null);
  const [listWidth, setListWidth] = useState(() => {
    return Number(localStorage.getItem("patch_list_width")) || 256;
  });
  const dragging = useRef(false);
  const dragStartX = useRef(0);
  const dragStartWidth = useRef(0);

  const onDragStart = useCallback((e) => {
    dragging.current = true;
    dragStartX.current = e.clientX;
    dragStartWidth.current = listWidth;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";

    const onMouseMove = (e) => {
      if (!dragging.current) return;
      const delta = e.clientX - dragStartX.current;
      const newWidth = Math.max(200, Math.min(600, dragStartWidth.current + delta));
      setListWidth(newWidth);
    };
    const onMouseUp = () => {
      dragging.current = false;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      document.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("mouseup", onMouseUp);
      setListWidth(w => { localStorage.setItem("patch_list_width", w); return w; });
    };
    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
  }, [listWidth]);

  // Enrich patches with status from pipeline tickets
  const enrichedPatches = useMemo(() => {
    const ticketByEvent = {};
    for (const t of pipelineTickets) ticketByEvent[t.id] = t;

    return patches.map(p => {
      const ticket = ticketByEvent[p.event_id];
      const related = audit.filter(a => a.event_id === p.event_id);

      let status = "unknown";
      if (ticket) {
        status = ticket.status === "deployed" ? "deployed" :
                 (ticket.status === "reviewing" || ticket.status === "pending_review") ? "reviewing" :
                 (ticket.status === "queued" && ticket.retry_count > 0) ? "rejected" :
                 "proposed";
      }

      return {
        ...p,
        status,
        timeline: related.sort((a, b) => a.timestamp - b.timestamp),
      };
    }).reverse(); // Most recent first
  }, [patches, audit, pipelineTickets]);

  const selectedPatch = selected != null ? enrichedPatches[selected] : null;

  return (
    <div className="h-full flex">
      {/* Patch list */}
      <div className="shrink-0 overflow-y-auto" style={{ width: listWidth }}>
        <div className="p-3 border-b border-gray-800">
          <h2 className="text-sm font-bold text-gray-300">Patches ({enrichedPatches.length})</h2>
        </div>
        {enrichedPatches.length === 0 ? (
          <div className="p-4 text-center text-gray-600 text-sm">No patches generated yet</div>
        ) : (
          enrichedPatches.map((p, idx) => (
            <div
              key={p.patch_id || idx}
              onClick={() => setSelected(selected === idx ? null : idx)}
              className={`p-3 border-b border-gray-800/50 cursor-pointer transition-colors ${
                selected === idx
                  ? "bg-gray-800 border-l-2 border-l-blue-500"
                  : "hover:bg-gray-800/50"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-gray-500 truncate">{p.patch_id || p.event_id}</span>
                <StatusBadge status={p.status} />
              </div>
              <div className="text-sm text-gray-300 mt-1 break-words">{p.description}</div>
              <div className="text-[10px] text-gray-600 mt-1">
                {p.files_modified?.length || 0} file(s) modified
              </div>
            </div>
          ))
        )}
      </div>

      {/* Drag handle */}
      <div
        onMouseDown={onDragStart}
        className="w-1 shrink-0 bg-gray-800 hover:bg-blue-500 cursor-col-resize transition-colors"
      />

      {/* Patch detail */}
      <div className="flex-1 overflow-y-auto overflow-x-hidden">
        {selectedPatch ? (
          <div className="p-4 space-y-4">
            {/* Header */}
            <div>
              <h2 className="text-lg font-bold text-white">{selectedPatch.description}</h2>
              <div className="flex items-center gap-3 mt-1">
                <span className="text-xs font-mono text-gray-500">{selectedPatch.patch_id}</span>
                <StatusBadge status={selectedPatch.status} />
                <span className="text-xs text-gray-500">{selectedPatch.patch_type}</span>
              </div>
            </div>

            {/* Files modified */}
            <div>
              <h3 className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Files Modified</h3>
              <div className="flex flex-wrap gap-2">
                {(selectedPatch.files_modified || []).map((f, i) => (
                  <span key={i} className="px-2 py-1 bg-gray-800 rounded text-xs font-mono text-gray-300">
                    {f}
                  </span>
                ))}
              </div>
            </div>

            {/* Diff */}
            {selectedPatch.diff && (
              <div>
                <h3 className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Changes</h3>
                <DiffView diff={selectedPatch.diff} />
              </div>
            )}

            {/* Changes summary (when no diff available) */}
            {!selectedPatch.diff && selectedPatch.changes_summary && (
              <div>
                <h3 className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Changes Summary</h3>
                <pre className="bg-gray-900 border border-gray-800 rounded p-3 text-xs text-gray-300 whitespace-pre-wrap">
                  {selectedPatch.changes_summary}
                </pre>
              </div>
            )}

            {/* Rollback */}
            {selectedPatch.rollback_steps && (
              <div>
                <h3 className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Rollback</h3>
                <pre className="bg-gray-900 border border-gray-800 rounded p-3 text-xs text-gray-400 font-mono">
                  {selectedPatch.rollback_steps}
                </pre>
              </div>
            )}

            {/* Timeline */}
            <div>
              <h3 className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Timeline</h3>
              <div className="space-y-1">
                {selectedPatch.timeline.map((a, i) => (
                  <TimelineEntry key={i} entry={a} />
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="flex items-center justify-center h-full text-gray-600">
            Select a patch to view details
          </div>
        )}
      </div>
    </div>
  );
}

function DiffView({ diff }) {
  if (!diff) return null;

  const lines = diff.split("\n");

  return (
    <div className="bg-gray-950 border border-gray-800 rounded overflow-x-auto font-mono text-xs">
      {lines.map((line, i) => {
        let cls = "px-3 py-0.5";
        if (line.startsWith("+") && !line.startsWith("+++")) {
          cls += " diff-add text-green-400";
        } else if (line.startsWith("-") && !line.startsWith("---")) {
          cls += " diff-remove text-red-400";
        } else if (line.startsWith("@@")) {
          cls += " text-blue-400 bg-blue-950/30";
        } else if (line.startsWith("diff ") || line.startsWith("---") || line.startsWith("+++")) {
          cls += " text-gray-500 font-bold";
        } else {
          cls += " text-gray-400";
        }

        return (
          <div key={i} className={cls}>
            <span className="text-gray-700 select-none inline-block w-8 text-right mr-2">{i + 1}</span>
            {line}
          </div>
        );
      })}
    </div>
  );
}

function StatusBadge({ status }) {
  const styles = {
    deployed: "bg-green-900 text-green-300 border-green-700",
    reviewing: "bg-purple-900 text-purple-300 border-purple-700",
    proposed: "bg-amber-900 text-amber-300 border-amber-700",
    rejected: "bg-red-900 text-red-300 border-red-700",
    unknown: "bg-gray-800 text-gray-400 border-gray-700",
  };

  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded border ${styles[status] || styles.unknown}`}>
      {status}
    </span>
  );
}

function TimelineEntry({ entry }) {
  const icons = {
    detection: "\u{1F50D}",
    shadow_exploit_detected: "\u{1F47E}",
    fixer_started: "\u{1F527}",
    patch_proposed: "\u{1F4E6}",
    review_passed: "\u2705",
    review_rejected: "\u274C",
    deployed: "\u{1F680}",
    test_failed: "\u26A0\uFE0F",
    error: "\u274C",
    session_redirected_to_shadow: "\u{1F300}",
  };

  return (
    <div className="flex items-start gap-2 text-xs py-1">
      <span className="shrink-0 mt-0.5">{icons[entry.action] || "\u25CF"}</span>
      <span className="text-gray-600 shrink-0 w-20">
        {new Date(entry.timestamp * 1000).toLocaleTimeString()}
      </span>
      <span className="text-gray-400 shrink-0 w-16 font-medium">{entry.agent}</span>
      <span className="text-gray-300 break-words min-w-0 overflow-hidden">{entry.detail}</span>
    </div>
  );
}
