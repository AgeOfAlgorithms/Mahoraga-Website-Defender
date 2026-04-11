import { useMemo, useState } from "react";

const COLUMNS = [
  { id: "new", label: "Detected", color: "border-gray-500", bg: "bg-gray-800/50" },
  { id: "analyzing", label: "Analyzing", color: "border-blue-500", bg: "bg-blue-900/20" },
  { id: "fix_proposed", label: "Fix Proposed", color: "border-amber-500", bg: "bg-amber-900/20" },
  { id: "fix_reviewing", label: "Reviewing", color: "border-purple-500", bg: "bg-purple-900/20" },
  { id: "fix_testing", label: "Testing", color: "border-cyan-500", bg: "bg-cyan-900/20" },
  { id: "resolved", label: "Deployed", color: "border-green-500", bg: "bg-green-900/20" },
];

const SEVERITY_BADGE = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-600 text-white",
  medium: "bg-amber-600 text-black",
  low: "bg-yellow-600 text-black",
  info: "bg-gray-600 text-gray-200",
};

export default function KanbanBoard({ events, audit, patches }) {
  const [selected, setSelected] = useState(null);

  // Group events by status
  const columns = useMemo(() => {
    const grouped = {};
    for (const col of COLUMNS) grouped[col.id] = [];

    for (const evt of events) {
      const status = (evt.status || "new").toLowerCase();
      if (grouped[status]) {
        grouped[status].push(evt);
      } else {
        grouped["new"].push(evt);
      }
    }

    // Also add shadow exploits from audit as synthetic events
    const shadowEvents = audit.filter(a => a.action === "shadow_exploit_detected");
    for (const a of shadowEvents) {
      // Check if there's a corresponding patch
      const deployed = audit.some(
        aa => aa.action === "deployed" && aa.event_id === a.event_id
      );
      const reviewing = audit.some(
        aa => aa.action === "patch_proposed" && aa.event_id === a.event_id
      );
      const escalated = audit.some(
        aa => aa.action === "escalated" && aa.event_id === a.event_id
      );

      const synthEvent = {
        event_id: a.event_id,
        event_type: `shadow: ${a.detail?.match(/type=(\S+)/)?.[1] || "unknown"}`,
        severity: a.detail?.match(/severity=(\S+)/)?.[1] || "high",
        timestamp: a.timestamp,
        source: "shadow_analyzer",
        status: deployed ? "resolved" : escalated ? "escalated" : reviewing ? "fix_reviewing" : "analyzing",
        evidence: { detail: a.detail },
        _shadow: true,
      };

      const status = synthEvent.status;
      if (grouped[status]) {
        // Avoid duplicates
        if (!grouped[status].some(e => e.event_id === synthEvent.event_id)) {
          grouped[status].push(synthEvent);
        }
      }
    }

    return grouped;
  }, [events, audit]);

  // Get audit trail for selected event
  const selectedAudit = useMemo(() => {
    if (!selected) return [];
    return audit
      .filter(a => a.event_id === selected.event_id)
      .sort((a, b) => a.timestamp - b.timestamp);
  }, [selected, audit]);

  const selectedPatch = useMemo(() => {
    if (!selected) return null;
    return patches.find(p => p.event_id === selected.event_id);
  }, [selected, patches]);

  return (
    <div className="h-full flex flex-col">
      {/* Kanban columns */}
      <div className="flex-1 flex gap-2 p-3 overflow-x-auto">
        {COLUMNS.map(col => (
          <div key={col.id} className="flex flex-col w-56 shrink-0">
            {/* Column header */}
            <div className={`flex items-center justify-between px-3 py-2 rounded-t border-t-2 ${col.color} ${col.bg}`}>
              <span className="text-sm font-medium text-gray-200">{col.label}</span>
              <span className="text-xs text-gray-500 font-mono">{columns[col.id].length}</span>
            </div>

            {/* Cards */}
            <div className="flex-1 overflow-y-auto space-y-1.5 p-1.5 bg-gray-900/30 rounded-b">
              {columns[col.id].map(evt => (
                <div
                  key={evt.event_id}
                  onClick={() => setSelected(selected?.event_id === evt.event_id ? null : evt)}
                  className={`kanban-card p-2.5 rounded cursor-pointer border ${
                    selected?.event_id === evt.event_id
                      ? "border-blue-500 bg-gray-800"
                      : "border-gray-700/50 bg-gray-800/80 hover:border-gray-600"
                  }`}
                >
                  <div className="flex items-start justify-between gap-1">
                    <span className="text-[10px] font-mono text-gray-500 truncate">
                      {evt.event_id?.slice(0, 16)}
                    </span>
                    <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold shrink-0 ${
                      SEVERITY_BADGE[evt.severity?.toLowerCase?.()] || SEVERITY_BADGE[evt.severity] || SEVERITY_BADGE.info
                    }`}>
                      {(evt.severity?.toUpperCase?.() || evt.severity || "").slice(0, 4)}
                    </span>
                  </div>
                  <div className="mt-1 text-xs text-gray-300 font-medium truncate">
                    {evt.event_type}
                  </div>
                  {evt._shadow && (
                    <span className="text-[9px] text-purple-400 mt-0.5 block">via shadow analyzer</span>
                  )}
                  <div className="text-[10px] text-gray-600 mt-1">
                    {evt.timestamp ? new Date(evt.timestamp * 1000).toLocaleTimeString() : ""}
                  </div>
                </div>
              ))}
              {columns[col.id].length === 0 && (
                <div className="text-center text-gray-700 text-xs py-4">Empty</div>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Detail panel */}
      {selected && (
        <div className="shrink-0 border-t border-gray-800 bg-gray-900 p-4 max-h-72 overflow-y-auto">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-bold text-white">
              {selected.event_type}
              <span className="ml-2 text-gray-500 font-mono text-xs">{selected.event_id}</span>
            </h3>
            <button onClick={() => setSelected(null)} className="text-gray-500 hover:text-white text-lg leading-none">&times;</button>
          </div>

          <div className="grid grid-cols-2 gap-4">
            {/* Evidence */}
            <div>
              <h4 className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Evidence</h4>
              <pre className="text-[11px] text-gray-300 bg-gray-950 rounded p-2 max-h-36 overflow-auto whitespace-pre-wrap">
                {JSON.stringify(selected.evidence, null, 2)}
              </pre>
            </div>

            {/* Audit trail */}
            <div>
              <h4 className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Timeline</h4>
              <div className="space-y-1 max-h-36 overflow-auto">
                {selectedAudit.map((a, i) => (
                  <div key={i} className="flex gap-2 text-[11px]">
                    <span className="text-gray-600 shrink-0">
                      {new Date(a.timestamp * 1000).toLocaleTimeString()}
                    </span>
                    <span className={`shrink-0 font-medium ${
                      a.action === "deployed" ? "text-green-400" :
                      a.action === "escalated" ? "text-red-400" :
                      a.action.includes("patch") ? "text-amber-400" :
                      "text-gray-400"
                    }`}>
                      {a.agent}
                    </span>
                    <span className="text-gray-300 truncate">{a.detail}</span>
                  </div>
                ))}
                {selectedAudit.length === 0 && (
                  <div className="text-gray-600 text-xs">No audit entries yet</div>
                )}
              </div>

              {/* Patch info */}
              {selectedPatch && (
                <div className="mt-2 p-2 rounded bg-green-950/30 border border-green-800">
                  <div className="text-[10px] text-green-400 uppercase font-bold">Patch Applied</div>
                  <div className="text-xs text-gray-300 mt-1">{selectedPatch.description}</div>
                  <div className="text-[10px] text-gray-500 mt-1">
                    Files: {selectedPatch.files_modified?.join(", ")}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
