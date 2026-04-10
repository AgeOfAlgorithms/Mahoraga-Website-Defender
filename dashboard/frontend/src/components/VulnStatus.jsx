import { useMemo } from "react";

const SEVERITY_COLORS = {
  critical: { bg: "bg-red-950", border: "border-red-700", text: "text-red-400", badge: "bg-red-600" },
  high: { bg: "bg-orange-950", border: "border-orange-700", text: "text-orange-400", badge: "bg-orange-600" },
  medium: { bg: "bg-amber-950", border: "border-amber-700", text: "text-amber-400", badge: "bg-amber-600" },
  low: { bg: "bg-yellow-950", border: "border-yellow-700", text: "text-yellow-400", badge: "bg-yellow-600" },
};

const STATUS_STYLES = {
  patched: { bg: "bg-green-900/40", border: "border-green-600", label: "PATCHED", labelBg: "bg-green-700" },
  in_progress: { bg: "bg-amber-900/30", border: "border-amber-600", label: "IN PROGRESS", labelBg: "bg-amber-600" },
  unpatched: { bg: "bg-gray-800/60", border: "border-gray-700", label: "UNPATCHED", labelBg: "bg-gray-600" },
};

export default function VulnStatus({ vulns, patches, events }) {
  // Count how many times each vuln was detected
  const detectionCounts = useMemo(() => {
    const counts = {};
    for (const evt of events) {
      const type = evt.event_type?.toLowerCase() || "";
      counts[type] = (counts[type] || 0) + 1;
    }
    return counts;
  }, [events]);

  // Group by severity
  const grouped = useMemo(() => {
    const groups = { critical: [], high: [], medium: [], low: [] };
    for (const v of vulns) {
      const sev = v.severity?.toLowerCase() || "medium";
      if (groups[sev]) groups[sev].push(v);
    }
    return groups;
  }, [vulns]);

  const totalVulns = vulns.length;
  const patchedCount = vulns.filter(v => v.status === "patched").length;
  const inProgressCount = vulns.filter(v => v.status === "in_progress").length;

  return (
    <div className="h-full overflow-y-auto p-4">
      {/* Summary bar */}
      <div className="flex items-center gap-6 mb-6">
        <h2 className="text-lg font-bold text-white">Vulnerability Status</h2>
        <div className="flex-1 h-3 bg-gray-800 rounded-full overflow-hidden flex">
          {patchedCount > 0 && (
            <div
              className="h-full bg-green-600 transition-all duration-500"
              style={{ width: `${(patchedCount / totalVulns) * 100}%` }}
            />
          )}
          {inProgressCount > 0 && (
            <div
              className="h-full bg-amber-600 transition-all duration-500"
              style={{ width: `${(inProgressCount / totalVulns) * 100}%` }}
            />
          )}
        </div>
        <span className="text-sm text-gray-400">
          <span className="text-green-400 font-bold">{patchedCount}</span>
          <span className="text-gray-600"> / </span>
          <span className="text-white font-bold">{totalVulns}</span>
          <span className="text-gray-500 ml-1">patched</span>
        </span>
      </div>

      {/* Vulnerability cards by severity */}
      {["critical", "high", "medium", "low"].map(sev => {
        const items = grouped[sev];
        if (!items || items.length === 0) return null;

        const colors = SEVERITY_COLORS[sev];
        return (
          <div key={sev} className="mb-6">
            <div className="flex items-center gap-2 mb-3">
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${colors.badge} text-white uppercase`}>
                {sev}
              </span>
              <span className="text-xs text-gray-500">{items.length} vulnerabilit{items.length === 1 ? "y" : "ies"}</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {items.map(v => {
                const statusStyle = STATUS_STYLES[v.status] || STATUS_STYLES.unpatched;
                const detectCount = detectionCounts[v.id] || 0;

                return (
                  <div
                    key={v.id}
                    className={`rounded-lg border p-4 transition-colors ${statusStyle.bg} ${statusStyle.border}`}
                  >
                    <div className="flex items-start justify-between">
                      <h3 className="text-sm font-bold text-white">{v.name}</h3>
                      <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded text-white ${statusStyle.labelBg}`}>
                        {statusStyle.label}
                      </span>
                    </div>
                    <p className="text-xs text-gray-400 mt-1">{v.description}</p>

                    {/* Solves */}
                    {v.solves > 0 && (
                      <div className="mt-2 p-1.5 rounded bg-red-950/40 border border-red-800/50">
                        <div className="flex items-center gap-1.5">
                          <span className="text-[10px] font-bold text-red-400">
                            {v.solves} solve{v.solves !== 1 ? "s" : ""}
                          </span>
                          <span className="text-[10px] text-gray-500">by</span>
                          <span className="text-[10px] text-red-300 truncate">
                            {v.solved_by?.join(", ")}
                          </span>
                        </div>
                      </div>
                    )}

                    <div className="flex items-center justify-between mt-2">
                      <span className="text-[10px] font-mono text-gray-600">{v.id}</span>
                      {detectCount > 0 && (
                        <span className="text-[10px] text-amber-400">
                          {detectCount} detection{detectCount !== 1 ? "s" : ""}
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}

      {vulns.length === 0 && (
        <div className="flex items-center justify-center h-64 text-gray-600">
          Loading vulnerability data...
        </div>
      )}
    </div>
  );
}
