import { useState, useCallback, useEffect } from "react";
import useWebSocket from "./hooks/useWebSocket";
import LogViewer from "./components/LogViewer";
import KanbanBoard from "./components/KanbanBoard";
import CodeDiff from "./components/CodeDiff";
import VulnStatus from "./components/VulnStatus";

const TABS = [
  { id: "logs", label: "Logs" },
  { id: "pipeline", label: "Pipeline" },
  { id: "patches", label: "Patches" },
  { id: "vulns", label: "Vulnerabilities" },
];

const MAX_LOGS = 800;

export default function App() {
  const [tab, setTab] = useState("logs");
  const [prodLogs, setProdLogs] = useState([]);
  const [shadowLogs, setShadowLogs] = useState([]);
  const [events, setEvents] = useState([]);
  const [audit, setAudit] = useState([]);
  const [patches, setPatches] = useState([]);
  const [status, setStatus] = useState(null);
  const [vulns, setVulns] = useState([]);

  // Load initial data
  useEffect(() => {
    fetch("/api/logs/recent?env=prod&limit=100").then(r => r.json()).then(setProdLogs).catch(() => {});
    fetch("/api/logs/recent?env=shadow&limit=100").then(r => r.json()).then(setShadowLogs).catch(() => {});
    fetch("/api/events").then(r => r.json()).then(setEvents).catch(() => {});
    fetch("/api/audit").then(r => r.json()).then(setAudit).catch(() => {});
    fetch("/api/patches").then(r => r.json()).then(setPatches).catch(() => {});
    fetch("/api/status").then(r => r.json()).then(setStatus).catch(() => {});
    fetch("/api/vulns").then(r => r.json()).then(setVulns).catch(() => {});

    // Poll vulns/scoreboard every 10s (flag submissions don't come via WebSocket)
    const vulnInterval = setInterval(() => {
      fetch("/api/vulns").then(r => r.json()).then(setVulns).catch(() => {});
    }, 10000);
    return () => clearInterval(vulnInterval);
  }, []);

  // Handle WebSocket messages
  const onMessage = useCallback((msg) => {
    switch (msg.type) {
      case "prod_log":
        setProdLogs(prev => [...prev.slice(-(MAX_LOGS - 1)), { ...msg.data, _new: true }]);
        break;
      case "shadow_log":
        setShadowLogs(prev => [...prev.slice(-(MAX_LOGS - 1)), { ...msg.data, _new: true }]);
        break;
      case "event":
        setEvents(prev => {
          const idx = prev.findIndex(e => e.event_id === msg.data.event_id);
          if (idx >= 0) {
            const next = [...prev];
            next[idx] = msg.data;
            return next;
          }
          return [...prev, msg.data];
        });
        break;
      case "audit":
        setAudit(prev => [...prev.slice(-199), msg.data]);
        break;
      case "patch":
        setPatches(prev => {
          const idx = prev.findIndex(p => p.patch_id === msg.data.patch_id);
          if (idx >= 0) {
            const next = [...prev];
            next[idx] = msg.data;
            return next;
          }
          return [...prev, msg.data];
        });
        // Refresh vulns when a new patch arrives
        fetch("/api/vulns").then(r => r.json()).then(setVulns).catch(() => {});
        break;
      case "status":
        setStatus(msg.data);
        break;
    }
  }, []);

  useWebSocket(onMessage);

  // Classify which log paths are suspicious (watcher-flagged)
  const watcherPaths = new Set(events.map(e => e.evidence?.request_path).filter(Boolean));
  const analyzerTypes = new Set(
    audit.filter(a => a.action === "shadow_exploit_detected").map(a => a.detail)
  );

  const shadowSessions = (status?.shadow?.redirected_tokens ?? 0) + (status?.shadow?.redirected_ja3s ?? 0);
  const totalEvents = events.length;
  const totalPatches = patches.length;
  const [resetOpen, setResetOpen] = useState(false);

  const doReset = async (endpoint, label) => {
    if (!confirm(`Reset ${label}? This cannot be undone.`)) return;
    try {
      await fetch(endpoint, { method: "POST" });
      // Refresh state
      if (endpoint.includes("logs")) {
        setProdLogs([]);
        setShadowLogs([]);
      }
      if (endpoint.includes("sessions")) {
        fetch("/api/status").then(r => r.json()).then(setStatus).catch(() => {});
      }
      if (endpoint.includes("events")) {
        setEvents([]);
        setAudit([]);
        setPatches([]);
      }
    } catch {}
    setResetOpen(false);
  };

  return (
    <div className="h-full flex flex-col text-gray-200">
      {/* Header */}
      <header className="bg-gray-900 border-b border-gray-800 px-4 py-2 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <h1 className="text-lg font-bold text-white tracking-tight">Mahoraga Defender Agent</h1>
        </div>
        <div className="flex items-center gap-6 text-sm">
          <Stat label="Events" value={totalEvents} color="amber" />
          <Stat label="Shadow Sessions" value={shadowSessions} color="purple" />
          <Stat label="Patches" value={totalPatches} color="green" />
          <StatusDot connected={!!status?.control_plane?.redis_connected} />

          {/* Reset dropdown */}
          <div className="relative">
            <button
              onClick={() => setResetOpen(!resetOpen)}
              className="px-2 py-1 text-xs text-gray-400 hover:text-white bg-gray-800 hover:bg-gray-700 rounded border border-gray-700 transition-colors"
            >
              Reset
            </button>
            {resetOpen && (
              <div className="absolute right-0 top-8 bg-gray-800 border border-gray-700 rounded shadow-xl z-50 w-48">
                <button onClick={() => doReset("/api/reset/logs", "logs")}
                  className="w-full text-left px-3 py-2 text-xs text-gray-300 hover:bg-gray-700 hover:text-white">
                  Clear Logs
                </button>
                <button onClick={() => doReset("/api/reset/sessions", "shadow sessions")}
                  className="w-full text-left px-3 py-2 text-xs text-gray-300 hover:bg-gray-700 hover:text-white">
                  Clear Shadow Sessions
                </button>
                <button onClick={() => doReset("/api/reset/events", "events & patches")}
                  className="w-full text-left px-3 py-2 text-xs text-gray-300 hover:bg-gray-700 hover:text-white">
                  Clear Events & Patches
                </button>
                <button onClick={() => { doReset("/api/reset/scoreboard", "scoreboard"); fetch("/api/vulns").then(r => r.json()).then(setVulns).catch(() => {}); }}
                  className="w-full text-left px-3 py-2 text-xs text-gray-300 hover:bg-gray-700 hover:text-white">
                  Clear Scoreboard
                </button>
                <div className="border-t border-gray-700" />
                <button onClick={async () => {
                    if (!confirm("Reset ALL state? This clears logs, sessions, events, patches, and scoreboard.")) return;
                    await fetch("/api/reset/logs", { method: "POST" });
                    await fetch("/api/reset/sessions", { method: "POST" });
                    await fetch("/api/reset/events", { method: "POST" });
                    await fetch("/api/reset/scoreboard", { method: "POST" });
                    setProdLogs([]); setShadowLogs([]); setEvents([]); setAudit([]); setPatches([]);
                    fetch("/api/status").then(r => r.json()).then(setStatus).catch(() => {});
                    fetch("/api/vulns").then(r => r.json()).then(setVulns).catch(() => {});
                    setResetOpen(false);
                  }}
                  className="w-full text-left px-3 py-2 text-xs text-red-400 hover:bg-red-900/30 hover:text-red-300 font-medium">
                  Reset Everything
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Tab bar */}
      <nav className="bg-gray-900 border-b border-gray-800 px-4 flex gap-1 shrink-0">
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-4 py-2 text-sm font-medium rounded-t transition-colors ${
              tab === t.id
                ? "bg-gray-800 text-white border-t-2 border-blue-500"
                : "text-gray-400 hover:text-gray-200 hover:bg-gray-800/50"
            }`}
          >
            {t.label}
            {t.id === "pipeline" && events.filter(e => e.status !== "resolved" && e.status !== "dismissed").length > 0 && (
              <span className="ml-2 px-1.5 py-0.5 rounded-full bg-amber-600 text-xs">
                {events.filter(e => e.status !== "resolved" && e.status !== "dismissed").length}
              </span>
            )}
          </button>
        ))}
      </nav>

      {/* Content */}
      <main className="flex-1 overflow-hidden bg-gray-950">
        {tab === "logs" && (
          <LogViewer
            prodLogs={prodLogs}
            shadowLogs={shadowLogs}
            watcherPaths={watcherPaths}
            analyzerTypes={analyzerTypes}
            events={events}
            audit={audit}
          />
        )}
        {tab === "pipeline" && (
          <KanbanBoard events={events} audit={audit} patches={patches} />
        )}
        {tab === "patches" && (
          <CodeDiff patches={patches} audit={audit} />
        )}
        {tab === "vulns" && (
          <VulnStatus vulns={vulns} patches={patches} events={events} />
        )}
      </main>
    </div>
  );
}

function Stat({ label, value, color }) {
  const colors = {
    amber: "text-amber-400",
    purple: "text-purple-400",
    green: "text-green-400",
    red: "text-red-400",
  };
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-gray-500">{label}</span>
      <span className={`font-mono font-bold ${colors[color] || "text-white"}`}>{value}</span>
    </div>
  );
}

function StatusDot({ connected }) {
  return (
    <div className="flex items-center gap-1.5" title={connected ? "Connected" : "Disconnected"}>
      <div className={`w-2 h-2 rounded-full ${connected ? "bg-green-500 animate-pulse" : "bg-red-500"}`} />
      <span className="text-xs text-gray-500">{connected ? "Live" : "Offline"}</span>
    </div>
  );
}
