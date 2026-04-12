import { useState, useRef, useEffect, useMemo, useCallback } from "react";

// Static singleton agents (not scalable)
const SINGLETON_AGENTS = [
  {
    id: "watcher",
    label: "Watcher",
    type: "watcher",
    description: "Scans nginx logs every 4s",
    systemPrompt: "Rule-based pattern matching on nginx access logs. Detects: SQL injection, XSS, path traversal, command injection, NoSQL injection, prototype pollution. Tracks per-IP sessions for sequential ID enumeration, multi-resource access, 404 probing, and rate limiting. No LLM — free and instant.",
  },
  {
    id: "shadow_analyzer",
    label: "Shadow Analyzer",
    type: "shadow_analyzer",
    description: "LLM reads shadow logs every 15s",
    systemPrompt: "You are a security analyst monitoring a web application's shadow environment. Attackers have been redirected here — every request you see is from a suspected attacker. Your job: determine if any request-response pair shows a SUCCESSFUL attack. Look for: data leakage, privilege escalation, injection success, business logic abuse, credential theft, SSRF success.",
  },
];

// Scalable agent types (1-3 instances each)
const SCALABLE_TYPES = {
  fixer: {
    label: "Fixer",
    description: "LLM patches vulnerabilities",
    systemPrompt: "You are a security engineer patching ONE specific vulnerability. Edit source files in crapi-fork/, then reload or rebuild. Sandboxed: only crapi-fork/ file access and docker exec into whitelisted containers.",
  },
  reviewer: {
    label: "Reviewer",
    description: "LLM reviews patches",
    systemPrompt: "You are a strict security reviewer. Check: 1) Does the patch fix the vulnerability? 2) New security issues? 3) Could it break functionality? 4) SCOPE CHECK: REJECT if it makes unrelated changes. Sandboxed: only docker exec verification.",
  },
};

const LEVEL_COLORS = {
  critical: "text-red-400",
  error: "text-red-400",
  warning: "text-amber-400",
  info: "text-blue-400",
  success: "text-green-400",
  default: "text-gray-400",
};

const STALE_THRESHOLD_MS = 300_000; // 5 minutes — LLM calls can take a while

function classifyLevel(entry) {
  const detail = (entry.detail || "").toLowerCase();
  const action = (entry.action || "").toLowerCase();
  if (detail.includes("error") || detail.includes("failed") || action.includes("error")) return "error";
  if (detail.includes("critical")) return "critical";
  if (detail.includes("warning") || action.includes("warning")) return "warning";
  if (action.includes("success") || action.includes("applied") || action.includes("approved") || action.includes("passed") || action.includes("deployed")) return "success";
  return "info";
}

function getAgentStatus(entries, now) {
  if (entries.length === 0) return "idle";
  const last = entries[entries.length - 1];
  const detail = (last.detail || "").toLowerCase();
  if (detail.includes("error") || detail.includes("failed")) return "error";
  const ts = (last.timestamp || 0) * 1000;
  if (now - ts < STALE_THRESHOLD_MS) return "active";
  return "idle";
}

function formatTime(timestamp) {
  if (!timestamp) return "";
  const d = new Date(timestamp * 1000);
  if (isNaN(d.getTime())) return "";
  return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function StatusDot({ status }) {
  if (status === "active") {
    return (
      <span className="relative flex h-2.5 w-2.5" title="Active">
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
        <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-green-500" />
      </span>
    );
  }
  if (status === "error") {
    return <span className="inline-flex rounded-full h-2.5 w-2.5 bg-red-500" title="Error" />;
  }
  return <span className="inline-flex rounded-full h-2.5 w-2.5 bg-gray-600" title="Idle" />;
}

function AgentLogEntry({ entry }) {
  const [open, setOpen] = useState(false);
  const level = classifyLevel(entry);
  const levelColor = LEVEL_COLORS[level] || LEVEL_COLORS.default;

  return (
    <div
      onClick={() => setOpen(!open)}
      className="flex gap-2 px-2 py-0.5 hover:bg-gray-700/30 rounded cursor-pointer"
    >
      <span className="text-gray-600 shrink-0 w-16">{formatTime(entry.timestamp)}</span>
      <span className={`shrink-0 w-16 uppercase text-[10px] leading-4 font-semibold ${levelColor}`}>{level}</span>
      <span className={`text-gray-300 break-words min-w-0 ${open ? "" : "line-clamp-3"}`}>
        <span className="text-gray-500">{entry.action}</span>
        {entry.detail && <span className="ml-1.5">{entry.detail}</span>}
      </span>
    </div>
  );
}

function AgentPanel({ agent, entries, status }) {
  const scrollRef = useRef(null);
  const isAtBottom = useRef(true);
  const [promptOpen, setPromptOpen] = useState(false);

  const handleScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    isAtBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
  }, []);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el || !isAtBottom.current) return;
    el.scrollTop = el.scrollHeight;
  }, [entries.length]);

  const statusLabel = status === "active" ? "ACTIVE" : status === "error" ? "ERROR" : "IDLE";
  const statusTextColor = status === "active" ? "text-green-400" : status === "error" ? "text-red-400" : "text-gray-500";

  return (
    <div className="flex flex-col h-full bg-gray-800/80 border border-gray-700 rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 bg-gray-900/50 border-b border-gray-800 shrink-0">
        <StatusDot status={status} />
        <span className="font-medium text-sm text-gray-200">{agent.label}</span>
        <span className={`ml-auto text-[10px] uppercase tracking-wider ${statusTextColor}`}>{statusLabel}</span>
      </div>

      <div className="shrink-0 border-b border-gray-800/50">
        <button
          onClick={() => setPromptOpen(!promptOpen)}
          className="w-full flex items-center gap-1 px-3 py-1 text-[10px] text-gray-500 hover:text-gray-300 transition-colors"
        >
          <span className="text-gray-600">{promptOpen ? "\u25BC" : "\u25B6"}</span>
          <span>System Prompt</span>
          <span className="ml-auto text-gray-600">{agent.description}</span>
        </button>
        {promptOpen && (
          <div className="px-3 pb-2 text-[11px] text-gray-400 leading-relaxed bg-gray-900/30 max-h-32 overflow-y-auto">
            {agent.systemPrompt}
          </div>
        )}
      </div>

      <div
        ref={scrollRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto font-mono text-xs min-h-0"
      >
        {entries.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-600 py-8">
            No activity yet
          </div>
        ) : (
          <div className="p-1">
            {entries.map((entry, idx) => (
              <AgentLogEntry key={entry.event_id || idx} entry={entry} />
            ))}
          </div>
        )}
      </div>

      <div className="px-3 py-1 text-[10px] text-gray-600 border-t border-gray-800/50 shrink-0 text-right">
        {entries.length} {entries.length === 1 ? "entry" : "entries"}
      </div>
    </div>
  );
}

function ScaleControl({ type, count, onScale }) {
  return (
    <div className="flex items-center gap-1">
      <button
        onClick={() => onScale(type, count - 1)}
        disabled={count <= 1}
        className="w-5 h-5 flex items-center justify-center rounded text-xs font-bold bg-gray-700 text-gray-300 hover:bg-gray-600 disabled:opacity-30 disabled:cursor-not-allowed"
      >
        -
      </button>
      <span className="text-xs text-gray-300 font-mono w-3 text-center">{count}</span>
      <button
        onClick={() => onScale(type, count + 1)}
        disabled={count >= 3}
        className="w-5 h-5 flex items-center justify-center rounded text-xs font-bold bg-gray-700 text-gray-300 hover:bg-gray-600 disabled:opacity-30 disabled:cursor-not-allowed"
      >
        +
      </button>
    </div>
  );
}

export default function AgentsView({ audit }) {
  const [columns, setColumns] = useState(() => {
    return Number(localStorage.getItem("agents_columns")) || 2;
  });
  const [now, setNow] = useState(Date.now());
  const [agentCounts, setAgentCounts] = useState({ fixer: 2, reviewer: 1 });

  // Poll agent counts on mount
  useEffect(() => {
    fetch("/api/agents/counts").then(r => r.json()).then(setAgentCounts).catch(() => {});
  }, []);

  useEffect(() => {
    const interval = setInterval(() => setNow(Date.now()), 5000);
    return () => clearInterval(interval);
  }, []);

  const handleScale = useCallback((type, count) => {
    const clamped = Math.max(1, Math.min(3, count));
    setAgentCounts(prev => ({ ...prev, [type]: clamped }));
    fetch("/api/agents/scale", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ [type]: clamped }),
    }).catch(() => {});
  }, []);

  // Build the full agent list: singletons + scaled instances
  const allAgents = useMemo(() => {
    const agents = [...SINGLETON_AGENTS];
    for (const [type, meta] of Object.entries(SCALABLE_TYPES)) {
      const count = agentCounts[type] || 1;
      for (let i = 1; i <= count; i++) {
        agents.push({
          id: `${type}_${i}`,
          label: count > 1 ? `${meta.label} ${i}` : meta.label,
          type,
          description: meta.description,
          systemPrompt: meta.systemPrompt,
        });
      }
    }
    return agents;
  }, [agentCounts]);

  // Map audit entries to agent instances
  const entriesByAgent = useMemo(() => {
    const map = {};
    for (const a of allAgents) map[a.id] = [];

    for (const entry of audit) {
      const agentId = entry.agent;
      if (map[agentId]) {
        map[agentId].push(entry);
      } else if (agentId === "fixer" || agentId === "reviewer") {
        // Legacy entries without instance number → route to instance 1
        if (map[`${agentId}_1`]) map[`${agentId}_1`].push(entry);
      }
    }
    return map;
  }, [audit, allAgents]);

  const statusByAgent = useMemo(() => {
    const map = {};
    for (const a of allAgents) {
      map[a.id] = getAgentStatus(entriesByAgent[a.id] || [], now);
    }
    return map;
  }, [entriesByAgent, now, allAgents]);

  return (
    <div className="h-full flex flex-col">
      {/* Toolbar */}
      <div className="flex items-center gap-4 px-4 py-2 bg-gray-900/50 border-b border-gray-800 shrink-0 flex-wrap">
        {/* Singletons */}
        {SINGLETON_AGENTS.map(agent => (
          <div key={agent.id} className="flex items-center gap-1.5 text-xs">
            <StatusDot status={statusByAgent[agent.id]} />
            <span className="text-gray-200">{agent.label}</span>
          </div>
        ))}

        {/* Scalable agents with +/- */}
        {Object.entries(SCALABLE_TYPES).map(([type, meta]) => (
          <div key={type} className="flex items-center gap-2 text-xs border-l border-gray-700 pl-3">
            <span className="text-gray-200">{meta.label}</span>
            <ScaleControl type={type} count={agentCounts[type] || 1} onScale={handleScale} />
          </div>
        ))}

        {/* Column count */}
        <div className="ml-auto flex items-center gap-1.5">
          <span className="text-[10px] text-gray-500">Columns</span>
          <select
            value={columns}
            onChange={e => { const v = Number(e.target.value); setColumns(v); localStorage.setItem("agents_columns", v); }}
            className="bg-gray-800 border border-gray-700 rounded px-1.5 py-0.5 text-xs text-gray-300 focus:outline-none focus:border-blue-500"
          >
            {[1, 2, 3, 4].map(n => <option key={n} value={n}>{n}</option>)}
          </select>
        </div>

        {/* Summary counts */}
        <div className="flex gap-3 text-xs text-gray-500">
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-green-500" />
            {Object.values(statusByAgent).filter(s => s === "active").length} active
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-gray-600" />
            {Object.values(statusByAgent).filter(s => s === "idle").length} idle
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-red-500" />
            {Object.values(statusByAgent).filter(s => s === "error").length} error
          </span>
        </div>
      </div>

      {/* Agent panels */}
      <div className="flex-1 flex gap-3 p-3 overflow-x-auto min-h-0">
        {allAgents.map(agent => {
          const peekFraction = columns + 0.2;
          const gapPx = 12;
          return (
            <div
              key={agent.id}
              className="shrink-0 h-full"
              style={{ width: `calc(${100 / peekFraction}% - ${((columns - 1) * gapPx) / columns}px)` }}
            >
              <AgentPanel
                agent={agent}
                entries={entriesByAgent[agent.id] || []}
                status={statusByAgent[agent.id] || "idle"}
              />
            </div>
          );
        })}
      </div>
    </div>
  );
}
