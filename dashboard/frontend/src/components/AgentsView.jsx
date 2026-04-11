import { useState, useRef, useEffect, useMemo, useCallback } from "react";

const AGENTS = [
  {
    id: "watcher",
    label: "Watcher",
    description: "Scans nginx logs every 4s",
    systemPrompt: "Rule-based pattern matching on nginx access logs. Detects: SQL injection, XSS, path traversal, command injection, NoSQL injection, prototype pollution. Tracks per-IP sessions for sequential ID enumeration, multi-resource access, 404 probing, and rate limiting. No LLM — free and instant.",
  },
  {
    id: "shadow_analyzer",
    label: "Shadow Analyzer",
    description: "LLM reads shadow logs every 15s",
    systemPrompt: "You are a security analyst monitoring a web application's shadow environment. Attackers have been redirected here — every request you see is from a suspected attacker. Your job: determine if any request-response pair shows a SUCCESSFUL attack. Not just attempts — look for evidence that the attacker actually GOT something they shouldn't have. Look for: data leakage, privilege escalation, injection success, business logic abuse, credential theft, SSRF success.",
  },
  {
    id: "fixer",
    label: "Fixer",
    description: "GLM patches vulnerabilities in Docker",
    systemPrompt: "You are a security engineer patching ONE specific vulnerability in a RUNNING web application. All file reads and edits must use docker exec — never direct file access. Fix ONLY the vulnerability described. Do NOT fix other bugs. Make the MINIMUM change necessary. Sandboxed: only docker exec into crapi-workshop, shadow-workshop, nginx-proxy allowed.",
  },
  {
    id: "reviewer",
    label: "Reviewer",
    description: "GLM reviews patches",
    systemPrompt: "You are a strict security reviewer. Check: 1) Does the patch fix the vulnerability? 2) Does it introduce new security issues? 3) Could it break existing functionality? 4) SCOPE CHECK: REJECT if it also fixes other bugs, adds comments, refactors code, or makes changes not directly needed. Sandboxed: only docker exec verification allowed.",
  },
];

const LEVEL_COLORS = {
  critical: "text-red-400",
  error: "text-red-400",
  warning: "text-amber-400",
  info: "text-blue-400",
  success: "text-green-400",
  default: "text-gray-400",
};

const STALE_THRESHOLD_MS = 30_000;

function classifyLevel(entry) {
  const detail = (entry.detail || "").toLowerCase();
  const action = (entry.action || "").toLowerCase();
  if (detail.includes("error") || detail.includes("failed") || action.includes("error")) return "error";
  if (detail.includes("critical")) return "critical";
  if (detail.includes("warning") || action.includes("warning")) return "warning";
  if (action.includes("success") || action.includes("applied") || action.includes("approved") || action.includes("passed")) return "success";
  return "info";
}

function getAgentStatus(entries, now) {
  if (entries.length === 0) return "idle";
  const last = entries[entries.length - 1];
  const detail = (last.detail || "").toLowerCase();
  if (detail.includes("error") || detail.includes("failed")) return "error";
  // timestamp is unix seconds
  const ts = (last.timestamp || 0) * 1000;
  if (now - ts < STALE_THRESHOLD_MS) return "active";
  return "idle";
}

function formatTime(timestamp) {
  if (!timestamp) return "";
  // Unix seconds → Date
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

  const statusLabel = status === "active" ? "Active" : status === "error" ? "Error" : "Idle";
  const statusTextColor = status === "active" ? "text-green-400" : status === "error" ? "text-red-400" : "text-gray-500";

  return (
    <div className="flex flex-col h-full bg-gray-800/80 border border-gray-700 rounded-lg overflow-hidden">
      {/* Panel header */}
      <div className="flex items-center gap-2 px-3 py-2 bg-gray-900/50 border-b border-gray-800 shrink-0">
        <StatusDot status={status} />
        <span className="font-medium text-sm text-gray-200">{agent.label}</span>
        <span className={`ml-auto text-[10px] uppercase tracking-wider ${statusTextColor}`}>{statusLabel}</span>
      </div>

      {/* System prompt (collapsible) */}
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

      {/* Log area */}
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
            {entries.map((entry, idx) => {
              const level = classifyLevel(entry);
              const levelColor = LEVEL_COLORS[level] || LEVEL_COLORS.default;
              return (
                <div key={entry.event_id || idx} className="flex gap-2 px-2 py-0.5 hover:bg-gray-700/30 rounded">
                  <span className="text-gray-600 shrink-0 w-16">{formatTime(entry.timestamp)}</span>
                  <span className={`shrink-0 w-16 uppercase text-[10px] leading-4 font-semibold ${levelColor}`}>{level}</span>
                  <span className="text-gray-300 break-all">
                    <span className="text-gray-500">{entry.action}</span>
                    {entry.detail && <span className="ml-1.5">{entry.detail}</span>}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Entry count footer */}
      <div className="px-3 py-1 text-[10px] text-gray-600 border-t border-gray-800/50 shrink-0 text-right">
        {entries.length} {entries.length === 1 ? "entry" : "entries"}
      </div>
    </div>
  );
}

export default function AgentsView({ audit }) {
  const [visible, setVisible] = useState(() => {
    try {
      const saved = localStorage.getItem("agents_visible");
      return saved ? new Set(JSON.parse(saved)) : new Set(AGENTS.map(a => a.id));
    } catch { return new Set(AGENTS.map(a => a.id)); }
  });
  const [columns, setColumns] = useState(() => {
    return Number(localStorage.getItem("agents_columns")) || 2;
  });
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const interval = setInterval(() => setNow(Date.now()), 5000);
    return () => clearInterval(interval);
  }, []);

  const entriesByAgent = useMemo(() => {
    const map = {};
    for (const a of AGENTS) map[a.id] = [];
    for (const entry of audit) {
      const agentId = entry.agent;
      if (map[agentId]) map[agentId].push(entry);
    }
    return map;
  }, [audit]);

  const statusByAgent = useMemo(() => {
    const map = {};
    for (const a of AGENTS) {
      map[a.id] = getAgentStatus(entriesByAgent[a.id], now);
    }
    return map;
  }, [entriesByAgent, now]);

  const toggleAgent = useCallback((id) => {
    setVisible(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        if (next.size > 1) next.delete(id);
      } else {
        next.add(id);
      }
      localStorage.setItem("agents_visible", JSON.stringify([...next]));
      return next;
    });
  }, []);

  const visibleAgents = AGENTS.filter(a => visible.has(a.id));

  return (
    <div className="h-full flex flex-col">
      {/* Toolbar */}
      <div className="flex items-center gap-3 px-4 py-2 bg-gray-900/50 border-b border-gray-800 shrink-0 flex-wrap">
        <span className="text-xs text-gray-500 uppercase tracking-wider mr-1">Agents</span>

        {AGENTS.map(agent => (
          <label
            key={agent.id}
            className="flex items-center gap-1.5 text-xs cursor-pointer select-none"
          >
            <input
              type="checkbox"
              checked={visible.has(agent.id)}
              onChange={() => toggleAgent(agent.id)}
              className="rounded border-gray-600 bg-gray-800 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
            />
            <StatusDot status={statusByAgent[agent.id]} />
            <span className={visible.has(agent.id) ? "text-gray-200" : "text-gray-500"}>
              {agent.label}
            </span>
          </label>
        ))}

        {/* Column count */}
        <div className="ml-auto flex items-center gap-1.5">
          <span className="text-[10px] text-gray-500">Columns</span>
          <select
            value={columns}
            onChange={e => { const v = Number(e.target.value); setColumns(v); localStorage.setItem("agents_columns", v); }}
            className="bg-gray-800 border border-gray-700 rounded px-1.5 py-0.5 text-xs text-gray-300 focus:outline-none focus:border-blue-500"
          >
            <option value={1}>1</option>
            <option value={2}>2</option>
            <option value={3}>3</option>
            <option value={4}>4</option>
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

      {/* Agent panels — horizontal scroll, peek next card to hint scrollability */}
      <div className="flex-1 flex gap-3 p-3 overflow-x-auto min-h-0">
        {visibleAgents.map(agent => {
          // Show `columns` cards + 1/5 of the next card visible as a peek hint
          // Total visible width = columns + 0.2 cards worth
          // Each card width = container / (columns + 0.2) minus gap
          const peekFraction = columns + 0.2;
          const gapPx = 12; // gap-3 = 12px
          return (
            <div
              key={agent.id}
              className="shrink-0 h-full"
              style={{ width: `calc(${100 / peekFraction}% - ${((columns - 1) * gapPx) / columns}px)` }}
            >
              <AgentPanel
                agent={agent}
                entries={entriesByAgent[agent.id]}
                status={statusByAgent[agent.id]}
              />
            </div>
          );
        })}
      </div>
    </div>
  );
}
