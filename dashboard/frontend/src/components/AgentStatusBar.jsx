import { useState, useEffect, useMemo, useCallback } from "react";

const SINGLETON_AGENTS = [
  { id: "watcher", label: "Watcher", type: "watcher" },
  { id: "shadow_analyzer", label: "Shadow Analyzer", type: "shadow_analyzer" },
];

const SCALABLE_TYPES = {
  fixer: { label: "Fixer" },
  reviewer: { label: "Reviewer" },
};

const STALE_THRESHOLD_MS = 20_000;
const HUNG_THRESHOLD_S = 90; // seconds without API response = likely hung

function StatusDot({ status, title }) {
  const color =
    status === "active" ? "bg-green-500" :
    status === "hung" ? "bg-orange-500 animate-pulse" :
    status === "error" ? "bg-red-500" :
    "bg-gray-600";
  return <span title={title} className={`inline-block w-2.5 h-2.5 rounded-full ${color}`} />;
}

function getAgentStatus(entries, now, agentType, heartbeat) {
  if (agentType === "watcher") return "active";
  if (entries.length === 0) return "idle";
  const last = entries[entries.length - 1];
  const action = (last.action || "").toLowerCase();
  // Success actions take priority
  const isSuccess = action === "patch_proposed" || action.includes("deployed") || action.includes("approved");
  if (!isSuccess && (action.includes("error") || action === "patch_failed" || action === "patch_abandoned")) return "error";
  const ts = (last.timestamp || 0) * 1000;
  const isRecent = now - ts < STALE_THRESHOLD_MS;

  // Check heartbeat: if agent is supposed to be active but hasn't gotten
  // an API response in a while, it's likely hung
  if (heartbeat && heartbeat.last_response) {
    const secsSinceResponse = (now / 1000) - heartbeat.last_response;
    if (secsSinceResponse > HUNG_THRESHOLD_S && isRecent) {
      return "hung";
    }
  }

  if (isRecent) return "active";
  return "idle";
}

function formatHeartbeat(heartbeat, nowMs) {
  if (!heartbeat || !heartbeat.last_response) return "";
  const secsAgo = Math.round((nowMs / 1000) - heartbeat.last_response);
  const turn = heartbeat.turn || 0;
  const maxTurns = heartbeat.max_turns || 0;
  return `Turn ${turn}/${maxTurns}, last response ${secsAgo}s ago`;
}

export default function AgentStatusBar({ audit }) {
  const [now, setNow] = useState(Date.now());
  const [agentCounts, setAgentCounts] = useState({ fixer: 2, reviewer: 1 });
  const [heartbeats, setHeartbeats] = useState({});

  useEffect(() => {
    fetch("/api/agents/counts").then(r => r.json()).then(setAgentCounts).catch(() => {});
  }, []);

  // Poll heartbeats every 5s
  useEffect(() => {
    const poll = () => {
      fetch("/api/agents/heartbeats").then(r => r.json()).then(setHeartbeats).catch(() => {});
    };
    poll();
    const interval = setInterval(poll, 5000);
    return () => clearInterval(interval);
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

  // Build all agent instances
  const allAgents = useMemo(() => {
    const agents = [...SINGLETON_AGENTS];
    for (const [type, meta] of Object.entries(SCALABLE_TYPES)) {
      const count = agentCounts[type] || 1;
      for (let i = 1; i <= count; i++) {
        agents.push({ id: `${type}_${i}`, label: `${meta.label} ${i}`, type });
      }
    }
    return agents;
  }, [agentCounts]);

  // Route audit entries to agents
  const entriesByAgent = useMemo(() => {
    const map = {};
    for (const a of allAgents) map[a.id] = [];
    for (const entry of audit) {
      const agent = entry.agent || "";
      if (map[agent]) {
        map[agent].push(entry);
      } else if (agent === "fixer" || agent === "reviewer") {
        if (map[`${agent}_1`]) map[`${agent}_1`].push(entry);
      }
    }
    return map;
  }, [audit, allAgents]);

  const statusByAgent = useMemo(() => {
    const map = {};
    for (const a of allAgents) {
      map[a.id] = getAgentStatus(
        entriesByAgent[a.id] || [], now, a.type,
        heartbeats[a.id]
      );
    }
    return map;
  }, [entriesByAgent, now, allAgents, heartbeats]);

  return (
    <div className="flex items-center gap-5 px-4 py-2.5 bg-gray-900/50 border-b border-gray-800 shrink-0 flex-wrap">
      {SINGLETON_AGENTS.map(agent => (
        <div key={agent.id} className="flex items-center gap-1.5 text-xs">
          <span className="text-gray-400">{agent.label}</span>
          <StatusDot status={statusByAgent[agent.id]} />
        </div>
      ))}

      {Object.entries(SCALABLE_TYPES).map(([type, meta]) => {
        const count = agentCounts[type] || 1;
        return (
          <div key={type} className="flex items-center gap-1.5 text-xs border-l border-gray-700 pl-3">
            <button
              onClick={() => handleScale(type, count - 1)}
              disabled={count <= 1}
              className="w-5 h-5 flex items-center justify-center rounded text-xs font-bold bg-gray-700 text-gray-300 hover:bg-gray-600 disabled:opacity-30 disabled:cursor-not-allowed"
            >-</button>
            <span className="text-gray-400">{meta.label}</span>
            <span className="flex items-center gap-0.5">
              {Array.from({ length: count }, (_, i) => {
                const agentId = `${type}_${i + 1}`;
                return (
                  <StatusDot
                    key={i}
                    status={statusByAgent[agentId] || "idle"}
                    title={formatHeartbeat(heartbeats[agentId], now)}
                  />
                );
              })}
            </span>
            <button
              onClick={() => handleScale(type, count + 1)}
              disabled={count >= 3}
              className="w-5 h-5 flex items-center justify-center rounded text-xs font-bold bg-gray-700 text-gray-300 hover:bg-gray-600 disabled:opacity-30 disabled:cursor-not-allowed"
            >+</button>
          </div>
        );
      })}

      <div className="ml-auto flex gap-3 text-xs text-gray-500">
        <span className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
          {Object.values(statusByAgent).filter(s => s === "active").length} active
        </span>
        <span className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-orange-500" />
          {Object.values(statusByAgent).filter(s => s === "hung").length} hung
        </span>
        <span className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-gray-600" />
          {Object.values(statusByAgent).filter(s => s === "idle").length} idle
        </span>
        <span className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
          {Object.values(statusByAgent).filter(s => s === "error").length} error
        </span>
      </div>
    </div>
  );
}
