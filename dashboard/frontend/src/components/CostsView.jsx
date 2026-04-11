import { useState, useEffect } from "react";

const AGENT_COLORS = {
  shadow_analyzer: "bg-purple-500",
  fixer: "bg-amber-500",
  reviewer: "bg-blue-500",
  unknown: "bg-gray-500",
};

const AGENT_LABELS = {
  shadow_analyzer: "Shadow Analyzer",
  fixer: "Fixer",
  reviewer: "Reviewer",
  unknown: "Other",
};

export default function CostsView() {
  const [costs, setCosts] = useState(null);

  useEffect(() => {
    const fetchCosts = () => {
      fetch("/api/costs").then(r => r.json()).then(setCosts).catch(() => {});
    };
    fetchCosts();
    const interval = setInterval(fetchCosts, 10000);
    return () => clearInterval(interval);
  }, []);

  if (!costs) {
    return (
      <div className="flex items-center justify-center h-full text-gray-600">
        Loading costs...
      </div>
    );
  }

  const { daily_spend, daily_budget, by_agent, incident_count, paused } = costs;
  const budgetPct = daily_budget > 0 ? (daily_spend / daily_budget) * 100 : 0;
  const sortedAgents = Object.entries(by_agent).sort((a, b) => b[1] - a[1]);
  const maxAgentCost = sortedAgents.length > 0 ? sortedAgents[0][1] : 1;

  return (
    <div className="h-full flex flex-col p-6 overflow-y-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-bold text-gray-200">API Costs</h2>
        {paused && (
          <span className="px-3 py-1 bg-red-900 text-red-300 rounded text-xs font-bold uppercase">
            Circuit Breaker Active
          </span>
        )}
      </div>

      {/* Daily budget overview */}
      <div className="bg-gray-800/80 border border-gray-700 rounded-lg p-5 mb-6">
        <div className="flex items-end justify-between mb-2">
          <div>
            <div className="text-[10px] text-gray-500 uppercase tracking-wider">Daily Spend</div>
            <div className="text-3xl font-bold text-gray-100">${daily_spend.toFixed(2)}</div>
          </div>
          <div className="text-right">
            <div className="text-[10px] text-gray-500 uppercase tracking-wider">Budget</div>
            <div className="text-lg text-gray-400">${daily_budget.toFixed(2)}</div>
          </div>
        </div>
        <div className="w-full bg-gray-900 rounded-full h-3 overflow-hidden">
          <div
            className={`h-full rounded-full transition-all ${
              budgetPct > 80 ? "bg-red-500" : budgetPct > 50 ? "bg-amber-500" : "bg-green-500"
            }`}
            style={{ width: `${Math.min(100, budgetPct)}%` }}
          />
        </div>
        <div className="flex justify-between mt-1 text-[10px] text-gray-600">
          <span>{budgetPct.toFixed(1)}% used</span>
          <span>${(daily_budget - daily_spend).toFixed(2)} remaining</span>
        </div>
      </div>

      {/* Per-agent breakdown */}
      <div className="bg-gray-800/80 border border-gray-700 rounded-lg p-5 mb-6">
        <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-4">Cost by Agent</div>
        {sortedAgents.length === 0 ? (
          <div className="text-gray-600 text-sm">No API costs recorded yet</div>
        ) : (
          <div className="space-y-3">
            {sortedAgents.map(([agent, cost]) => {
              const pct = maxAgentCost > 0 ? (cost / maxAgentCost) * 100 : 0;
              const color = AGENT_COLORS[agent] || AGENT_COLORS.unknown;
              const label = AGENT_LABELS[agent] || agent;
              return (
                <div key={agent}>
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span className={`w-2.5 h-2.5 rounded-sm ${color}`} />
                      <span className="text-sm text-gray-300">{label}</span>
                    </div>
                    <span className="text-sm font-mono text-gray-200">${cost.toFixed(4)}</span>
                  </div>
                  <div className="w-full bg-gray-900 rounded-full h-2 overflow-hidden">
                    <div
                      className={`h-full rounded-full ${color} opacity-70`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-gray-800/80 border border-gray-700 rounded-lg p-4">
          <div className="text-[10px] text-gray-500 uppercase tracking-wider">Incidents</div>
          <div className="text-2xl font-bold text-gray-200 mt-1">{incident_count}</div>
        </div>
        <div className="bg-gray-800/80 border border-gray-700 rounded-lg p-4">
          <div className="text-[10px] text-gray-500 uppercase tracking-wider">Avg Cost / Incident</div>
          <div className="text-2xl font-bold text-gray-200 mt-1">
            ${incident_count > 0 ? (daily_spend / incident_count).toFixed(3) : "0.00"}
          </div>
        </div>
        <div className="bg-gray-800/80 border border-gray-700 rounded-lg p-4">
          <div className="text-[10px] text-gray-500 uppercase tracking-wider">Est. Hourly Rate</div>
          <div className="text-2xl font-bold text-gray-200 mt-1">
            ${(daily_spend > 0 ? daily_spend * (24 / Math.max(1, (Date.now() / 1000 - (costs._day_start || Date.now() / 1000)) / 3600)) : 0).toFixed(2)}/hr
          </div>
        </div>
      </div>
    </div>
  );
}
