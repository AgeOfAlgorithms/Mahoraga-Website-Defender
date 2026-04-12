import { useState, useRef, useEffect, useMemo, useCallback } from "react";

const SEVERITY_COLORS = {
  critical: "bg-red-900/60 border-l-4 border-red-500",
  high: "bg-orange-900/40 border-l-4 border-orange-500",
  medium: "bg-amber-900/30 border-l-4 border-amber-500",
  low: "bg-yellow-900/20 border-l-4 border-yellow-600",
  info: "",
};

const STATUS_COLORS = {
  200: "text-green-400",
  201: "text-green-400",
  301: "text-blue-400",
  302: "text-blue-400",
  400: "text-amber-400",
  401: "text-red-400",
  403: "text-red-400",
  404: "text-gray-500",
  500: "text-red-500",
};

const METHOD_COLORS = {
  GET: "text-emerald-400",
  POST: "text-blue-400",
  PUT: "text-amber-400",
  DELETE: "text-red-400",
  PATCH: "text-purple-400",
};

const HTTP_STATUS_NAMES = {
  200: "OK", 201: "Created", 204: "No Content",
  301: "Moved", 302: "Found", 304: "Not Modified",
  400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
  404: "Not Found", 405: "Method Not Allowed", 429: "Too Many Requests",
  500: "Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
};

export default function LogViewer({ prodLogs, shadowLogs, watcherPaths, analyzerTypes, events, audit }) {
  const [env, setEnv] = useState("all");
  const [expanded, setExpanded] = useState(new Set());
  const [autoScroll, setAutoScroll] = useState(true);
  const [filter, setFilter] = useState("");
  const scrollRef = useRef(null);

  // Merge all logs, tag shadow-only logs, then filter by env toggle
  const allLogs = useMemo(() => {
    // prodLogs come from access.log (have env field: "prod" or "shadow")
    // shadowLogs come from shadow.log (always shadow, have resp_body)
    // Combine: use prodLogs as primary, enrich with shadow resp_body where available
    const shadowByKey = {};
    for (const s of shadowLogs) {
      const key = `${s.time}|${s.method}|${s.path}`;
      shadowByKey[key] = s;
    }
    return prodLogs.map(entry => {
      const key = `${entry.time}|${entry.method}|${entry.path}`;
      const shadow = shadowByKey[key];
      if (shadow?.resp_body) {
        return { ...entry, resp_body: shadow.resp_body, req_body: shadow.req_body || entry.body };
      }
      return entry;
    });
  }, [prodLogs, shadowLogs]);

  const logs = useMemo(() => {
    if (env === "all") return allLogs;
    return allLogs.filter(l => (l.env || "prod") === env);
  }, [allLogs, env]);

  // Build a set of flagged request paths from events
  const eventsByPath = useMemo(() => {
    const map = {};
    for (const evt of events) {
      const path = evt.evidence?.request_path;
      if (path) {
        map[path] = evt;
      }
    }
    return map;
  }, [events]);

  // Build set of analyzer-flagged requests
  const analyzerFlagged = useMemo(() => {
    const set = new Set();
    for (const a of audit) {
      if (a.action === "shadow_exploit_detected" && a.detail) {
        // Extract request path from detail
        const match = a.detail.match(/request=(\S+)/);
        if (match) set.add(match[1]);
      }
    }
    return set;
  }, [audit]);

  // Auto-scroll
  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs.length, autoScroll]);

  const filteredLogs = useMemo(() => {
    const filtered = !filter ? logs : logs.filter(l => {
      const q = filter.toLowerCase();
      return (
        l.path?.toLowerCase().includes(q) ||
        l.method?.toLowerCase().includes(q) ||
        String(l.status).includes(q) ||
        l.ip?.includes(q)
      );
    });

    // Group consecutive identical requests (same method+path+ip+status)
    // Assign stable IDs based on content + sequence counter
    const grouped = [];
    const idCounts = {};
    for (const entry of filtered) {
      if (!entry._id) {
        const base = `${entry.time}|${entry.method}|${entry.path}|${entry.ip}|${entry.status}|${entry.env || "prod"}`;
        idCounts[base] = (idCounts[base] || 0) + 1;
        entry._id = `${base}#${idCounts[base]}`;
      }

      const last = grouped[grouped.length - 1];
      if (
        last && !last._group && !last._grouped &&
        last.method === entry.method &&
        last.path === entry.path &&
        last.ip === entry.ip &&
        last.status === entry.status &&
        last.env === entry.env
      ) {
        const group = {
          ...entry,
          _id: `group_${last._id}`,
          _group: true,
          _count: 2,
          _firstTime: last.time,
          _lastTime: entry.time,
          _samples: [last, entry],
        };
        grouped[grouped.length - 1] = group;
      } else if (last?._group &&
        last.method === entry.method &&
        last.path === entry.path &&
        last.ip === entry.ip &&
        last.status === entry.status &&
        last.env === entry.env
      ) {
        last._count++;
        last._lastTime = entry.time;
        if (last._samples.length < 5) last._samples.push(entry);
      } else {
        grouped.push(entry);
      }
    }
    return grouped;
  }, [logs, filter]);

  const toggleExpand = (idx) => {
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(idx) ? next.delete(idx) : next.add(idx);
      return next;
    });
  };

  const getRowClass = (entry) => {
    // Check if analyzer flagged this (red)
    if (analyzerFlagged.has(entry.path)) {
      return "bg-red-950/50 border-l-4 border-red-500";
    }
    // Check if watcher flagged this (amber)
    const evt = eventsByPath[entry.path];
    if (evt) {
      const sev = evt.severity?.toLowerCase?.() || evt.severity;
      return SEVERITY_COLORS[sev] || "bg-amber-900/30 border-l-4 border-amber-500";
    }
    // Honeypot paths (purple)
    if (entry.path?.includes("v3/admin") || entry.path?.includes("debug/") ||
        entry.path?.includes("internal/") || entry.path?.includes(".env") ||
        entry.path?.includes(".git") || entry.path?.includes("wp-admin")) {
      return "bg-purple-950/30 border-l-4 border-purple-500";
    }
    return "";
  };

  return (
    <div className="h-full flex flex-col">
      {/* Toolbar */}
      <div className="flex items-center gap-3 px-4 py-2 bg-gray-900/50 border-b border-gray-800 shrink-0">
        <div className="flex rounded overflow-hidden border border-gray-700">
          {[
            { id: "all", label: "ALL", count: allLogs.length, active: "bg-gray-600" },
            { id: "prod", label: "PROD", count: allLogs.filter(l => l.env === "prod").length, active: "bg-blue-600" },
            { id: "shadow", label: "SHADOW", count: allLogs.filter(l => l.env === "shadow").length, active: "bg-purple-600" },
          ].map(btn => (
            <button
              key={btn.id}
              onClick={() => setEnv(btn.id)}
              className={`px-3 py-1 text-xs font-medium ${
                env === btn.id ? `${btn.active} text-white` : "bg-gray-800 text-gray-400 hover:text-white"
              }`}
            >
              {btn.label} ({btn.count})
            </button>
          ))}
        </div>

        <input
          type="text"
          placeholder="Filter by path, method, status, IP..."
          value={filter}
          onChange={e => setFilter(e.target.value)}
          className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-1 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />

        <label className="flex items-center gap-1.5 text-xs text-gray-400 cursor-pointer">
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={e => setAutoScroll(e.target.checked)}
            className="rounded"
          />
          Auto-scroll
        </label>

        {/* Legend */}
        <div className="flex gap-3 text-xs text-gray-500 ml-2">
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded bg-amber-500" /> Watcher</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded bg-red-500" /> Analyzer</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded bg-purple-500" /> Honeypot</span>
        </div>
      </div>

      {/* Log entries */}
      {env === "all" ? (
        /* Split screen for ALL view */
        <div className="flex-1 flex min-h-0">
          <LogPanel
            title="PROD"
            titleColor="text-blue-400"
            logs={filteredLogs.filter(l => (l.env || "prod") === "prod")}
            expanded={expanded}
            toggleExpand={toggleExpand}
            getRowClass={getRowClass}
            eventsByPath={eventsByPath}
            autoScroll={autoScroll}
            side="left"
          />
          <div className="w-px bg-gray-700 shrink-0" />
          <LogPanel
            title="SHADOW"
            titleColor="text-purple-400"
            logs={filteredLogs.filter(l => l.env === "shadow")}
            expanded={expanded}
            toggleExpand={toggleExpand}
            getRowClass={getRowClass}
            eventsByPath={eventsByPath}
            autoScroll={autoScroll}
            side="right"
          />
        </div>
      ) : (
        /* Single pane for PROD or SHADOW */
        <div ref={scrollRef} className="flex-1 overflow-y-auto font-mono text-xs">
          <LogList
            logs={filteredLogs}
            expanded={expanded}
            toggleExpand={toggleExpand}
            getRowClass={getRowClass}
            eventsByPath={eventsByPath}
          />
        </div>
      )}
    </div>
  );
}

function LogRow({ entry, idx, expanded, toggleExpand, getRowClass, eventsByPath }) {
  const isGroup = entry._group;
  const isExpanded = expanded.has(idx);

  return (
    <div className={`${entry._new ? "log-entry-new" : ""}`}>
      <div
        onClick={() => toggleExpand(idx)}
        className={`flex items-center gap-2 px-4 py-1 cursor-pointer hover:bg-gray-800/50 ${getRowClass(entry)}`}
      >
        <span className="text-gray-600 w-20 shrink-0">{entry.time?.match(/(\d{2}:\d{2}:\d{2})/)?.[1] || ""}</span>
        <span className={`w-10 shrink-0 font-bold ${METHOD_COLORS[entry.method] || "text-gray-400"}`}>
          {entry.method}
        </span>
        <span className={`w-8 shrink-0 ${STATUS_COLORS[entry.status] || "text-gray-400"}`}>
          {entry.status}
        </span>
        <span className="flex-1 truncate text-gray-300">
          {entry.path}
          {isGroup && (
            <span className="ml-2 px-1.5 py-0.5 rounded bg-amber-900/60 text-amber-300 text-[10px] font-bold">
              {"\u00D7"}{entry._count}
            </span>
          )}
        </span>
        <span className="text-gray-600 w-32 shrink-0 text-right">{entry.ip}</span>
        <span className="text-gray-700 w-4">{isExpanded ? "\u25BC" : "\u25B6"}</span>
      </div>

      {isExpanded && !isGroup && (
        <div className="px-8 py-2 bg-gray-900/80 border-b border-gray-800 space-y-2">
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px]">
            <KeyVal k="Method" v={entry.method} color={METHOD_COLORS[entry.method]} />
            <KeyVal k="Status" v={`${entry.status} ${HTTP_STATUS_NAMES[entry.status] || ""}`} color={STATUS_COLORS[entry.status]} />
            <KeyVal k="URL" v={entry.path} />
            <KeyVal k="IP" v={entry.ip} />
            <KeyVal k="Env" v={entry.env} color={entry.env === "shadow" ? "text-purple-400" : "text-gray-400"} />
            {entry.response_time != null && <KeyVal k="Time" v={`${entry.response_time}s`} />}
            {entry.bytes != null && <KeyVal k="Size" v={`${entry.bytes}B`} />}
          </div>
          {entry.user_agent && <Detail label="User-Agent" value={entry.user_agent} />}
          {entry.auth && <Detail label="Auth" value={entry.auth} />}
          {(entry.body || entry.req_body) && <Detail label="Request Body" value={entry.body || entry.req_body} json />}
          {entry.resp_body && <Detail label="Response Body" value={entry.resp_body} json />}
          {entry.referer && <Detail label="Referer" value={entry.referer} />}
          {eventsByPath[entry.path] && (
            <div className="mt-2 p-2 rounded bg-amber-950/40 border border-amber-800">
              <span className="text-amber-400 font-bold text-[10px] uppercase">Watcher Alert: </span>
              <span className="text-amber-200">
                {eventsByPath[entry.path].event_type} [{eventsByPath[entry.path].severity}]
              </span>
            </div>
          )}
        </div>
      )}

      {isExpanded && isGroup && (
        <div className="px-4 py-2 bg-gray-900/80 border-b border-gray-800 space-y-1">
          <div className="flex items-center gap-3 text-[11px] text-gray-400 mb-2">
            <span className="font-bold text-amber-400">{entry._count} repeated requests</span>
            <span>{entry._firstTime?.match(/(\d{2}:\d{2}:\d{2})/)?.[1]} — {entry._lastTime?.match(/(\d{2}:\d{2}:\d{2})/)?.[1]}</span>
            <span className="text-gray-600">{entry.method} {entry.path} → {entry.status}</span>
          </div>
          <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Latest samples</div>
          {entry._samples.map((s, i) => (
            <div key={i} className="flex gap-2 px-2 py-0.5 text-[11px] bg-gray-950/50 rounded">
              <span className="text-gray-600 w-16 shrink-0">{s.time?.match(/(\d{2}:\d{2}:\d{2})/)?.[1]}</span>
              <span className={`w-6 shrink-0 ${STATUS_COLORS[s.status]}`}>{s.status}</span>
              {(s.body || s.req_body) && (
                <span className="text-gray-400 truncate">{s.body || s.req_body}</span>
              )}
              {s.auth && !s.body && !s.req_body && (
                <span className="text-gray-500 truncate">{s.auth}</span>
              )}
              {!s.body && !s.req_body && !s.auth && (
                <span className="text-gray-600">—</span>
              )}
            </div>
          ))}
          {entry._count > entry._samples.length && (
            <div className="text-[10px] text-gray-600 px-2">
              ... and {entry._count - entry._samples.length} more
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function LogList({ logs, expanded, toggleExpand, getRowClass, eventsByPath }) {
  if (logs.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-gray-600">
        Waiting for log entries...
      </div>
    );
  }
  return logs.map((entry) => (
    <LogRow
      key={entry._id}
      entry={entry}
      idx={entry._id}
      expanded={expanded}
      toggleExpand={toggleExpand}
      getRowClass={getRowClass}
      eventsByPath={eventsByPath}
    />
  ));
}

function LogPanel({ title, titleColor, logs, expanded, toggleExpand, getRowClass, eventsByPath, autoScroll }) {
  const ref = useRef(null);
  const isAtBottom = useRef(true);

  const handleScroll = useCallback(() => {
    const el = ref.current;
    if (!el) return;
    isAtBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
  }, []);

  useEffect(() => {
    if (autoScroll && isAtBottom.current && ref.current) {
      ref.current.scrollTop = ref.current.scrollHeight;
    }
  }, [logs.length, autoScroll]);

  return (
    <div className="flex-1 flex flex-col min-h-0 min-w-0">
      <div className={`px-3 py-1 text-[10px] font-bold uppercase tracking-wider ${titleColor} bg-gray-900/60 border-b border-gray-800 shrink-0 flex items-center justify-between`}>
        <span>{title}</span>
        <span className="text-gray-500 font-mono font-normal">{logs.length}</span>
      </div>
      <div ref={ref} onScroll={handleScroll} className="flex-1 overflow-y-auto font-mono text-xs">
        <LogList
          logs={logs}
          expanded={expanded}
          toggleExpand={toggleExpand}
          getRowClass={getRowClass}
          eventsByPath={eventsByPath}
        />
      </div>
    </div>
  );
}

function Detail({ label, value, json }) {
  let display = value;
  if (json && typeof value === "string") {
    try {
      display = JSON.stringify(JSON.parse(value), null, 2);
    } catch {
      display = value;
    }
  }

  return (
    <div>
      <span className="text-gray-500 text-[10px] uppercase tracking-wider">{label}</span>
      <pre className="text-gray-300 mt-0.5 whitespace-pre-wrap break-all text-[11px] bg-gray-950 rounded p-1.5 max-h-40 overflow-auto">
        {display}
      </pre>
    </div>
  );
}

function KeyVal({ k, v, color }) {
  return (
    <span>
      <span className="text-gray-500">{k}: </span>
      <span className={color || "text-gray-300"}>{v}</span>
    </span>
  );
}
