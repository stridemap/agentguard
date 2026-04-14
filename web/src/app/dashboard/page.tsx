"use client";

import { useCallback, useEffect, useState } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import EventTable from "@/components/EventTable";
import MetricCard from "@/components/MetricCard";
import type { AgentEvent, HealthStatus } from "@/lib/api";
import { api } from "@/lib/api";

const REFRESH_INTERVAL = 5000; // 5s polling
const RISK_COLORS = ["#00D4AA", "#F59E0B", "#EF4444", "#EF4444"];

function parseFlags(raw: string): string[] {
  try {
    const p = JSON.parse(raw);
    return Array.isArray(p) ? p : [];
  } catch {
    return [];
  }
}

export default function DashboardPage() {
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Filters
  const [filterAgent, setFilterAgent] = useState("");
  const [filterTool, setFilterTool] = useState("");

  const fetchData = useCallback(async () => {
    try {
      const [h, e] = await Promise.all([
        api.health(),
        api.isAuthenticated()
          ? api.queryEvents({
              ...(filterAgent ? { agent_id: filterAgent } : {}),
              ...(filterTool ? { tool_name: filterTool } : {}),
            })
          : Promise.resolve([]),
      ]);
      setHealth(h);
      setEvents(e);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch data");
    } finally {
      setLoading(false);
    }
  }, [filterAgent, filterTool]);

  useEffect(() => {
    fetchData();
    if (!autoRefresh) return;
    const interval = setInterval(fetchData, REFRESH_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchData, autoRefresh]);

  // Compute metrics
  const totalEvents = health?.event_count || events.length;
  const latencies = events.map((e) => e.latency_ms).filter((l): l is number => l != null);
  const p99 = latencies.length > 0 ? latencies.sort((a, b) => a - b)[Math.floor(latencies.length * 0.99)] : 0;
  const blocked = events.filter((e) => e.policy_result === "BLOCK").length;
  const flagged = events.filter((e) => {
    const flags = parseFlags(e.risk_flags);
    return flags.length > 0;
  }).length;

  // Chart data: events by tool
  const toolCounts: Record<string, number> = {};
  events.forEach((e) => {
    toolCounts[e.tool_name] = (toolCounts[e.tool_name] || 0) + 1;
  });
  const toolChartData = Object.entries(toolCounts).map(([name, count]) => ({ name, count }));

  // Chart data: policy distribution
  const policyCounts: Record<string, number> = {};
  events.forEach((e) => {
    policyCounts[e.policy_result] = (policyCounts[e.policy_result] || 0) + 1;
  });
  const policyChartData = Object.entries(policyCounts).map(([name, value]) => ({ name, value }));
  const pieColors: Record<string, string> = {
    ALLOW: "#00D4AA",
    ALERT: "#F59E0B",
    BLOCK: "#EF4444",
    BYPASS: "#64748B",
    PENDING: "#94A3B8",
  };

  // Unique values for filters
  const agents = [...new Set(events.map((e) => e.agent_id))];
  const tools = [...new Set(events.map((e) => e.tool_name))];

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-bold">Live Event Feed</h1>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-sm text-text-secondary">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="rounded"
            />
            Auto-refresh
          </label>
          <span className="text-xs text-text-muted">
            {health ? `v${health.version} | ${health.status}` : "connecting..."}
          </span>
        </div>
      </div>

      {error && (
        <div className="mb-4 rounded-lg border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger">
          {error}. Make sure the API is running and you&apos;re authenticated.
        </div>
      )}

      {/* Metric cards */}
      <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-4">
        <MetricCard label="Total Events" value={totalEvents.toLocaleString()} />
        <MetricCard
          label="Latency p99"
          value={`${p99.toFixed(1)} ms`}
          delta={p99 < 50 ? "Within SLA" : "Above SLA"}
          deltaColor={p99 < 50 ? "green" : "red"}
        />
        <MetricCard
          label="Blocked"
          value={blocked}
          delta={blocked > 0 ? `${blocked} threats stopped` : "No blocks"}
          deltaColor={blocked > 0 ? "red" : "green"}
        />
        <MetricCard
          label="Risk Flagged"
          value={flagged}
          delta={`${events.length > 0 ? Math.round((flagged / events.length) * 100) : 0}% of events`}
          deltaColor={flagged > events.length * 0.3 ? "amber" : "green"}
        />
      </div>

      {/* Charts */}
      {events.length > 0 && (
        <div className="mb-6 grid gap-4 md:grid-cols-2">
          <div className="rounded-xl border border-border bg-surface-raised p-4">
            <h3 className="mb-3 text-sm font-semibold text-text-secondary">Events by Tool</h3>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={toolChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" />
                <XAxis dataKey="name" tick={{ fill: "#94A3B8", fontSize: 11 }} />
                <YAxis tick={{ fill: "#94A3B8", fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#111827", border: "1px solid #1E293B", borderRadius: "8px" }}
                  labelStyle={{ color: "#F1F5F9" }}
                />
                <Bar dataKey="count" fill="#00D4AA" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="rounded-xl border border-border bg-surface-raised p-4">
            <h3 className="mb-3 text-sm font-semibold text-text-secondary">Policy Decisions</h3>
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={policyChartData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`}
                >
                  {policyChartData.map((entry) => (
                    <Cell key={entry.name} fill={pieColors[entry.name] || "#64748B"} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: "#111827", border: "1px solid #1E293B", borderRadius: "8px" }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="mb-4 flex gap-3">
        <select
          value={filterAgent}
          onChange={(e) => setFilterAgent(e.target.value)}
          className="rounded-lg border border-border bg-surface-raised px-3 py-2 text-sm text-text-primary"
        >
          <option value="">All Agents</option>
          {agents.map((a) => (
            <option key={a} value={a}>{a}</option>
          ))}
        </select>
        <select
          value={filterTool}
          onChange={(e) => setFilterTool(e.target.value)}
          className="rounded-lg border border-border bg-surface-raised px-3 py-2 text-sm text-text-primary"
        >
          <option value="">All Tools</option>
          {tools.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
      </div>

      {/* Event table */}
      <EventTable events={events} />
    </div>
  );
}
