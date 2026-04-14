"use client";

import { useState } from "react";
import type { AgentEvent } from "@/lib/api";

function parseRiskFlags(raw: string): string[] {
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function riskLevel(flags: string[], policy: string): string {
  if (policy === "BLOCK") return "BLOCKED";
  if (flags.length === 0) return "CLEAN";
  const high = ["pii_detected", "unknown_tool"];
  if (flags.some((f) => high.includes(f))) return "HIGH";
  return "MEDIUM";
}

function riskColor(level: string): string {
  switch (level) {
    case "CLEAN": return "text-accent";
    case "MEDIUM": return "text-warning font-semibold";
    case "HIGH": return "text-danger font-semibold";
    case "BLOCKED": return "text-danger font-bold";
    default: return "text-text-secondary";
  }
}

export default function EventTable({ events }: { events: AgentEvent[] }) {
  const [selected, setSelected] = useState<string | null>(null);

  if (events.length === 0) {
    return (
      <div className="rounded-xl border border-border bg-surface-raised p-8 text-center text-text-muted">
        No events found. Run a demo scenario or adjust filters.
      </div>
    );
  }

  return (
    <div>
      <div className="overflow-x-auto rounded-xl border border-border">
        <table className="w-full min-w-[800px] text-sm">
          <thead>
            <tr className="border-b border-border bg-surface-raised text-left text-text-muted">
              <th className="px-4 py-3 font-medium">Time</th>
              <th className="px-4 py-3 font-medium">Agent</th>
              <th className="px-4 py-3 font-medium">Tool</th>
              <th className="px-4 py-3 font-medium text-right">Latency</th>
              <th className="px-4 py-3 font-medium">Risk Flags</th>
              <th className="px-4 py-3 font-medium">Policy</th>
              <th className="px-4 py-3 font-medium">Risk</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event) => {
              const flags = parseRiskFlags(event.risk_flags);
              const level = riskLevel(flags, event.policy_result);
              const isSelected = selected === event.event_id;

              return (
                <tr
                  key={event.event_id}
                  onClick={() => setSelected(isSelected ? null : event.event_id)}
                  className={`cursor-pointer border-b border-border/50 transition ${
                    isSelected ? "bg-accent/10" : "hover:bg-surface-overlay/50"
                  }`}
                >
                  <td className="px-4 py-2.5 font-mono text-xs text-text-secondary">
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="px-4 py-2.5">{event.agent_id}</td>
                  <td className="px-4 py-2.5 font-medium">{event.tool_name}</td>
                  <td className="px-4 py-2.5 text-right font-mono text-xs">
                    {event.latency_ms != null ? `${event.latency_ms.toFixed(1)}ms` : "-"}
                  </td>
                  <td className="px-4 py-2.5 text-xs">
                    {flags.length > 0 ? flags.join(", ") : "-"}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`rounded-md px-2 py-0.5 text-xs font-semibold ${
                      event.policy_result === "BLOCK"
                        ? "bg-danger/15 text-danger"
                        : event.policy_result === "ALERT"
                        ? "bg-warning/15 text-warning"
                        : "bg-accent/10 text-accent"
                    }`}>
                      {event.policy_result}
                    </span>
                  </td>
                  <td className={`px-4 py-2.5 text-xs ${riskColor(level)}`}>{level}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Event detail panel */}
      {selected && (
        <div className="mt-4 rounded-xl border border-accent/30 bg-surface-raised p-5">
          <h3 className="mb-3 text-sm font-bold text-accent">Event Detail</h3>
          <pre className="overflow-x-auto text-xs text-text-secondary">
            {JSON.stringify(events.find((e) => e.event_id === selected), null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
