"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

interface PolicyRule {
  id: string;
  name: string;
  description: string;
  priority: number;
  action: string;
  alert_severity: string;
  conditions: Record<string, unknown>;
}

export default function PoliciesPage() {
  const [rules, setRules] = useState<PolicyRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [reloadMsg, setReloadMsg] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    loadPolicies();
  }, []);

  const loadPolicies = async () => {
    try {
      const data = (await api.getPolicies()) as PolicyRule[];
      setRules(data);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load policies");
    } finally {
      setLoading(false);
    }
  };

  const handleReload = async () => {
    setReloadMsg("");
    try {
      const result = await api.reloadPolicies();
      setReloadMsg(`Reloaded: ${result.rules} rules from ${result.status}`);
      await loadPolicies();
    } catch (err) {
      setReloadMsg(err instanceof Error ? err.message : "Reload failed");
    }
  };

  const actionColor = (action: string) => {
    switch (action) {
      case "BLOCK": return "bg-danger/15 text-danger";
      case "ALERT": return "bg-warning/15 text-warning";
      case "ALLOW": return "bg-accent/10 text-accent";
      case "BYPASS": return "bg-surface-overlay text-text-muted";
      default: return "bg-surface-overlay text-text-secondary";
    }
  };

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-bold">Policy Rules</h1>
        <button
          onClick={handleReload}
          className="rounded-lg border border-accent/30 bg-accent/10 px-4 py-2 text-sm font-semibold text-accent transition hover:bg-accent/20"
        >
          Reload Policies
        </button>
      </div>

      {reloadMsg && (
        <div className="mb-4 rounded-lg border border-accent/30 bg-accent/10 px-4 py-2 text-sm text-accent">
          {reloadMsg}
        </div>
      )}

      {error && (
        <div className="mb-4 rounded-lg border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger">
          {error}
        </div>
      )}

      {loading ? (
        <p className="text-text-muted">Loading policies...</p>
      ) : rules.length === 0 ? (
        <div className="rounded-xl border border-border bg-surface-raised p-8 text-center text-text-muted">
          No policies loaded. Configure AGENTGUARD_POLICY_PATH and reload.
        </div>
      ) : (
        <div className="space-y-3">
          {rules.map((rule) => (
            <div
              key={rule.id}
              className="rounded-xl border border-border bg-surface-raised p-4 transition hover:border-border-light"
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="font-semibold text-text-primary">{rule.name}</h3>
                    <span className={`rounded-md px-2 py-0.5 text-xs font-semibold ${actionColor(rule.action)}`}>
                      {rule.action}
                    </span>
                    <span className="rounded-md bg-surface-overlay px-2 py-0.5 text-xs text-text-muted">
                      Priority: {rule.priority}
                    </span>
                  </div>
                  <p className="mt-1 text-sm text-text-secondary">{rule.description}</p>
                </div>
                <span className="text-xs text-text-muted">{rule.id}</span>
              </div>
              <div className="mt-3">
                <p className="text-xs font-medium text-text-muted">Conditions:</p>
                <pre className="mt-1 overflow-x-auto rounded-lg bg-surface-overlay p-2 text-xs text-text-secondary">
                  {JSON.stringify(rule.conditions, null, 2)}
                </pre>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
