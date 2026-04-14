"use client";

import { useState } from "react";
import { api } from "@/lib/api";

export default function ReportsPage() {
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState("");

  const handleExport = async (format: "json" | "csv") => {
    setExporting(true);
    setError("");
    try {
      const blob = await api.exportEvents(format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `agentguard_audit_export.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export failed");
    } finally {
      setExporting(false);
    }
  };

  return (
    <div>
      <h1 className="mb-6 text-2xl font-bold">Compliance Reports</h1>

      {error && (
        <div className="mb-4 rounded-lg border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger">
          {error}
        </div>
      )}

      {/* SOC2 CC6 */}
      <div className="mb-4 rounded-xl border border-border bg-surface-raised p-6">
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-lg font-semibold">SOC2 CC6 — Logical Access Controls</h2>
            <p className="mt-1 text-sm text-text-secondary">
              Export tamper-evident audit trail showing all AI agent tool-call events,
              policy decisions, and risk flags. Maps to SOC2 CC6.1 (access controls),
              CC6.6 (system boundaries), and CC6.8 (unauthorized access prevention).
            </p>
          </div>
          <span className="rounded-lg bg-accent/10 px-3 py-1 text-xs font-semibold text-accent">
            SOC2
          </span>
        </div>
        <div className="mt-4 flex gap-3">
          <button
            onClick={() => handleExport("json")}
            disabled={exporting}
            className="rounded-lg bg-accent px-5 py-2 text-sm font-semibold text-surface transition hover:bg-accent-light disabled:opacity-50"
          >
            Export JSON
          </button>
          <button
            onClick={() => handleExport("csv")}
            disabled={exporting}
            className="rounded-lg border border-accent/30 bg-accent/10 px-5 py-2 text-sm font-semibold text-accent transition hover:bg-accent/20 disabled:opacity-50"
          >
            Export CSV
          </button>
        </div>
      </div>

      {/* HIPAA */}
      <div className="mb-4 rounded-xl border border-border bg-surface-raised p-6">
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-lg font-semibold">HIPAA §164.312 — Technical Safeguards</h2>
            <p className="mt-1 text-sm text-text-secondary">
              Audit evidence pack showing PHI access controls, DLP scanning results,
              and policy enforcement for healthcare agent operations. Covers §164.312(b)
              (audit controls) and §164.312(c) (integrity controls).
            </p>
          </div>
          <span className="rounded-lg bg-purple-400/10 px-3 py-1 text-xs font-semibold text-purple-400">
            HIPAA
          </span>
        </div>
        <div className="mt-4 flex gap-3">
          <button
            onClick={() => handleExport("json")}
            disabled={exporting}
            className="rounded-lg bg-accent px-5 py-2 text-sm font-semibold text-surface transition hover:bg-accent-light disabled:opacity-50"
          >
            Export JSON
          </button>
          <button
            onClick={() => handleExport("csv")}
            disabled={exporting}
            className="rounded-lg border border-accent/30 bg-accent/10 px-5 py-2 text-sm font-semibold text-accent transition hover:bg-accent/20 disabled:opacity-50"
          >
            Export CSV
          </button>
        </div>
      </div>

      {/* ISO 27001 */}
      <div className="rounded-xl border border-border bg-surface-raised p-6">
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-lg font-semibold">ISO 27001 A.12.4 — Logging and Monitoring</h2>
            <p className="mt-1 text-sm text-text-secondary">
              Event log evidence for ISO 27001 Annex A.12.4 compliance. Demonstrates
              that agent activities are logged, monitored, and reviewed with
              cryptographic integrity guarantees.
            </p>
          </div>
          <span className="rounded-lg bg-blue-400/10 px-3 py-1 text-xs font-semibold text-blue-400">
            ISO 27001
          </span>
        </div>
        <div className="mt-4 flex gap-3">
          <button
            onClick={() => handleExport("json")}
            disabled={exporting}
            className="rounded-lg bg-accent px-5 py-2 text-sm font-semibold text-surface transition hover:bg-accent-light disabled:opacity-50"
          >
            Export JSON
          </button>
          <button
            onClick={() => handleExport("csv")}
            disabled={exporting}
            className="rounded-lg border border-accent/30 bg-accent/10 px-5 py-2 text-sm font-semibold text-accent transition hover:bg-accent/20 disabled:opacity-50"
          >
            Export CSV
          </button>
        </div>
      </div>
    </div>
  );
}
