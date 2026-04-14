"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import type { AuditResult } from "@/lib/api";

export default function AuditPage() {
  const [result, setResult] = useState<AuditResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const verifyChain = async () => {
    setLoading(true);
    setError("");
    try {
      const data = await api.verifyAuditChain();
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h1 className="mb-6 text-2xl font-bold">Audit Chain Verification</h1>

      <div className="mb-6 rounded-xl border border-border bg-surface-raised p-6">
        <h2 className="mb-2 text-lg font-semibold">SHA-256 Cryptographic Chain</h2>
        <p className="mb-4 text-sm text-text-secondary">
          Every event&apos;s hash includes the previous event&apos;s hash, forming a tamper-evident
          chain from the genesis event. Any modification to any historical event breaks the chain
          at that point.
        </p>
        <button
          onClick={verifyChain}
          disabled={loading}
          className="rounded-lg bg-accent px-6 py-2.5 font-semibold text-surface transition hover:bg-accent-light disabled:opacity-50"
        >
          {loading ? "Verifying..." : "Verify Chain Integrity"}
        </button>
      </div>

      {error && (
        <div className="mb-4 rounded-lg border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger">
          {error}
        </div>
      )}

      {result && (
        <div
          className={`rounded-xl border p-6 ${
            result.is_valid
              ? "border-accent/30 bg-accent/10"
              : "border-danger/30 bg-danger/10"
          }`}
        >
          <div className="mb-4 flex items-center gap-3">
            <span className="text-3xl">{result.is_valid ? "✅" : "🚫"}</span>
            <div>
              <h3 className={`text-xl font-bold ${result.is_valid ? "text-accent" : "text-danger"}`}>
                {result.is_valid ? "Chain Valid" : "Chain Broken — Tampering Detected"}
              </h3>
              <p className="text-sm text-text-secondary">
                {result.total_events.toLocaleString()} events verified in{" "}
                {result.verification_latency_ms.toFixed(1)}ms
              </p>
            </div>
          </div>

          {!result.is_valid && result.first_tampered_event_id && (
            <div className="mt-4 rounded-lg border border-danger/30 bg-surface-raised p-4">
              <p className="text-sm font-semibold text-danger">First tampered event:</p>
              <p className="mt-1 font-mono text-xs text-text-secondary">
                {result.first_tampered_event_id}
              </p>
            </div>
          )}

          <div className="mt-4 grid grid-cols-3 gap-4">
            <div className="rounded-lg bg-surface-raised p-3 text-center">
              <p className="text-2xl font-bold text-text-primary">{result.total_events}</p>
              <p className="text-xs text-text-muted">Total Events</p>
            </div>
            <div className="rounded-lg bg-surface-raised p-3 text-center">
              <p className="text-2xl font-bold text-text-primary">
                {result.verification_latency_ms.toFixed(0)}ms
              </p>
              <p className="text-xs text-text-muted">Verification Time</p>
            </div>
            <div className="rounded-lg bg-surface-raised p-3 text-center">
              <p className="text-2xl font-bold text-text-primary">SHA-256</p>
              <p className="text-xs text-text-muted">Hash Algorithm</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
