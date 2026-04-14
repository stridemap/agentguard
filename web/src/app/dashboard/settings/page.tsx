"use client";

import { useState } from "react";
import { api } from "@/lib/api";

export default function SettingsPage() {
  const [apiKey, setApiKey] = useState("");
  const [loginStatus, setLoginStatus] = useState("");
  const [loginError, setLoginError] = useState("");

  const handleLogin = async () => {
    setLoginError("");
    setLoginStatus("");
    try {
      const result = await api.login(apiKey);
      setLoginStatus(`Authenticated as ${result.role} (token expires in ${result.expires_in}s)`);
      setApiKey("");
    } catch (err) {
      setLoginError(err instanceof Error ? err.message : "Login failed");
    }
  };

  return (
    <div>
      <h1 className="mb-6 text-2xl font-bold">Settings</h1>

      {/* API Authentication */}
      <div className="mb-6 rounded-xl border border-border bg-surface-raised p-6">
        <h2 className="mb-2 text-lg font-semibold">API Authentication</h2>
        <p className="mb-4 text-sm text-text-secondary">
          Enter your API key to authenticate with the AgentGuard backend.
          This is required to view events, audit chains, and policies.
        </p>
        <div className="flex gap-3">
          <input
            type="password"
            placeholder="Enter API key"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            className="flex-1 rounded-lg border border-border-light bg-surface px-4 py-2.5 text-sm text-text-primary placeholder-text-muted outline-none transition focus:border-accent focus:ring-1 focus:ring-accent"
          />
          <button
            onClick={handleLogin}
            className="rounded-lg bg-accent px-6 py-2.5 text-sm font-semibold text-surface transition hover:bg-accent-light"
          >
            Authenticate
          </button>
        </div>
        {loginStatus && (
          <p className="mt-3 text-sm text-accent">{loginStatus}</p>
        )}
        {loginError && (
          <p className="mt-3 text-sm text-danger">{loginError}</p>
        )}
      </div>

      {/* Connection info */}
      <div className="mb-6 rounded-xl border border-border bg-surface-raised p-6">
        <h2 className="mb-2 text-lg font-semibold">Connection</h2>
        <div className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span className="text-text-muted">API URL</span>
            <span className="font-mono text-text-secondary">
              {process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-text-muted">Role</span>
            <span className="font-semibold text-accent">{api.getRole()}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-text-muted">Authenticated</span>
            <span className={api.isAuthenticated() ? "text-accent" : "text-text-muted"}>
              {api.isAuthenticated() ? "Yes" : "No"}
            </span>
          </div>
        </div>
      </div>

      {/* About */}
      <div className="rounded-xl border border-border bg-surface-raised p-6">
        <h2 className="mb-2 text-lg font-semibold">About</h2>
        <div className="space-y-1 text-sm text-text-secondary">
          <p>AgentGuard v1.0.0 — Guardrails for the Agentic Frontier</p>
          <p>
            <a href="https://github.com/stridemap/agentguard" className="text-accent hover:underline">
              GitHub
            </a>
            {" | "}
            <a href="https://stridemap.ai" className="text-accent hover:underline">
              stridemap.ai
            </a>
            {" | "}
            <a href="mailto:support@stridemap.ai" className="text-accent hover:underline">
              support@stridemap.ai
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}
