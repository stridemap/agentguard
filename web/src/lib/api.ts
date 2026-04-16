/**
 * AgentGuard API client for the Next.js dashboard.
 * Talks to the FastAPI backend at NEXT_PUBLIC_API_URL.
 * Persists auth token in localStorage for cross-page navigation.
 */

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export type Role = "admin" | "analyst" | "auditor" | "viewer";

export interface AuthToken {
  access_token: string;
  token_type: string;
  expires_in: number;
  role: string;
}

export interface AgentEvent {
  event_id: string;
  timestamp: string;
  agent_id: string;
  session_id: string;
  tool_name: string;
  run_id: string;
  parent_run_id: string | null;
  input_hash: string;
  output_hash: string;
  latency_ms: number | null;
  risk_flags: string;
  policy_result: string;
  prev_hash: string;
  event_hash: string;
}

export interface HealthStatus {
  status: string;
  version: string;
  db_connection: string;
  event_count: number;
  policy_rules: number;
}

export interface AuditResult {
  is_valid: boolean;
  total_events: number;
  first_tampered_event_id: string | null;
  verification_latency_ms: number;
}

class ApiClient {
  private token: string = "";
  private role: Role = "viewer";

  constructor() {
    // Restore token from localStorage on init
    if (typeof window !== "undefined") {
      const saved = localStorage.getItem("agentguard_token");
      const savedRole = localStorage.getItem("agentguard_role");
      if (saved) this.token = saved;
      if (savedRole) this.role = savedRole as Role;
    }
  }

  setToken(token: string, role: Role) {
    this.token = token;
    this.role = role;
    if (typeof window !== "undefined") {
      localStorage.setItem("agentguard_token", token);
      localStorage.setItem("agentguard_role", role);
    }
  }

  getRole(): Role {
    return this.role;
  }

  isAuthenticated(): boolean {
    return !!this.token;
  }

  logout() {
    this.token = "";
    this.role = "viewer";
    if (typeof window !== "undefined") {
      localStorage.removeItem("agentguard_token");
      localStorage.removeItem("agentguard_role");
    }
  }

  private headers(): HeadersInit {
    const h: HeadersInit = { "Content-Type": "application/json" };
    if (this.token) h["Authorization"] = `Bearer ${this.token}`;
    return h;
  }

  async login(apiKey: string): Promise<AuthToken> {
    const res = await fetch(`${API_URL}/auth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ api_key: apiKey }),
    });
    if (!res.ok) throw new Error("Invalid API key");
    const data: AuthToken = await res.json();
    this.setToken(data.access_token, data.role as Role);
    return data;
  }

  async health(): Promise<HealthStatus> {
    const res = await fetch(`${API_URL}/health`);
    return res.json();
  }

  async metrics(): Promise<string> {
    const res = await fetch(`${API_URL}/metrics`);
    return res.text();
  }

  async queryEvents(filters: Record<string, unknown> = {}): Promise<AgentEvent[]> {
    const res = await fetch(`${API_URL}/events`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify({ limit: 100, ...filters }),
    });
    if (!res.ok) {
      if (res.status === 401) this.logout();
      return [];
    }
    return res.json();
  }

  async getEvent(id: string): Promise<AgentEvent> {
    const res = await fetch(`${API_URL}/events/${id}`, { headers: this.headers() });
    if (!res.ok) throw new Error(`Event not found: ${id}`);
    return res.json();
  }

  async verifyAuditChain(): Promise<AuditResult> {
    const res = await fetch(`${API_URL}/audit/verify`, { headers: this.headers() });
    return res.json();
  }

  async exportEvents(format: "json" | "csv"): Promise<Blob> {
    const res = await fetch(`${API_URL}/audit/export?format=${format}`, {
      headers: this.headers(),
    });
    return res.blob();
  }

  async getPolicies(): Promise<unknown[]> {
    const res = await fetch(`${API_URL}/policies`, { headers: this.headers() });
    return res.json();
  }

  async reloadPolicies(): Promise<{ status: string; rules: string }> {
    const res = await fetch(`${API_URL}/policies/reload`, {
      method: "POST",
      headers: this.headers(),
    });
    if (!res.ok) throw new Error(`Reload failed: ${res.status}`);
    return res.json();
  }
}

export const api = new ApiClient();
