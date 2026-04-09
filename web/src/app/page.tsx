"use client";

import { useState } from "react";

/* ─── Icons (inline SVG to avoid deps) ─────────────────────────────── */

function ShieldIcon({ className = "w-6 h-6" }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 2l7 4v5c0 5.25-3.5 9.75-7 11-3.5-1.25-7-5.75-7-11V6l7-4z" />
    </svg>
  );
}

function EyeIcon({ className = "w-6 h-6" }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
  );
}

function LockIcon({ className = "w-6 h-6" }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
    </svg>
  );
}

function BoltIcon({ className = "w-6 h-6" }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" />
    </svg>
  );
}

function CheckIcon({ className = "w-5 h-5" }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
    </svg>
  );
}

function XIcon({ className = "w-5 h-5" }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
    </svg>
  );
}

function MinusIcon({ className = "w-5 h-5" }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 12h-15" />
    </svg>
  );
}

function ArrowRightIcon({ className = "w-5 h-5" }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
    </svg>
  );
}

function GitHubIcon({ className = "w-6 h-6" }: { className?: string }) {
  return (
    <svg className={className} fill="currentColor" viewBox="0 0 24 24">
      <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
    </svg>
  );
}

/* ─── Nav ───────────────────────────────────────────────────────────── */

function Navbar() {
  return (
    <nav className="fixed top-0 left-0 right-0 z-50 border-b border-border bg-surface/80 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-6">
        <a href="#" className="flex items-center gap-2 text-lg font-bold tracking-tight">
          <ShieldIcon className="w-7 h-7 text-accent" />
          <span>AgentGuard</span>
        </a>
        <div className="hidden items-center gap-8 text-sm text-text-secondary md:flex">
          <a href="#problem" className="transition hover:text-text-primary">Problem</a>
          <a href="#solution" className="transition hover:text-text-primary">Solution</a>
          <a href="#how-it-works" className="transition hover:text-text-primary">How It Works</a>
          <a href="#compare" className="transition hover:text-text-primary">Compare</a>
        </div>
        <div className="flex items-center gap-3">
          <a
            href="https://github.com/stridemap/agentguard"
            target="_blank"
            rel="noopener noreferrer"
            className="text-text-secondary transition hover:text-text-primary"
          >
            <GitHubIcon />
          </a>
          <a
            href="#early-access"
            className="rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-surface transition hover:bg-accent-light"
          >
            Get Early Access
          </a>
        </div>
      </div>
    </nav>
  );
}

/* ─── Hero ──────────────────────────────────────────────────────────── */

function Hero() {
  return (
    <section className="relative flex min-h-[90vh] items-center justify-center overflow-hidden pt-16">
      {/* Gradient orbs */}
      <div className="pointer-events-none absolute -top-40 left-1/2 h-[600px] w-[600px] -translate-x-1/2 rounded-full bg-accent/10 blur-[120px]" />
      <div className="pointer-events-none absolute -bottom-20 right-0 h-[400px] w-[400px] rounded-full bg-accent/5 blur-[100px]" />

      <div className="relative z-10 mx-auto max-w-4xl px-6 text-center">
        <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-accent/30 bg-accent/10 px-4 py-1.5 text-sm text-accent">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-accent" />
          </span>
          Built for Enterprise AI Teams
        </div>

        <h1 className="mb-6 text-5xl font-extrabold leading-tight tracking-tight sm:text-6xl lg:text-7xl">
          Guardrails for the{" "}
          <span className="bg-gradient-to-r from-accent to-accent-light bg-clip-text text-transparent">
            Agentic Frontier
          </span>
        </h1>

        <p className="mx-auto mb-10 max-w-2xl text-lg leading-relaxed text-text-secondary sm:text-xl">
          AgentGuard intercepts every tool call your AI agents make and enforces security
          policies — DLP, prompt injection detection, and tamper-proof audit logging —
          without changing a single line of agent code.
        </p>

        <div className="flex flex-col items-center gap-4 sm:flex-row sm:justify-center">
          <a
            href="#early-access"
            className="inline-flex items-center gap-2 rounded-lg bg-accent px-8 py-3.5 text-base font-semibold text-surface transition hover:bg-accent-light hover:shadow-lg hover:shadow-accent/20"
          >
            Get Early Access
            <ArrowRightIcon className="w-4 h-4" />
          </a>
          <a
            href="https://github.com/stridemap/agentguard"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 rounded-lg border border-border-light px-8 py-3.5 text-base font-semibold text-text-primary transition hover:border-accent/50 hover:bg-surface-raised"
          >
            <GitHubIcon className="w-5 h-5" />
            View on GitHub
          </a>
        </div>

        {/* Code snippet */}
        <div className="mx-auto mt-14 max-w-xl overflow-hidden rounded-xl border border-border bg-surface-raised text-left shadow-2xl shadow-black/40">
          <div className="flex items-center gap-2 border-b border-border px-4 py-3">
            <span className="h-3 w-3 rounded-full bg-red-500/80" />
            <span className="h-3 w-3 rounded-full bg-yellow-500/80" />
            <span className="h-3 w-3 rounded-full bg-green-500/80" />
            <span className="ml-2 text-xs text-text-muted">quickstart.py</span>
          </div>
          <pre className="overflow-x-auto p-5 text-sm leading-relaxed">
            <code>
              <span className="text-text-muted">{"# 2 lines. Zero agent code changes.\n"}</span>
              <span className="text-purple-400">from</span>
              <span className="text-text-primary"> agentguard </span>
              <span className="text-purple-400">import</span>
              <span className="text-accent"> AgentGuardInterceptor</span>
              {"\n\n"}
              <span className="text-text-primary">config </span>
              <span className="text-text-muted">= </span>
              <span className="text-text-primary">{"{"}</span>
              <span className="text-green-400">{'"callbacks"'}</span>
              <span className="text-text-muted">: </span>
              <span className="text-text-primary">[</span>
              <span className="text-accent">AgentGuardInterceptor</span>
              <span className="text-text-primary">()]{"}"}</span>
              {"\n"}
              <span className="text-text-primary">agent</span>
              <span className="text-text-muted">.</span>
              <span className="text-blue-400">invoke</span>
              <span className="text-text-primary">(input, config</span>
              <span className="text-text-muted">=</span>
              <span className="text-text-primary">config)</span>
            </code>
          </pre>
        </div>
      </div>
    </section>
  );
}

/* ─── Problem ──────────────────────────────────────────────────────── */

const problems = [
  {
    icon: <EyeIcon className="w-7 h-7" />,
    title: "Blind Spots",
    description:
      "AI agents make hundreds of tool calls per session. Without governance, you have zero visibility into what data they access, send, or modify.",
  },
  {
    icon: <LockIcon className="w-7 h-7" />,
    title: "Data Leakage",
    description:
      "Agents can accidentally exfiltrate PII, PHI, or financial data to external APIs. One unguarded tool call can violate HIPAA, SOC2, or PCI-DSS.",
  },
  {
    icon: <BoltIcon className="w-7 h-7" />,
    title: "Prompt Injection",
    description:
      "Malicious inputs embedded in documents, emails, or API responses hijack agent behavior. Traditional input validation doesn't catch LLM-specific attacks.",
  },
  {
    icon: <ShieldIcon className="w-7 h-7" />,
    title: "No Audit Trail",
    description:
      "When a compliance auditor asks 'what did your AI agent do on March 15th?', most teams can't answer. There's no tamper-proof record of agent actions.",
  },
];

function Problem() {
  return (
    <section id="problem" className="py-24">
      <div className="mx-auto max-w-6xl px-6">
        <div className="mb-16 text-center">
          <p className="mb-3 text-sm font-semibold uppercase tracking-wider text-accent">
            The Problem
          </p>
          <h2 className="mb-4 text-3xl font-bold sm:text-4xl">
            AI Agents Are Powerful — and Ungoverned
          </h2>
          <p className="mx-auto max-w-2xl text-text-secondary">
            Enterprises are deploying LLM agents that read emails, query databases, call
            APIs, and execute code. But nobody is watching what they do.
          </p>
        </div>

        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {problems.map((p) => (
            <div
              key={p.title}
              className="group rounded-xl border border-border bg-surface-raised p-6 transition hover:border-accent/40 hover:shadow-lg hover:shadow-accent/5"
            >
              <div className="mb-4 inline-flex rounded-lg bg-accent/10 p-3 text-accent transition group-hover:bg-accent/20">
                {p.icon}
              </div>
              <h3 className="mb-2 text-lg font-semibold">{p.title}</h3>
              <p className="text-sm leading-relaxed text-text-secondary">
                {p.description}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ─── Solution (5-module architecture) ────────────────────────────── */

const modules = [
  {
    name: "Interceptor",
    tag: "OBSERVE",
    description: "LangGraph BaseCallbackHandler — captures every tool call with zero code changes.",
    color: "text-blue-400",
    bgColor: "bg-blue-400/10",
    borderColor: "border-blue-400/30",
  },
  {
    name: "Policy Engine",
    tag: "DECIDE",
    description: "YAML rules with ALLOW / BLOCK / ALERT / BYPASS actions. Hot-reload without restart.",
    color: "text-amber-400",
    bgColor: "bg-amber-400/10",
    borderColor: "border-amber-400/30",
  },
  {
    name: "DLP Scanner",
    tag: "PROTECT",
    description: "Microsoft Presidio PII detection — 15+ entity types, 100% local, zero data egress.",
    color: "text-rose-400",
    bgColor: "bg-rose-400/10",
    borderColor: "border-rose-400/30",
  },
  {
    name: "Injection Detector",
    tag: "DEFEND",
    description: "Two-stage defense: fast regex patterns (<5ms) + LLM classifier for edge cases.",
    color: "text-purple-400",
    bgColor: "bg-purple-400/10",
    borderColor: "border-purple-400/30",
  },
  {
    name: "Audit Chain",
    tag: "PROVE",
    description: "SHA-256 cryptographic chaining — tamper-evident, SOC2 and HIPAA audit-ready.",
    color: "text-accent",
    bgColor: "bg-accent/10",
    borderColor: "border-accent/30",
  },
];

function Solution() {
  return (
    <section id="solution" className="border-y border-border bg-surface-raised/50 py-24">
      <div className="mx-auto max-w-6xl px-6">
        <div className="mb-16 text-center">
          <p className="mb-3 text-sm font-semibold uppercase tracking-wider text-accent">
            The Solution
          </p>
          <h2 className="mb-4 text-3xl font-bold sm:text-4xl">
            Five Modules. One Governance Layer.
          </h2>
          <p className="mx-auto max-w-2xl text-text-secondary">
            AgentGuard sits between your agents and their tools — observing, deciding,
            protecting, defending, and proving compliance at every step.
          </p>
        </div>

        {/* Architecture flow */}
        <div className="mx-auto max-w-3xl">
          {/* Agent box */}
          <div className="mb-3 rounded-lg border border-border-light bg-surface-overlay px-6 py-4 text-center">
            <p className="text-sm font-medium text-text-secondary">Your AI Agent</p>
            <p className="text-xs text-text-muted">LangGraph / LangChain / any framework</p>
          </div>

          {/* Down arrow */}
          <div className="flex justify-center py-1">
            <svg className="h-6 w-6 text-text-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 13.5L12 21m0 0l-7.5-7.5M12 21V3" />
            </svg>
          </div>

          {/* AgentGuard modules */}
          <div className="rounded-2xl border border-accent/30 bg-surface-raised p-1">
            <div className="mb-1 rounded-t-xl bg-accent/10 px-4 py-2.5 text-center">
              <p className="text-sm font-bold text-accent">AgentGuard Governance Layer</p>
            </div>
            <div className="space-y-1">
              {modules.map((m) => (
                <div
                  key={m.name}
                  className={`flex items-center gap-4 rounded-lg border ${m.borderColor} ${m.bgColor} px-5 py-3.5 transition hover:brightness-125`}
                >
                  <span className={`shrink-0 rounded-md border ${m.borderColor} ${m.bgColor} px-2 py-0.5 text-xs font-bold uppercase tracking-wider ${m.color}`}>
                    {m.tag}
                  </span>
                  <div className="min-w-0">
                    <p className="font-semibold text-text-primary">{m.name}</p>
                    <p className="text-sm text-text-secondary">{m.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Down arrow */}
          <div className="flex justify-center py-1">
            <svg className="h-6 w-6 text-text-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 13.5L12 21m0 0l-7.5-7.5M12 21V3" />
            </svg>
          </div>

          {/* Tool box */}
          <div className="rounded-lg border border-border-light bg-surface-overlay px-6 py-4 text-center">
            <p className="text-sm font-medium text-text-secondary">Tool Execution</p>
            <p className="text-xs text-text-muted">APIs, databases, email, file systems</p>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ─── How It Works ─────────────────────────────────────────────────── */

const steps = [
  {
    step: "01",
    title: "Install",
    code: "pip install agentguard",
    description:
      "One command. No external services, no infrastructure. SQLite event store and local Presidio DLP included out of the box.",
  },
  {
    step: "02",
    title: "Wrap",
    code: 'config = {"callbacks": [AgentGuardInterceptor()]}',
    description:
      "Add the interceptor to your LangGraph/LangChain config. Zero changes to your agent logic. Fail-open by design — if AgentGuard crashes, your agents keep running.",
  },
  {
    step: "03",
    title: "Govern",
    code: "agentguard dashboard",
    description:
      "Write YAML policy rules, scan for PII, detect prompt injection, and watch every tool call in the real-time trace dashboard. Export audit logs for SOC2 and HIPAA.",
  },
];

function HowItWorks() {
  return (
    <section id="how-it-works" className="py-24">
      <div className="mx-auto max-w-6xl px-6">
        <div className="mb-16 text-center">
          <p className="mb-3 text-sm font-semibold uppercase tracking-wider text-accent">
            How It Works
          </p>
          <h2 className="mb-4 text-3xl font-bold sm:text-4xl">
            Three Steps to Governed Agents
          </h2>
          <p className="mx-auto max-w-2xl text-text-secondary">
            From zero to full governance in under five minutes.
          </p>
        </div>

        <div className="grid gap-8 lg:grid-cols-3">
          {steps.map((s) => (
            <div key={s.step} className="relative">
              <div className="mb-6">
                <span className="text-5xl font-black text-accent/20">{s.step}</span>
              </div>
              <h3 className="mb-3 text-xl font-bold">{s.title}</h3>
              <div className="mb-4 overflow-hidden rounded-lg border border-border bg-surface-raised">
                <pre className="overflow-x-auto px-4 py-3 text-sm">
                  <code className="text-accent">{s.code}</code>
                </pre>
              </div>
              <p className="text-sm leading-relaxed text-text-secondary">
                {s.description}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ─── Competitor Comparison ────────────────────────────────────────── */

type CellValue = "yes" | "no" | "partial";

interface CompRow {
  feature: string;
  agentguard: CellValue;
  langsmith: CellValue;
  hiddenlayer: CellValue;
  calypsoai: CellValue;
}

const compData: CompRow[] = [
  { feature: "Open Source (MIT)", agentguard: "yes", langsmith: "no", hiddenlayer: "no", calypsoai: "no" },
  { feature: "Tool-Call Interception", agentguard: "yes", langsmith: "yes", hiddenlayer: "no", calypsoai: "partial" },
  { feature: "YAML Policy-as-Code", agentguard: "yes", langsmith: "no", hiddenlayer: "no", calypsoai: "partial" },
  { feature: "DLP / PII Scanning (Local)", agentguard: "yes", langsmith: "no", hiddenlayer: "partial", calypsoai: "yes" },
  { feature: "Prompt Injection Detection", agentguard: "yes", langsmith: "no", hiddenlayer: "yes", calypsoai: "yes" },
  { feature: "Cryptographic Audit Chain", agentguard: "yes", langsmith: "no", hiddenlayer: "no", calypsoai: "no" },
  { feature: "Zero Agent Code Changes", agentguard: "yes", langsmith: "yes", hiddenlayer: "no", calypsoai: "no" },
  { feature: "Fail-Open Guarantee", agentguard: "yes", langsmith: "no", hiddenlayer: "no", calypsoai: "no" },
  { feature: "Self-Hosted / VPC", agentguard: "yes", langsmith: "partial", hiddenlayer: "yes", calypsoai: "no" },
];

function CompCell({ value }: { value: CellValue }) {
  if (value === "yes")
    return <CheckIcon className="mx-auto h-5 w-5 text-accent" />;
  if (value === "no")
    return <XIcon className="mx-auto h-5 w-5 text-text-muted/50" />;
  return <MinusIcon className="mx-auto h-5 w-5 text-warning" />;
}

function Competitors() {
  return (
    <section id="compare" className="border-y border-border bg-surface-raised/50 py-24">
      <div className="mx-auto max-w-6xl px-6">
        <div className="mb-16 text-center">
          <p className="mb-3 text-sm font-semibold uppercase tracking-wider text-accent">
            Compare
          </p>
          <h2 className="mb-4 text-3xl font-bold sm:text-4xl">
            How AgentGuard Stacks Up
          </h2>
          <p className="mx-auto max-w-2xl text-text-secondary">
            The only open-source solution that combines tool-call governance, DLP, injection detection,
            and cryptographic audit — all in one library.
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="px-4 py-3 text-left font-medium text-text-secondary">Feature</th>
                <th className="px-4 py-3 text-center font-bold text-accent">AgentGuard</th>
                <th className="px-4 py-3 text-center font-medium text-text-secondary">LangSmith</th>
                <th className="px-4 py-3 text-center font-medium text-text-secondary">HiddenLayer</th>
                <th className="px-4 py-3 text-center font-medium text-text-secondary">CalypsoAI</th>
              </tr>
            </thead>
            <tbody>
              {compData.map((row) => (
                <tr key={row.feature} className="border-b border-border/50 transition hover:bg-surface-overlay/50">
                  <td className="px-4 py-3 text-text-primary">{row.feature}</td>
                  <td className="px-4 py-3"><CompCell value={row.agentguard} /></td>
                  <td className="px-4 py-3"><CompCell value={row.langsmith} /></td>
                  <td className="px-4 py-3"><CompCell value={row.hiddenlayer} /></td>
                  <td className="px-4 py-3"><CompCell value={row.calypsoai} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

/* ─── Early Access Form ────────────────────────────────────────────── */

function EarlyAccess() {
  const [email, setEmail] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) return;
    setLoading(true);
    setError("");

    try {
      const res = await fetch("/api/waitlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Something went wrong");
      }

      setSubmitted(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <section id="early-access" className="py-24">
      <div className="mx-auto max-w-2xl px-6 text-center">
        <p className="mb-3 text-sm font-semibold uppercase tracking-wider text-accent">
          Early Access
        </p>
        <h2 className="mb-4 text-3xl font-bold sm:text-4xl">
          Be First to Deploy Governed Agents
        </h2>
        <p className="mb-10 text-text-secondary">
          Join the waitlist and get notified when AgentGuard is ready for production.
          Early access members shape the roadmap.
        </p>

        {submitted ? (
          <div className="inline-flex items-center gap-3 rounded-xl border border-accent/30 bg-accent/10 px-8 py-5 text-accent">
            <CheckIcon className="h-6 w-6" />
            <span className="text-lg font-semibold">
              You&apos;re on the list. We&apos;ll be in touch.
            </span>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="mx-auto flex max-w-md flex-col gap-3 sm:flex-row">
            <input
              type="email"
              required
              placeholder="you@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="flex-1 rounded-lg border border-border-light bg-surface-raised px-4 py-3 text-text-primary placeholder-text-muted outline-none transition focus:border-accent focus:ring-1 focus:ring-accent"
            />
            <button
              type="submit"
              disabled={loading}
              className="inline-flex items-center justify-center gap-2 rounded-lg bg-accent px-6 py-3 font-semibold text-surface transition hover:bg-accent-light disabled:opacity-60"
            >
              {loading ? (
                <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-surface border-t-transparent" />
              ) : (
                <>
                  Join Waitlist
                  <ArrowRightIcon className="w-4 h-4" />
                </>
              )}
            </button>
          </form>
        )}
        {error && (
          <p className="mt-3 text-sm text-danger">{error}</p>
        )}
      </div>
    </section>
  );
}

/* ─── Footer ───────────────────────────────────────────────────────── */

function Footer() {
  return (
    <footer className="border-t border-border py-12">
      <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-6 px-6 sm:flex-row">
        <div className="flex items-center gap-2 text-sm text-text-secondary">
          <ShieldIcon className="h-5 w-5 text-accent" />
          <span>&copy; {new Date().getFullYear()} Stridemap. MIT License.</span>
        </div>
        <div className="flex items-center gap-6 text-sm text-text-secondary">
          <a
            href="https://github.com/stridemap/agentguard"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 transition hover:text-text-primary"
          >
            <GitHubIcon className="h-4 w-4" />
            GitHub
          </a>
          <a href="mailto:support@stridemap.ai" className="transition hover:text-text-primary">
            support@stridemap.ai
          </a>
        </div>
      </div>
    </footer>
  );
}

/* ─── Page ─────────────────────────────────────────────────────────── */

export default function Home() {
  return (
    <>
      <Navbar />
      <Hero />
      <Problem />
      <Solution />
      <HowItWorks />
      <Competitors />
      <EarlyAccess />
      <Footer />
    </>
  );
}
