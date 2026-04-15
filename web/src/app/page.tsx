"use client";

import { useState } from "react";

/* ─── Icons ────────────────────────────────────────────────────────── */

function ShieldIcon({ className = "w-6 h-6" }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 2l7 4v5c0 5.25-3.5 9.75-7 11-3.5-1.25-7-5.75-7-11V6l7-4z" />
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

function CheckIcon({ className = "w-5 h-5" }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
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

/* ─── Navbar ───────────────────────────────────────────────────────── */

function Navbar() {
  return (
    <nav className="fixed top-0 left-0 right-0 z-50 border-b border-border bg-surface/80 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-6">
        <a href="#" className="flex items-center gap-2 text-lg font-bold tracking-tight">
          <ShieldIcon className="w-7 h-7 text-accent" />
          <span>Stridemap Labs</span>
        </a>
        <div className="hidden items-center gap-8 text-sm text-text-secondary md:flex">
          <a href="#products" className="transition hover:text-text-primary">Products</a>
          <a href="#why" className="transition hover:text-text-primary">Why Stridemap</a>
          <a href="#agentguard" className="transition hover:text-text-primary">AgentGuard</a>
          <a href="#early-access" className="transition hover:text-text-primary">Early Access</a>
        </div>
        <div className="flex items-center gap-3">
          <a
            href="https://github.com/stridemap"
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
            Get Started
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
      <div className="pointer-events-none absolute -top-40 left-1/2 h-[600px] w-[600px] -translate-x-1/2 rounded-full bg-accent/10 blur-[120px]" />
      <div className="pointer-events-none absolute -bottom-20 right-0 h-[400px] w-[400px] rounded-full bg-accent/5 blur-[100px]" />

      <div className="relative z-10 mx-auto max-w-4xl px-6 text-center">
        <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-accent/30 bg-accent/10 px-4 py-1.5 text-sm text-accent">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-accent" />
          </span>
          AI Security for the Enterprise
        </div>

        <h1 className="mb-6 text-5xl font-extrabold leading-tight tracking-tight sm:text-6xl lg:text-7xl">
          Securing the{" "}
          <span className="bg-gradient-to-r from-accent to-accent-light bg-clip-text text-transparent">
            Agentic Frontier
          </span>
        </h1>

        <p className="mx-auto mb-10 max-w-2xl text-lg leading-relaxed text-text-secondary sm:text-xl">
          Stridemap Labs builds security infrastructure for the AI agent era.
          We help enterprises govern, monitor, and protect their LLM-powered
          agents — so they can deploy with confidence.
        </p>

        <div className="flex flex-col items-center gap-4 sm:flex-row sm:justify-center">
          <a
            href="#agentguard"
            className="inline-flex items-center gap-2 rounded-lg bg-accent px-8 py-3.5 text-base font-semibold text-surface transition hover:bg-accent-light hover:shadow-lg hover:shadow-accent/20"
          >
            Explore AgentGuard
            <ArrowRightIcon className="w-4 h-4" />
          </a>
          <a
            href="#early-access"
            className="inline-flex items-center gap-2 rounded-lg border border-border-light px-8 py-3.5 text-base font-semibold text-text-primary transition hover:border-accent/50 hover:bg-surface-raised"
          >
            Join Early Access
          </a>
        </div>
      </div>
    </section>
  );
}

/* ─── Why Stridemap ────────────────────────────────────────────────── */

const whyCards = [
  {
    icon: "🤖",
    title: "Agents Are Everywhere",
    description:
      "Enterprises are deploying LLM agents that read emails, query databases, call APIs, and execute code. They're powerful — and ungoverned.",
  },
  {
    icon: "🔓",
    title: "Security Gaps Are Growing",
    description:
      "Traditional security tools weren't built for AI agents. Prompt injection, data leakage, and unauthorized actions are the new attack surface.",
  },
  {
    icon: "📋",
    title: "Compliance Is Mandatory",
    description:
      "SOC2, HIPAA, PCI-DSS, and ISO 27001 all require audit trails and access controls. AI agents need the same governance as human operators.",
  },
  {
    icon: "🛡️",
    title: "We Built the Solution",
    description:
      "Stridemap Labs builds the security layer that sits between agents and their tools — intercepting, governing, and logging every action.",
  },
];

function WhyStridemap() {
  return (
    <section id="why" className="py-24">
      <div className="mx-auto max-w-6xl px-6">
        <div className="mb-16 text-center">
          <p className="mb-3 text-sm font-semibold uppercase tracking-wider text-accent">
            Why Stridemap Labs
          </p>
          <h2 className="mb-4 text-3xl font-bold sm:text-4xl">
            AI Agents Need a Security Layer
          </h2>
          <p className="mx-auto max-w-2xl text-text-secondary">
            We&apos;re building the Palo Alto Networks for the AI agent era —
            infrastructure that makes autonomous AI safe for enterprise deployment.
          </p>
        </div>
        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {whyCards.map((c) => (
            <div
              key={c.title}
              className="group rounded-xl border border-border bg-surface-raised p-6 transition hover:border-accent/40 hover:shadow-lg hover:shadow-accent/5"
            >
              <div className="mb-4 text-3xl">{c.icon}</div>
              <h3 className="mb-2 text-lg font-semibold">{c.title}</h3>
              <p className="text-sm leading-relaxed text-text-secondary">{c.description}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ─── Products ─────────────────────────────────────────────────────── */

function Products() {
  return (
    <section id="products" className="border-y border-border bg-surface-raised/50 py-24">
      <div className="mx-auto max-w-6xl px-6">
        <div className="mb-16 text-center">
          <p className="mb-3 text-sm font-semibold uppercase tracking-wider text-accent">
            Products
          </p>
          <h2 className="mb-4 text-3xl font-bold sm:text-4xl">
            Security Infrastructure for AI Agents
          </h2>
          <p className="mx-auto max-w-2xl text-text-secondary">
            Open-source tools that give enterprises full visibility and control
            over their AI agent deployments.
          </p>
        </div>

        {/* AgentGuard — featured product */}
        <div className="rounded-2xl border border-accent/30 bg-surface-raised p-8 transition hover:shadow-lg hover:shadow-accent/10">
          <div className="flex flex-col gap-8 lg:flex-row lg:items-center">
            <div className="flex-1">
              <div className="mb-3 inline-flex items-center gap-2 rounded-full bg-accent/10 px-3 py-1 text-xs font-bold uppercase tracking-wider text-accent">
                Fall 2026
              </div>
              <h3 className="mb-3 text-2xl font-bold">
                <ShieldIcon className="mr-2 inline h-7 w-7 text-accent" />
                AgentGuard
              </h3>
              <p className="mb-4 text-text-secondary">
                The open-source governance layer for LLM-powered AI agents.
                Intercepts every tool call and enforces security policies — DLP scanning,
                prompt injection detection, and tamper-proof audit logging —
                without changing a single line of agent code.
              </p>
              <ul className="mb-6 grid gap-2 text-sm text-text-secondary sm:grid-cols-2">
                {[
                  "YAML Policy Engine (ALLOW / BLOCK / ALERT)",
                  "Microsoft Presidio DLP (15+ PII types)",
                  "Two-stage injection detection",
                  "SHA-256 cryptographic audit chain",
                  "FastAPI REST API + JWT auth",
                  "SOC2 / HIPAA / ISO 27001 reports",
                ].map((f) => (
                  <li key={f} className="flex items-start gap-2">
                    <CheckIcon className="mt-0.5 h-4 w-4 shrink-0 text-accent" />
                    {f}
                  </li>
                ))}
              </ul>
              <div className="flex flex-wrap gap-3">
                <a
                  href="https://github.com/stridemap/agentguard"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 rounded-lg bg-accent px-6 py-2.5 text-sm font-semibold text-surface transition hover:bg-accent-light"
                >
                  <GitHubIcon className="h-4 w-4" />
                  View on GitHub
                </a>
                <a
                  href="/dashboard"
                  className="inline-flex items-center gap-2 rounded-lg border border-border-light px-6 py-2.5 text-sm font-semibold text-text-primary transition hover:border-accent/50 hover:bg-surface-overlay"
                >
                  Dashboard Demo
                </a>
              </div>
            </div>
            <div className="lg:w-[400px]">
              <div className="overflow-hidden rounded-xl border border-border bg-surface shadow-2xl shadow-black/40">
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
          </div>
        </div>

        {/* Coming soon products */}
        <div className="mt-8 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {[
            {
              icon: "🔍",
              name: "AgentWatch",
              description: "Real-time observability and anomaly detection for multi-agent systems. Monitor agent behavior at scale.",
              status: "Winter 2026",
            },
            {
              icon: "🧪",
              name: "AgentTest",
              description: "Automated red-teaming and adversarial testing for AI agents. Find vulnerabilities before attackers do.",
              status: "Spring 2027",
            },
            {
              icon: "🔐",
              name: "AgentVault",
              description: "Secrets management and credential rotation for AI agents. Zero-trust access to APIs and databases.",
              status: "Fall 2027",
            },
          ].map((p) => (
            <div
              key={p.name}
              className="rounded-xl border border-border bg-surface-raised p-6 opacity-80 transition hover:opacity-100"
            >
              <div className="mb-3 text-2xl">{p.icon}</div>
              <h3 className="mb-1 text-lg font-semibold">{p.name}</h3>
              <p className="mb-3 text-sm leading-relaxed text-text-secondary">{p.description}</p>
              <span className="rounded-full bg-surface-overlay px-3 py-1 text-xs font-medium text-text-muted">
                {p.status}
              </span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ─── AgentGuard Detail ────────────────────────────────────────────── */

function AgentGuardDetail() {
  return (
    <section id="agentguard" className="py-24">
      <div className="mx-auto max-w-6xl px-6">
        <div className="mb-16 text-center">
          <p className="mb-3 text-sm font-semibold uppercase tracking-wider text-accent">
            AgentGuard
          </p>
          <h2 className="mb-4 text-3xl font-bold sm:text-4xl">
            Five Modules. One Governance Layer.
          </h2>
        </div>

        <div className="mx-auto max-w-3xl space-y-3">
          {[
            { tag: "OBSERVE", name: "Interceptor", desc: "LangGraph BaseCallbackHandler — captures every tool call with zero code changes.", color: "text-blue-400", bg: "bg-blue-400/10", border: "border-blue-400/30" },
            { tag: "DECIDE", name: "Policy Engine", desc: "YAML rules with ALLOW / BLOCK / ALERT / BYPASS. Hot-reload, regex conditions, AND/OR logic.", color: "text-amber-400", bg: "bg-amber-400/10", border: "border-amber-400/30" },
            { tag: "PROTECT", name: "DLP Scanner", desc: "Microsoft Presidio PII detection — 15+ entity types, 100% local, zero data egress.", color: "text-rose-400", bg: "bg-rose-400/10", border: "border-rose-400/30" },
            { tag: "DEFEND", name: "Injection Detector", desc: "Two-stage: fast regex patterns (<5ms) + LLM classifier. OWASP LLM01-06 coverage.", color: "text-purple-400", bg: "bg-purple-400/10", border: "border-purple-400/30" },
            { tag: "PROVE", name: "Audit Chain", desc: "SHA-256 cryptographic chaining — tamper-evident, SOC2 and HIPAA audit-ready.", color: "text-accent", bg: "bg-accent/10", border: "border-accent/30" },
          ].map((m) => (
            <div
              key={m.name}
              className={`flex items-center gap-4 rounded-lg border ${m.border} ${m.bg} px-5 py-3.5 transition hover:brightness-125`}
            >
              <span className={`shrink-0 rounded-md border ${m.border} ${m.bg} px-2 py-0.5 text-xs font-bold uppercase tracking-wider ${m.color}`}>
                {m.tag}
              </span>
              <div>
                <p className="font-semibold text-text-primary">{m.name}</p>
                <p className="text-sm text-text-secondary">{m.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ─── Early Access ─────────────────────────────────────────────────── */

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
    <section id="early-access" className="border-t border-border py-24">
      <div className="mx-auto max-w-2xl px-6 text-center">
        <p className="mb-3 text-sm font-semibold uppercase tracking-wider text-accent">
          Early Access
        </p>
        <h2 className="mb-4 text-3xl font-bold sm:text-4xl">
          Be First to Secure Your AI Agents
        </h2>
        <p className="mb-10 text-text-secondary">
          Join the waitlist for early access to Stridemap Labs products.
          Help shape the future of AI agent security.
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
      <div className="mx-auto max-w-6xl px-6">
        <div className="flex flex-col items-center justify-between gap-8 sm:flex-row sm:items-start">
          <div>
            <div className="flex items-center gap-2 text-lg font-bold">
              <ShieldIcon className="h-6 w-6 text-accent" />
              Stridemap Labs
            </div>
            <p className="mt-2 max-w-xs text-sm text-text-secondary">
              AI security infrastructure for the enterprise.
              Open source. Built for production.
            </p>
          </div>
          <div className="flex gap-12 text-sm">
            <div>
              <p className="mb-3 font-semibold text-text-primary">Products</p>
              <ul className="space-y-2 text-text-secondary">
                <li><a href="https://github.com/stridemap/agentguard" className="transition hover:text-accent">AgentGuard</a></li>
                <li><span className="text-text-muted">AgentWatch (soon)</span></li>
                <li><span className="text-text-muted">AgentTest (soon)</span></li>
              </ul>
            </div>
            <div>
              <p className="mb-3 font-semibold text-text-primary">Company</p>
              <ul className="space-y-2 text-text-secondary">
                <li><a href="https://github.com/stridemap" className="transition hover:text-accent">GitHub</a></li>
                <li><a href="mailto:support@stridemap.ai" className="transition hover:text-accent">Contact</a></li>
              </ul>
            </div>
          </div>
        </div>
        <div className="mt-10 border-t border-border pt-6 text-center text-xs text-text-muted">
          &copy; {new Date().getFullYear()} Stridemap Labs LLC. All rights reserved.
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
      <WhyStridemap />
      <Products />
      <AgentGuardDetail />
      <EarlyAccess />
      <Footer />
    </>
  );
}
