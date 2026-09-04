"use client";

import { useState } from "react";

/* ─── Icons ────────────────────────────────────────────────────────── */

function GatewayIcon({ className = "w-6 h-6" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}>
      <path d="M4 21V8a8 8 0 0 1 16 0v13" strokeLinecap="round" />
      <path d="M9 21v-9a3 3 0 0 1 6 0v9" strokeLinecap="round" />
      <path d="M2 21h20" strokeLinecap="round" />
    </svg>
  );
}

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
          <a href="#use-cases" className="transition hover:text-text-primary">Use Cases</a>
          <a href="#agentguard" className="transition hover:text-text-primary">How it works</a>
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
            href="#products"
            className="inline-flex items-center gap-2 rounded-lg bg-accent px-8 py-3.5 text-base font-semibold text-surface transition hover:bg-accent-light hover:shadow-lg hover:shadow-accent/20"
          >
            Explore MiniGate
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
            We&apos;re building the security infrastructure that makes
            autonomous AI safe for enterprise deployment.
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
            Govern What Your AI Agents Can Actually Do
          </h2>
          <p className="mx-auto max-w-2xl text-text-secondary">
            Assistants now reach into Linear, Drive, Notion and everything else through
            the Model Context Protocol. MiniGate is the control point that sits in the
            middle of it.
          </p>
        </div>

        {/* MiniGate — the MCP gateway */}
        <div className="rounded-2xl border border-accent/30 bg-surface-raised p-8 transition hover:shadow-lg hover:shadow-accent/10">
          <div className="flex flex-col gap-8 lg:flex-row lg:items-center">
            <div className="flex-1">
              <div className="mb-3 inline-flex items-center gap-2 rounded-full bg-accent/10 px-3 py-1 text-xs font-bold uppercase tracking-wider text-accent">
                Design Partners
              </div>
              <h3 className="mb-3 text-2xl font-bold">
                <GatewayIcon className="mr-2 inline h-7 w-7 text-accent" />
                MiniGate
              </h3>
              <p className="mb-4 text-text-secondary">
                A security gateway for the Model Context Protocol — the standard by which
                AI assistants reach outside tools. MiniGate sits between the assistant and
                the vendor&apos;s MCP server and mediates every message in both directions.
                Connecting an assistant to a SaaS tool is all-or-nothing today: the vendor
                decides which tools exist and the client hands every one of them to the
                model. MiniGate is the layer that was missing.
              </p>
              <ul className="mb-6 grid gap-2 text-sm text-text-secondary sm:grid-cols-2">
                {[
                  "Policy per tool call, before the vendor sees it",
                  "Tool definition pinning — catches silent changes",
                  "Injection scanning on results and descriptions",
                  "Local PII redaction — nothing leaves the machine",
                  "Data lineage across chained calls",
                  "Tamper-evident SHA-256 audit chain",
                ].map((f) => (
                  <li key={f} className="flex items-start gap-2">
                    <CheckIcon className="mt-0.5 h-4 w-4 shrink-0 text-accent" />
                    {f}
                  </li>
                ))}
              </ul>
              <p className="mb-6 text-sm text-text-muted">
                Runs as a local shim or a hosted gateway. No model-channel access, no TLS
                interception, no credential custody — OAuth is relayed, never minted.
                Powered by AgentGuard.
              </p>
              <div className="flex flex-wrap gap-3">
                <a
                  href="#early-access"
                  className="inline-flex items-center gap-2 rounded-lg bg-accent px-6 py-2.5 text-sm font-semibold text-surface transition hover:bg-accent-light"
                >
                  Become a design partner
                  <ArrowRightIcon className="h-4 w-4" />
                </a>
              </div>
            </div>
            <div className="lg:w-[400px]">
              <div className="overflow-hidden rounded-xl border border-border bg-surface shadow-2xl shadow-black/40">
                <div className="flex items-center gap-2 border-b border-border px-4 py-3">
                  <span className="h-3 w-3 rounded-full bg-red-500/80" />
                  <span className="h-3 w-3 rounded-full bg-yellow-500/80" />
                  <span className="h-3 w-3 rounded-full bg-green-500/80" />
                  <span className="ml-2 text-xs text-text-muted">minigate.yaml</span>
                </div>
                <pre className="overflow-x-auto p-5 text-sm leading-relaxed">
                  <code>
                    <span className="text-text-muted">{"# Policy as code, reviewed like any other config\n"}</span>
                    <span className="text-blue-400">rules</span>
                    <span className="text-text-muted">:</span>
                    {"\n  - "}
                    <span className="text-blue-400">id</span>
                    <span className="text-text-muted">: </span>
                    <span className="text-accent">MG-010</span>
                    {"\n    "}
                    <span className="text-blue-400">name</span>
                    <span className="text-text-muted">: </span>
                    <span className="text-text-primary">Block deletion across all servers</span>
                    {"\n    "}
                    <span className="text-blue-400">conditions</span>
                    <span className="text-text-muted">:</span>
                    {"\n      "}
                    <span className="text-blue-400">tool_name</span>
                    <span className="text-text-muted">: </span>
                    <span className="text-green-400">{'".*\\.(delete|remove|drop).*"'}</span>
                    {"\n    "}
                    <span className="text-blue-400">action</span>
                    <span className="text-text-muted">: </span>
                    <span className="text-red-400">BLOCK</span>
                    {"\n\n"}
                    <span className="text-text-muted">{"# 57 tools offered by the vendor\n"}</span>
                    <span className="text-text-muted">{"# 36 reach the model"}</span>
                  </code>
                </pre>
              </div>
            </div>
          </div>
        </div>

        {/* AgentGuard — the engine, deliberately understated */}
        <div className="mt-6 rounded-xl border border-border bg-surface-raised/60 p-6">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-start">
            <div className="flex-1">
              <div className="mb-2 flex items-center gap-3">
                <ShieldIcon className="h-5 w-5 text-text-muted" />
                <h3 className="text-lg font-semibold text-text-primary">AgentGuard</h3>
                <span className="rounded-full bg-surface-overlay px-2.5 py-0.5 text-xs font-medium text-text-muted">
                  Engine
                </span>
              </div>
              <p className="mb-4 text-sm leading-relaxed text-text-secondary">
                The governance library MiniGate runs on — policy evaluation, local PII
                detection, prompt-injection scanning and the cryptographic audit chain.
                It is also embeddable directly in a LangGraph or LangChain agent for teams
                who want the controls without a gateway in front.
              </p>
              <ul className="grid gap-1.5 text-sm text-text-muted sm:grid-cols-2">
                {[
                  "YAML policy engine",
                  "Microsoft Presidio DLP",
                  "Two-stage injection detection",
                  "SHA-256 audit chain",
                ].map((f) => (
                  <li key={f} className="flex items-start gap-2">
                    <CheckIcon className="mt-0.5 h-3.5 w-3.5 shrink-0 text-text-muted" />
                    {f}
                  </li>
                ))}
              </ul>
            </div>
            <div className="lg:w-[320px] lg:shrink-0">
              <a
                href="#agentguard"
                className="inline-flex items-center gap-2 text-sm font-medium text-text-secondary transition hover:text-accent"
              >
                How the five modules fit together
                <ArrowRightIcon className="h-4 w-4" />
              </a>
            </div>
          </div>
        </div>

      </div>
    </section>
  );
}

/* ─── Use Cases ────────────────────────────────────────────────────── */

const useCases = [
  {
    tag: "Least privilege",
    title: "Shrink a connector to what you meant",
    body: "Linear's MCP server ships 57 tools, four of which delete things. You wanted read and comment. A policy file gets you 36 — no waiting on the vendor for finer scopes.",
  },
  {
    tag: "Supply chain",
    title: "Catch a tool that changed after you approved it",
    body: "The name never changes, so every allowlist still says ALLOW. MiniGate hashes the whole definition at approval. Real case: Linear altered save_issue between two days in September. The diff exits non-zero, so it gates CI.",
  },
  {
    tag: "Prompt injection",
    title: "Instructions hidden in the data your agent reads",
    body: "Anyone with your intake form URL can write into your database. A ticket saying \u201cignore previous instructions\u201d is a code path an attacker controls without touching your infrastructure. Scanned on the way back, after policy already said the call was fine.",
  },
  {
    tag: "Data protection",
    title: "Minimise before it reaches a third-party model",
    body: "Names, emails and card numbers are redacted in flight; an SSN refuses the call outright, because redaction is the wrong answer when the data should not be in play. Scanning runs locally — nothing leaves the machine to be classified.",
  },
  {
    tag: "Exfiltration",
    title: "The breach that is a sequence, not a call",
    body: "Read from the CRM: allowed. Post to the public tracker: allowed. In that order it is a breach. Every allowlist and DLP appliance evaluates one request at a time, so the information is never in front of them.",
  },
  {
    tag: "Coverage",
    title: "Govern agents whose code you do not own",
    body: "SDK callbacks need a line in the agent. You cannot add one to Claude Desktop, Cursor, or a vendor's agent. A proxy in the protocol path does not ask the code for permission.",
  },
  {
    tag: "Reverse channel",
    title: "Stop a server spending your tokens — or phishing your users",
    body: "MCP is bidirectional. A server can ask your client to run the model and hand back the result, or render a form to your user asking for an API key. The spec says it must not. That is an expectation, not a control.",
  },
  {
    tag: "Evidence",
    title: "Prove nobody edited the log",
    body: "\u201cShow me what your agents did\u201d is answerable with logs. \u201cProve nobody rewrote them\u201d is not. Each event's hash covers the one before it, so any edit breaks the chain from that row on. Verification walks the whole thing in milliseconds.",
  },
];

function UseCases() {
  return (
    <section id="use-cases" className="border-y border-border bg-surface-raised/30 py-24">
      <div className="mx-auto max-w-6xl px-6">
        <div className="mb-16 text-center">
          <p className="mb-3 text-sm font-semibold uppercase tracking-wider text-accent">
            Use Cases
          </p>
          <h2 className="mb-4 text-3xl font-bold sm:text-4xl">
            What It Actually Stops
          </h2>
          <p className="mx-auto max-w-2xl text-text-secondary">
            Every one of these is a real failure mode of connecting an AI assistant
            to a work tool — not a hypothetical.
          </p>
        </div>
        <div className="grid gap-5 sm:grid-cols-2">
          {useCases.map((u) => (
            <div
              key={u.title}
              className="rounded-xl border border-border bg-surface p-6 transition hover:border-accent/40"
            >
              <span className="mb-3 inline-block rounded-full bg-accent/10 px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wider text-accent">
                {u.tag}
              </span>
              <h3 className="mb-2 text-base font-semibold">{u.title}</h3>
              <p className="text-sm leading-relaxed text-text-secondary">{u.body}</p>
            </div>
          ))}
        </div>
        <p className="mx-auto mt-10 max-w-3xl text-center text-sm leading-relaxed text-text-muted">
          MiniGate never sees your prompts and does not proxy the model API. Everything it
          governs is visible in the protocol itself — which tool, with what arguments, and
          what came back. No TLS interception, and no credentials held: OAuth is relayed,
          never minted.
        </p>
      </div>
    </section>
  );
}

/* ─── How You Use It ───────────────────────────────────────────────── */

const steps = [
  {
    n: "01",
    title: "Point your client at the gateway",
    body: "A custom connector URL, or two lines in your MCP client config. Nothing in your agent changes — MiniGate speaks the same protocol the client already speaks.",
    code: "https://gateway.example.com/mcp/linear",
  },
  {
    n: "02",
    title: "Write policy as code",
    body: "YAML, in your repo, reviewed in a pull request like any other config. Rules match on tool name, data pattern, direction and destination, in priority order.",
    code: "tool_name: \".*\\.(delete|remove|drop).*\"\naction:    BLOCK",
  },
  {
    n: "03",
    title: "Approve the tools you audited",
    body: "One sync records what each tool looked like the day you reviewed it — the whole definition, not the name. When a vendor changes one afterwards, you find out.",
    code: "minigate registry sync --server-name linear",
  },
  {
    n: "04",
    title: "Read the evidence",
    body: "Every decision lands in an append-only, hash-chained record. Verification walks the whole chain and tells you whether a single row was ever altered.",
    code: "minigate verify\n{ \"is_valid\": true, \"total_events\": 212 }",
  },
];

function HowYouUseIt() {
  return (
    <section id="how" className="py-24">
      <div className="mx-auto max-w-6xl px-6">
        <div className="mb-16 text-center">
          <p className="mb-3 text-sm font-semibold uppercase tracking-wider text-accent">
            How You Use It
          </p>
          <h2 className="mb-4 text-3xl font-bold sm:text-4xl">
            A Config File and a URL
          </h2>
          <p className="mx-auto max-w-2xl text-text-secondary">
            No SDK to adopt and no agent code to change. MiniGate runs as a local shim
            beside your client, or as a hosted gateway your whole team points at.
          </p>
        </div>

        <div className="space-y-4">
          {steps.map((s) => (
            <div
              key={s.n}
              className="flex flex-col gap-5 rounded-xl border border-border bg-surface-raised p-6 sm:flex-row sm:items-center"
            >
              <span className="shrink-0 font-mono text-2xl font-bold text-accent/40">{s.n}</span>
              <div className="flex-1">
                <h3 className="mb-1.5 text-base font-semibold">{s.title}</h3>
                <p className="text-sm leading-relaxed text-text-secondary">{s.body}</p>
              </div>
              <pre className="overflow-x-auto rounded-lg border border-border bg-surface px-4 py-3 font-mono text-xs leading-relaxed text-text-secondary sm:w-[330px] sm:shrink-0">
                {s.code}
              </pre>
            </div>
          ))}
        </div>

        <p className="mx-auto mt-10 max-w-3xl text-center text-sm leading-relaxed text-text-muted">
          Faults fail open, policy fails closed. An error inside MiniGate lets the call
          through — a security tool that breaks your agent gets uninstalled. A rule that
          says block, blocks.
        </p>
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
            How it works
          </p>
          <h2 className="mb-4 text-3xl font-bold sm:text-4xl">
            Five Modules Behind Every Decision
          </h2>
          <p className="mx-auto mt-4 max-w-2xl text-text-secondary">
            Every message MiniGate mediates passes through these. They are AgentGuard,
            the library underneath — usable on their own if you would rather embed the
            controls than run a gateway.
          </p>
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
              Built for enterprise. Built for production.
            </p>
          </div>
          <div className="flex gap-12 text-sm">
            <div>
              <p className="mb-3 font-semibold text-text-primary">Products</p>
              <ul className="space-y-2 text-text-secondary">
                <li><a href="#products" className="transition hover:text-accent">MiniGate</a></li>
                <li><a href="#agentguard" className="transition hover:text-accent">AgentGuard</a></li>
              </ul>
            </div>
            <div>
              <p className="mb-3 font-semibold text-text-primary">Company</p>
              <ul className="space-y-2 text-text-secondary">
                <li><a href="https://github.com/stridemap" className="transition hover:text-accent">GitHub</a></li>
                <li><a href="mailto:support@stridemap.ai" className="transition hover:text-accent">Contact</a></li>
                <li><a href="mailto:support@stridemap.ai" className="text-text-muted transition hover:text-accent">support@stridemap.ai</a></li>
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
      <UseCases />
      <HowYouUseIt />
      <AgentGuardDetail />
      <EarlyAccess />
      <Footer />
    </>
  );
}
