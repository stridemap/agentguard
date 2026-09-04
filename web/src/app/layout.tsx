import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Stridemap Labs — Securing the Agentic Frontier",
  description:
    "Stridemap Labs builds security infrastructure for the AI agent era. MiniGate: a security gateway for the Model Context Protocol — policy, injection scanning, PII redaction and tamper-evident audit for every tool an AI assistant reaches.",
  keywords: [
    "AI security",
    "AI agents",
    "agent governance",
    "LLM security",
    "guardrails",
    "DLP",
    "prompt injection",
    "MiniGate",
    "Model Context Protocol",
    "MCP security",
    "AgentGuard",
    "Stridemap Labs",
    "enterprise AI",
  ],
  authors: [{ name: "Stridemap Labs", url: "https://stridemap.ai" }],
  openGraph: {
    title: "Stridemap Labs — Securing the Agentic Frontier",
    description:
      "Security infrastructure for LLM-powered AI agents. Policy enforcement, DLP scanning, injection detection, and tamper-proof audit logging.",
    url: "https://stridemap.ai",
    siteName: "Stridemap Labs",
    locale: "en_US",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Stridemap Labs — Securing the Agentic Frontier",
    description:
      "AI security infrastructure for the enterprise. Agent governance, DLP, injection detection, audit logging.",
  },
  metadataBase: new URL("https://stridemap.ai"),
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="scroll-smooth">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
