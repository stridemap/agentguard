import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AgentGuard — Guardrails for the Agentic Frontier",
  description:
    "Open-source governance layer for LLM-powered AI agents. Policy enforcement, DLP scanning, prompt injection detection, and tamper-proof audit logging — without changing a line of agent code.",
  keywords: [
    "AI agents",
    "guardrails",
    "LangGraph",
    "LangChain",
    "policy engine",
    "DLP",
    "prompt injection",
    "AI security",
    "agent governance",
    "open source",
  ],
  authors: [{ name: "Stridemap", url: "https://stridemap.ai" }],
  openGraph: {
    title: "AgentGuard — Guardrails for the Agentic Frontier",
    description:
      "Open-source governance layer for LLM-powered AI agents. Policy enforcement, DLP scanning, prompt injection detection, and tamper-proof audit logging.",
    url: "https://stridemap.ai",
    siteName: "AgentGuard by Stridemap",
    locale: "en_US",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "AgentGuard — Guardrails for the Agentic Frontier",
    description:
      "Open-source governance layer for LLM-powered AI agents. Policy enforcement, DLP, injection detection, audit logging.",
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
