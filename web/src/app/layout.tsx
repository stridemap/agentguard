export const metadata = {
  title: "AgentGuard",
  description: "Guardrails and policy enforcement for AI agents",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
