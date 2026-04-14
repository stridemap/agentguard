"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { Role } from "@/lib/api";

interface NavItem {
  label: string;
  href: string;
  icon: string;
  roles: Role[];
}

const NAV_ITEMS: NavItem[] = [
  { label: "Live Feed", href: "/dashboard", icon: "📋", roles: ["admin", "analyst", "auditor", "viewer"] },
  { label: "Audit Chain", href: "/dashboard/audit", icon: "🔗", roles: ["admin", "auditor", "analyst"] },
  { label: "Policies", href: "/dashboard/policies", icon: "📜", roles: ["admin", "analyst"] },
  { label: "Reports", href: "/dashboard/reports", icon: "📊", roles: ["admin", "auditor"] },
  { label: "Settings", href: "/dashboard/settings", icon: "⚙️", roles: ["admin"] },
];

export default function Sidebar({ role }: { role: Role }) {
  const pathname = usePathname();
  const visibleItems = NAV_ITEMS.filter((item) => item.roles.includes(role));

  return (
    <aside className="flex h-screen w-56 shrink-0 flex-col border-r border-border bg-surface-raised">
      <div className="flex items-center gap-2 border-b border-border px-4 py-4">
        <span className="text-xl">🛡️</span>
        <span className="font-bold text-text-primary">AgentGuard</span>
      </div>
      <nav className="flex-1 overflow-y-auto px-2 py-3">
        {visibleItems.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`mb-1 flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition ${
                isActive
                  ? "bg-accent/15 font-semibold text-accent"
                  : "text-text-secondary hover:bg-surface-overlay hover:text-text-primary"
              }`}
            >
              <span>{item.icon}</span>
              {item.label}
            </Link>
          );
        })}
      </nav>
      <div className="border-t border-border px-4 py-3">
        <div className="text-xs text-text-muted">
          Role: <span className="font-semibold text-accent">{role}</span>
        </div>
      </div>
    </aside>
  );
}
