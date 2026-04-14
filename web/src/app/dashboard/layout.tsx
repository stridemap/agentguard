"use client";

import { useState } from "react";
import Sidebar from "@/components/Sidebar";
import type { Role } from "@/lib/api";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  // In production, role comes from JWT / SSO. For now, default to admin.
  const [role] = useState<Role>("admin");

  return (
    <div className="flex min-h-screen bg-surface">
      <Sidebar role={role} />
      <main className="flex-1 overflow-y-auto p-6">{children}</main>
    </div>
  );
}
