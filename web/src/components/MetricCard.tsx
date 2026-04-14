"use client";

interface MetricCardProps {
  label: string;
  value: string | number;
  delta?: string;
  deltaColor?: "green" | "red" | "amber";
}

export default function MetricCard({ label, value, delta, deltaColor = "green" }: MetricCardProps) {
  const colors = {
    green: "text-accent",
    red: "text-danger",
    amber: "text-warning",
  };

  return (
    <div className="rounded-xl border border-border bg-surface-raised p-4">
      <p className="text-xs font-medium uppercase tracking-wider text-text-muted">{label}</p>
      <p className="mt-1 text-2xl font-bold text-text-primary">{value}</p>
      {delta && <p className={`mt-1 text-xs font-medium ${colors[deltaColor]}`}>{delta}</p>}
    </div>
  );
}
