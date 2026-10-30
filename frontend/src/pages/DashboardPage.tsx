import { useEffect, useState } from "react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { getStats } from "../services/api";
import type { StatsResponse } from "../types/scan";
import { RiskBadge } from "../components/RiskBadge";
import { formatTimestamp } from "../lib/utils";

const COLORS = {
  high: "#f87171",
  medium: "#fbbf24",
  low: "#34d399",
  unknown: "#94a3b8",
};

export function DashboardPage() {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getStats()
      .then(setStats)
      .catch((err) => setError(err instanceof Error ? err.message : "Unable to load stats"));
  }, []);

  if (error) {
    return <p className="text-red-400">{error}</p>;
  }
  if (!stats) {
    return <p className="text-slate-400">Loading dashboard…</p>;
  }
  if (stats.total === 0) {
    return (
      <div className="rounded-xl border border-dashed border-slate-700 p-12 text-center">
        <h1 className="text-2xl font-semibold">No scan data yet</h1>
        <p className="mt-2 text-slate-400">
          The dashboard only shows real stored scans for this session or database. Nothing is fabricated when the
          store is empty.
        </p>
      </div>
    );
  }

  const slices = [
    { name: "High", key: "high", value: stats.high },
    { name: "Medium", key: "medium", value: stats.medium },
    { name: "Low", key: "low", value: stats.low },
    { name: "Unknown", key: "unknown", value: stats.unknown },
  ].filter((s) => s.value > 0);

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-semibold">Dashboard</h1>
        <p className="mt-2 text-slate-400">Aggregated from {stats.persistence} storage. Counts are not threat probabilities.</p>
      </div>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        {[
          ["Total", stats.total],
          ["High", stats.high],
          ["Medium", stats.medium],
          ["Low", stats.low],
          ["Incomplete", stats.incomplete],
        ].map(([label, value]) => (
          <article key={String(label)} className="rounded-xl border border-slate-800 bg-navy-900 p-4">
            <p className="text-sm text-slate-400">{label}</p>
            <p className="mt-2 text-3xl font-semibold">{value}</p>
          </article>
        ))}
      </div>
      <div className="grid gap-6 lg:grid-cols-2">
        <article className="h-80 rounded-xl border border-slate-800 bg-navy-900 p-4">
          <h2 className="font-medium">Risk-category distribution</h2>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={slices} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80}>
                {slices.map((slice) => (
                  <Cell key={slice.key} fill={COLORS[slice.key as keyof typeof COLORS]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </article>
        <article className="rounded-xl border border-slate-800 bg-navy-900 p-4">
          <h2 className="font-medium">Recent activity</h2>
          <ul className="mt-4 space-y-3">
            {stats.recent.map((item) => (
              <li key={item.id} className="flex flex-wrap items-center justify-between gap-2 text-sm">
                <span className="font-mono text-xs">{item.hostname}</span>
                <RiskBadge value={item.risk_classification} />
                <span className="text-slate-500">{formatTimestamp(item.created_at)}</span>
              </li>
            ))}
          </ul>
        </article>
      </div>
    </div>
  );
}
