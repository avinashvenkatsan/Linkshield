import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Button } from "../components/ui/button";
import { RiskBadge } from "../components/RiskBadge";
import { clearScans, listScans } from "../services/api";
import type { ScanSummary } from "../types/scan";
import { formatTimestamp } from "../lib/utils";

export function HistoryPage() {
  const [items, setItems] = useState<ScanSummary[]>([]);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    try {
      const data = await listScans();
      setItems(data.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load history");
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  const visible = useMemo(() => {
    return items.filter((item) => {
      const matchesQuery = item.hostname.toLowerCase().includes(query.toLowerCase()) || item.display_url.toLowerCase().includes(query.toLowerCase());
      const matchesFilter = filter === "all" || item.risk_classification === filter;
      return matchesQuery && matchesFilter;
    });
  }, [items, query, filter]);

  async function onClear() {
    if (!window.confirm("Delete all scans stored for this session?")) return;
    await clearScans();
    await refresh();
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold">Scan history</h1>
        <p className="mt-2 text-slate-400">
          History is scoped to this browser session cookie. Anonymous scans work without an account. Enable “save
          history” on the scanner if you want a longer retention window.
        </p>
      </div>
      <div className="flex flex-wrap gap-3">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search hostname"
          className="min-w-[16rem] flex-1 rounded-lg border border-slate-700 bg-navy-900 px-3 py-2 text-sm"
        />
        <select
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="rounded-lg border border-slate-700 bg-navy-900 px-3 py-2 text-sm"
        >
          <option value="all">All classifications</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="unknown">Unknown</option>
        </select>
        <Button variant="danger" onClick={onClear}>
          Clear history
        </Button>
      </div>
      {error && <p className="text-red-400">{error}</p>}
      {visible.length === 0 ? (
        <div className="rounded-xl border border-dashed border-slate-700 p-10 text-center text-slate-400">
          No stored scans match this view. Run a scan from the home page to populate history.
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="min-w-full text-left text-sm">
            <thead className="bg-navy-900 text-slate-400">
              <tr>
                <th className="px-4 py-3 font-medium">When</th>
                <th className="px-4 py-3 font-medium">Domain</th>
                <th className="px-4 py-3 font-medium">Classification</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Details</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((item) => (
                <tr key={item.id} className="border-t border-slate-800">
                  <td className="px-4 py-3">{formatTimestamp(item.created_at)}</td>
                  <td className="px-4 py-3 font-mono text-xs">{item.display_url}</td>
                  <td className="px-4 py-3">
                    <RiskBadge value={item.risk_classification} score={item.risk_score} />
                  </td>
                  <td className="px-4 py-3">{item.status}</td>
                  <td className="px-4 py-3">
                    <Link to={`/scans/${item.id}`} className="text-accent-cyan hover:underline">
                      Open report
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
