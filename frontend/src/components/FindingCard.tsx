import type { Finding } from "../types/scan";
import { RiskBadge } from "./RiskBadge";

const severityToClass: Record<string, string> = {
  high: "high",
  medium: "medium",
  low: "low",
  info: "unknown",
};

export function FindingCard({ finding }: { finding: Finding }) {
  return (
    <article className="rounded-xl border border-slate-800 bg-navy-900 p-5 shadow-card">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <h3 className="text-lg font-medium text-white">{finding.title}</h3>
        <div className="flex gap-2">
          <RiskBadge value={severityToClass[finding.severity] || "unknown"} />
          <span className="rounded-full border border-slate-700 px-2 py-1 text-xs uppercase tracking-wide text-slate-400">
            {finding.status}
          </span>
        </div>
      </div>
      <dl className="mt-4 space-y-3 text-sm">
        <div>
          <dt className="text-slate-400">Evidence</dt>
          <dd className="mt-1 font-mono text-slate-200 break-all">{finding.evidence}</dd>
        </div>
        <div>
          <dt className="text-slate-400">Explanation</dt>
          <dd className="mt-1 text-slate-200">{finding.explanation}</dd>
        </div>
        <div>
          <dt className="text-slate-400">Why it matters</dt>
          <dd className="mt-1 text-slate-200">{finding.why_it_matters}</dd>
        </div>
        <div>
          <dt className="text-slate-400">Suggested action</dt>
          <dd className="mt-1 text-slate-200">{finding.suggested_action}</dd>
        </div>
        <div className="flex flex-wrap gap-4 text-xs text-slate-500">
          <span>Source: {finding.source}</span>
          {typeof finding.score_contribution === "number" && finding.score_contribution > 0 && (
            <span>Score contribution: +{finding.score_contribution}</span>
          )}
        </div>
      </dl>
    </article>
  );
}
