import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Button } from "../components/ui/button";
import { FindingCard } from "../components/FindingCard";
import { RiskBadge } from "../components/RiskBadge";
import { deleteScan, getScan } from "../services/api";
import type { ScanRecord } from "../types/scan";
import { formatTimestamp } from "../lib/utils";

export function ScanResultPage() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState<ScanRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!scanId) return;
    getScan(scanId)
      .then(setScan)
      .catch((err) => setError(err instanceof Error ? err.message : "Unable to load scan"));
  }, [scanId]);

  if (error) {
    return (
      <div className="rounded-xl border border-slate-800 bg-navy-900 p-8 text-center">
        <h1 className="text-xl font-semibold">Scan not available</h1>
        <p className="mt-2 text-slate-400">{error}</p>
        <Button className="mt-6" onClick={() => navigate("/")}>
          Scan another URL
        </Button>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="rounded-xl border border-slate-800 bg-navy-900 p-8" role="status">
        <p className="text-slate-300">Loading scan report…</p>
      </div>
    );
  }

  const summaryText = [
    `LinkShield report ${scan.id}`,
    `Host: ${scan.hostname}`,
    `Classification: ${scan.risk.label} (score ${scan.risk_score})`,
    `Assessment: ${scan.assessment}`,
    "This score is not a probability that the URL is malicious.",
  ].join("\n");

  async function copySummary() {
    await navigator.clipboard.writeText(summaryText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function exportJson() {
    const blob = new Blob([JSON.stringify(scan, null, 2)], { type: "application/json" });
    const href = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = href;
    a.download = `linkshield-${scan.id}.json`;
    a.click();
    URL.revokeObjectURL(href);
  }

  async function onDelete() {
    await deleteScan(scan.id);
    navigate("/history");
  }

  return (
    <div className="space-y-6">
      <section className="rounded-2xl border border-slate-800 bg-navy-900 p-6 shadow-card">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-xs uppercase tracking-widest text-slate-500">Scan report</p>
            <h1 className="mt-1 text-2xl font-semibold text-white">{scan.hostname}</h1>
            <p className="mt-2 font-mono text-sm text-slate-300 break-all">{scan.submitted_url}</p>
          </div>
          <RiskBadge value={scan.risk_classification} score={scan.risk_score} />
        </div>
        <dl className="mt-6 grid gap-4 text-sm sm:grid-cols-2 lg:grid-cols-4">
          <div>
            <dt className="text-slate-400">Normalized URL</dt>
            <dd className="mt-1 font-mono break-all">{scan.normalized_url}</dd>
          </div>
          <div>
            <dt className="text-slate-400">Registrable domain</dt>
            <dd className="mt-1 font-mono">{scan.registrable_domain}</dd>
          </div>
          <div>
            <dt className="text-slate-400">Scan time</dt>
            <dd className="mt-1">{formatTimestamp(scan.created_at)}</dd>
          </div>
          <div>
            <dt className="text-slate-400">Scan ID</dt>
            <dd className="mt-1 font-mono text-xs">{scan.id}</dd>
          </div>
        </dl>
        <p className="mt-6 text-slate-200">{scan.assessment}</p>
        <p className="mt-3 text-sm text-slate-400">
          Evidence quality: {scan.risk.evidence_quality}. Confidence: {scan.risk.confidence}. Findings:{" "}
          {scan.finding_count}. {scan.local_only ? "Local analysis only." : "External intelligence was authorized."}
        </p>
        <p className="mt-3 text-sm text-slate-400">{scan.risk.methodology}</p>
      </section>

      <div className="flex flex-wrap gap-2">
        <Button onClick={() => navigate("/")}>Scan another URL</Button>
        <Button variant="outline" onClick={copySummary}>
          {copied ? "Copied" : "Copy summary"}
        </Button>
        <Button variant="outline" onClick={exportJson}>
          Export JSON
        </Button>
        <Button variant="danger" onClick={onDelete}>
          Delete this scan
        </Button>
      </div>

      <section>
        <h2 className="text-xl font-semibold">Recommended actions</h2>
        <ul className="mt-3 list-disc space-y-2 pl-5 text-slate-300">
          {scan.recommendations.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </section>

      <section>
        <h2 className="text-xl font-semibold">Threat intelligence</h2>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          {scan.providers.map((provider) => (
            <article key={provider.provider} className="rounded-xl border border-slate-800 bg-navy-900 p-4">
              <h3 className="font-medium capitalize text-white">{provider.provider.replaceAll("_", " ")}</h3>
              <p className="mt-1 text-sm text-accent-cyan">{provider.status.replaceAll("_", " ")}</p>
              <p className="mt-2 text-sm text-slate-300">{provider.summary}</p>
              <p className="mt-2 text-sm text-slate-400">{provider.explanation}</p>
              <p className="mt-2 text-xs text-slate-500">{provider.limitations}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold">Findings</h2>
        {scan.findings.length === 0 ? (
          <p className="rounded-xl border border-slate-800 bg-navy-900 p-5 text-slate-300">
            No heuristic findings were raised. That is not evidence the URL is safe.
          </p>
        ) : (
          scan.findings.map((finding) => <FindingCard key={finding.type + finding.title} finding={finding} />)
        )}
      </section>

      <section className="grid gap-4 md:grid-cols-3">
        <article className="rounded-xl border border-slate-800 bg-navy-900 p-4">
          <h3 className="font-medium">DNS</h3>
          <pre className="mt-2 overflow-auto text-xs text-slate-300">{JSON.stringify(scan.dns, null, 2)}</pre>
        </article>
        <article className="rounded-xl border border-slate-800 bg-navy-900 p-4">
          <h3 className="font-medium">HTTPS certificate</h3>
          <pre className="mt-2 overflow-auto text-xs text-slate-300">{JSON.stringify(scan.tls, null, 2)}</pre>
        </article>
        <article className="rounded-xl border border-slate-800 bg-navy-900 p-4">
          <h3 className="font-medium">Redirects</h3>
          <pre className="mt-2 overflow-auto text-xs text-slate-300">{JSON.stringify(scan.redirects, null, 2)}</pre>
        </article>
      </section>

      {scan.incomplete_checks.length > 0 && (
        <p className="text-sm text-amber-300">Incomplete checks: {scan.incomplete_checks.join(", ")}</p>
      )}

      <p className="text-sm text-slate-500">
        Need the scoring model? See <Link to="/about" className="text-accent-cyan">methodology</Link>.
      </p>
    </div>
  );
}
