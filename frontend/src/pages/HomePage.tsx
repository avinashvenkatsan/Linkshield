import { FormEvent, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Globe, Link2, Route, Shield } from "lucide-react";
import { Button } from "../components/ui/button";
import { createScan, getHealth } from "../services/api";
import type { HealthResponse } from "../types/scan";

const features = [
  {
    icon: Link2,
    title: "URL analysis",
    text: "Local heuristics inspect structure, lookalikes, shorteners, encoding, and misleading hosts — without opening the page.",
  },
  {
    icon: Shield,
    title: "Threat intelligence",
    text: "Optional Google Safe Browsing and VirusTotal lookups. Missing keys or failed calls are reported as unavailable, never as clean.",
  },
  {
    icon: Globe,
    title: "Domain information",
    text: "Public DNS, optional RDAP registration age, and HTTPS certificate details when a safe connection is possible.",
  },
  {
    icon: Route,
    title: "Redirect analysis",
    text: "Controlled hop inspection with SSRF blocking. If a hop cannot be fetched safely, the report says so.",
  },
];

export function HomePage() {
  const navigate = useNavigate();
  const [url, setUrl] = useState("");
  const [saveHistory, setSaveHistory] = useState(false);
  const [allowIntel, setAllowIntel] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [health, setHealth] = useState<HealthResponse | null>(null);

  useEffect(() => {
    getHealth()
      .then(setHealth)
      .catch(() => setHealth(null));
  }, []);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    if (!url.trim()) {
      setError("Enter an HTTP or HTTPS URL.");
      return;
    }
    setLoading(true);
    try {
      const scan = await createScan({
        url: url.trim(),
        save_history: saveHistory,
        allow_external_intel: allowIntel,
      });
      navigate(`/scans/${scan.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-16">
      <section className="grid gap-10 lg:grid-cols-[1.2fr_0.8fr] lg:items-center">
        <div>
          <p className="text-sm uppercase tracking-[0.2em] text-accent-cyan">Suspicious link checker</p>
          <h1 className="mt-3 text-4xl font-semibold tracking-tight text-white md:text-5xl">Check Before You Click.</h1>
          <p className="mt-4 max-w-xl text-lg text-slate-300">
            LinkShield investigates a URL with local pattern analysis and optional threat-intelligence lookups. It never
            opens the destination in your browser and never treats a quiet report as proof of safety.
          </p>
        </div>
        <form onSubmit={onSubmit} className="rounded-2xl border border-slate-800 bg-navy-900 p-6 shadow-card">
          <label htmlFor="url" className="text-sm font-medium text-slate-200">
            URL to investigate
          </label>
          <input
            id="url"
            name="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/suspicious-path"
            autoComplete="off"
            spellCheck={false}
            className="mt-2 w-full rounded-lg border border-slate-700 bg-navy-950 px-3 py-3 font-mono text-sm text-white placeholder:text-slate-500"
          />
          {error && (
            <p role="alert" className="mt-2 text-sm text-red-400">
              {error}
            </p>
          )}
          <fieldset className="mt-4 space-y-2 text-sm text-slate-300">
            <legend className="sr-only">Scan options</legend>
            <label className="flex items-start gap-2">
              <input type="checkbox" checked={saveHistory} onChange={(e) => setSaveHistory(e.target.checked)} className="mt-1" />
              <span>Save this scan to history on this device session (hostname and redacted path only).</span>
            </label>
            <label className="flex items-start gap-2">
              <input type="checkbox" checked={allowIntel} onChange={(e) => setAllowIntel(e.target.checked)} className="mt-1" />
              <span>
                Send the URL to configured third-party providers (Google Safe Browsing, VirusTotal) according to their
                terms. Leave unchecked for local analysis only.
              </span>
            </label>
          </fieldset>
          <Button type="submit" size="lg" className="mt-5 w-full" disabled={loading}>
            {loading ? "Scanning…" : "Scan URL"}
          </Button>
          <p className="mt-3 text-xs text-slate-500">
            Privacy: query strings and fragments are redacted in stored history. Do not submit URLs that contain
            passwords or access tokens if you enable third-party intelligence.
          </p>
          {health && (
            <p className="mt-2 text-xs text-slate-500">
              Safe Browsing: {health.integrations.google_safe_browsing.replace("_", " ")}. VirusTotal:{" "}
              {health.integrations.virustotal.replace("_", " ")}. Storage: {health.database.mode}.
            </p>
          )}
        </form>
      </section>

      <section>
        <h2 className="text-2xl font-semibold text-white">What LinkShield checks</h2>
        <div className="mt-6 grid gap-4 md:grid-cols-2">
          {features.map((feature) => (
            <article key={feature.title} className="rounded-xl border border-slate-800 bg-navy-900 p-5">
              <feature.icon className="h-5 w-5 text-accent-cyan" aria-hidden="true" />
              <h3 className="mt-3 font-medium text-white">{feature.title}</h3>
              <p className="mt-2 text-sm text-slate-300">{feature.text}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="grid gap-6 md:grid-cols-2">
        <article className="rounded-xl border border-slate-800 bg-navy-900 p-6">
          <h2 className="text-xl font-semibold text-white">How scanning works</h2>
          <ol className="mt-4 list-decimal space-y-2 pl-5 text-sm text-slate-300">
            <li>The URL is validated on the server. Unsupported schemes are rejected.</li>
            <li>Local heuristics describe structural and lookalike indicators.</li>
            <li>Optional providers are queried only if you authorize them and keys are configured.</li>
            <li>DNS, TLS, and redirects run only against public addresses with timeouts and hop limits.</li>
            <li>A transparent score is produced. Incomplete checks are labeled as such.</li>
          </ol>
        </article>
        <article className="rounded-xl border border-amber-900/60 bg-navy-900 p-6">
          <h2 className="text-xl font-semibold text-amber-200">Security limitations</h2>
          <ul className="mt-4 list-disc space-y-2 pl-5 text-sm text-slate-300">
            <li>LinkShield does not execute page content or inspect files after download.</li>
            <li>Zero findings is not a guarantee of safety.</li>
            <li>List-based intel can be delayed, incomplete, or unavailable.</li>
            <li>Private and metadata destinations are blocked and will not be fetched.</li>
          </ul>
        </article>
      </section>
    </div>
  );
}
