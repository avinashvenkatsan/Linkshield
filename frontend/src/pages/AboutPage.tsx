export function AboutPage() {
  return (
    <article className="prose prose-invert max-w-3xl space-y-6 text-slate-300">
      <h1 className="text-3xl font-semibold text-white">About and security methodology</h1>
      <p>
        LinkShield is a suspicious-URL investigation tool. It helps people inspect a link before they click it. It is
        not an antivirus, not a sandbox, and not a guarantee that a destination is safe.
      </p>
      <h2 className="text-xl font-semibold text-white">What it does</h2>
      <p>
        The backend validates HTTP/HTTPS URLs, runs explainable local heuristics, optionally queries Google Safe
        Browsing and VirusTotal, and — when SSRF controls allow — inspects public DNS, TLS certificates, and a bounded
        redirect chain.
      </p>
      <h2 className="text-xl font-semibold text-white">URL pattern analysis</h2>
      <p>
        Heuristics look for IP hosts, deep subdomain chains, known shorteners, embedded credentials, nested encoding,
        redirect-style query parameters, punycode, unusual ports, and a small brand-lookalike list. Each hit is an
        indicator with an explanation, not proof of intent.
      </p>
      <h2 className="text-xl font-semibold text-white">Threat intelligence</h2>
      <p>
        Google Safe Browsing Lookup API (v4) reports list matches. VirusTotal API v3 returns existing URL reports;
        this version does not submit new URLs for analysis. Failed, rate-limited, or unconfigured providers are shown
        with those states. A failed call is never scored as clean.
      </p>
      <h2 className="text-xl font-semibold text-white">Risk classifications</h2>
      <ul className="list-disc pl-5">
        <li>Low (0–24): no significant indicators among the checks that completed.</li>
        <li>Medium (25–49): suspicious indicators that deserve attention.</li>
        <li>High (50–100, or a confirmed intel match): strong signals or a list match.</li>
        <li>Unknown / Incomplete: important checks failed and there is no confirmed threat.</li>
      </ul>
      <p>
        Scores are an application-defined index. They are not a percentage probability that a URL is malicious.
        Confirmed provider matches set a floor of 80. Heuristics are de-duplicated by type and capped at 45.
      </p>
      <h2 className="text-xl font-semibold text-white">Why a clean result is not safety</h2>
      <p>
        New phishing sites often have valid certificates, no list matches, and ordinary-looking URLs. LinkShield cannot
        see the page after JavaScript runs, cannot judge social engineering copy, and cannot know whether a domain will
        be weaponized later.
      </p>
      <h2 className="text-xl font-semibold text-white">What may be sent externally</h2>
      <p>
        If you opt in, the full URL may be sent to Google and VirusTotal. RDAP queries send the registrable domain to
        rdap.org. DNS queries go to the resolver used by the server. Local heuristics never require leaving the server.
      </p>
      <h2 className="text-xl font-semibold text-white">Privacy</h2>
      <p>
        Basic scans do not require an account. Stored history keeps a redacted display URL, hostname, and a hash — not
        query strings. Session cookies isolate history. You can delete stored scans.
      </p>
      <h2 className="text-xl font-semibold text-white">Known limitations</h2>
      <ul className="list-disc pl-5">
        <li>No browser rendering or file detonation.</li>
        <li>Lookalike detection uses a small static brand list.</li>
        <li>RDAP registration dates can be missing or wrong.</li>
        <li>Redirect inspection is skipped for unsafe or unusual ports.</li>
        <li>Provider quotas and licenses are the operator’s responsibility.</li>
      </ul>
    </article>
  );
}
