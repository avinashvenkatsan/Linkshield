export function PrivacyPage() {
  return (
    <article className="max-w-3xl space-y-5 text-slate-300">
      <h1 className="text-3xl font-semibold text-white">Privacy policy</h1>
      <p className="text-sm text-slate-500">This is a product description, not legal advice. No compliance certification is claimed.</p>
      <h2 className="text-xl font-semibold text-white">URL handling</h2>
      <p>
        URLs you submit are processed in memory to produce a report. Query strings and fragments are omitted from stored
        display URLs. Do not paste secrets into the scanner if you enable third-party intelligence.
      </p>
      <h2 className="text-xl font-semibold text-white">External processing</h2>
      <p>
        Third-party lookups happen only when you check the authorization box and the operator has configured API keys.
        Those providers process URLs under their own terms. RDAP and DNS may still query public infrastructure using the
        domain name.
      </p>
      <h2 className="text-xl font-semibold text-white">Retention</h2>
      <p>
        Default scans expire after 24 hours. Opt-in history uses a longer TTL (default 30 days). You can delete an
        individual scan or clear this session’s history. Server logs redact query strings.
      </p>
      <h2 className="text-xl font-semibold text-white">Cookies</h2>
      <p>
        An HTTP-only session cookie (`ls_client`) associates history with your browser. It is not used for advertising.
      </p>
      <h2 className="text-xl font-semibold text-white">Sharing</h2>
      <p>LinkShield does not sell user data. Operators who deploy their own instance are responsible for their infrastructure policies.</p>
    </article>
  );
}
