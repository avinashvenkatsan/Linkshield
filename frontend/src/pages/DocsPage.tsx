export function DocsPage() {
  return (
    <article className="max-w-3xl space-y-5 text-slate-300">
      <h1 className="text-3xl font-semibold text-white">Documentation</h1>
      <h2 className="text-xl font-semibold text-white">Local analysis vs providers</h2>
      <p>
        Local analysis always runs. Google Safe Browsing and VirusTotal run only with API keys and your explicit
        authorization on each scan.
      </p>
      <h2 className="text-xl font-semibold text-white">API</h2>
      <ul className="list-disc space-y-1 pl-5 font-mono text-sm">
        <li>GET /api/v1/health</li>
        <li>POST /api/v1/scans</li>
        <li>GET /api/v1/scans</li>
        <li>GET /api/v1/scans/{"{id}"}</li>
        <li>DELETE /api/v1/scans/{"{id}"}</li>
        <li>DELETE /api/v1/scans</li>
        <li>GET /api/v1/stats</li>
      </ul>
      <p>
        Interactive OpenAPI docs are served by the backend at <code>/api/docs</code> when you run it locally.
      </p>
      <h2 className="text-xl font-semibold text-white">Configuring providers</h2>
      <ol className="list-decimal space-y-2 pl-5">
        <li>Create a Google Cloud API key with Safe Browsing API enabled and set GOOGLE_SAFE_BROWSING_API_KEY.</li>
        <li>Create a VirusTotal API key and set VIRUSTOTAL_API_KEY. This app only GETs existing URL reports.</li>
        <li>Restart the backend. The health endpoint shows configured vs not_configured.</li>
        <li>On the scanner form, enable third-party lookups for that scan.</li>
      </ol>
      <h2 className="text-xl font-semibold text-white">Running tests</h2>
      <pre className="overflow-auto rounded-lg bg-navy-900 p-4 text-sm">{`cd backend
python -m venv .venv
.venv\\Scripts\\activate
pip install -r requirements-dev.txt
pytest`}</pre>
    </article>
  );
}
