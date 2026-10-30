# LinkShield

**Check Before You Click.**

LinkShield is a professional suspicious-URL investigation app. It helps people inspect a link before opening it, using local heuristics, optional threat-intelligence APIs, DNS/TLS data, and tightly controlled redirect inspection.

A quiet report is **not** a guarantee that a URL is safe. LinkShield never fabricates provider results, domain records, or dashboard metrics.

## Problem

Phishing and malware links hide behind lookalike domains, shorteners, and valid HTTPS certificates. Opening a link “just to check” is already too late. LinkShield analyzes the URL on a server that will not render or execute the destination.

## Features

- HTTP/HTTPS URL validation with IDN normalization
- Explainable local heuristics (structure, lookalikes, shorteners, encoding)
- Optional Google Safe Browsing Lookup API (v4) and VirusTotal URL report (v3 GET only)
- Public DNS inspection, optional RDAP age, TLS certificate details
- SSRF-safe redirect following with hop limits
- Transparent 0–100 risk index (not a probability)
- Anonymous scans, optional history, deletion
- Dashboard backed by real stored scans (empty state when none exist)
- Rate limiting, CORS allowlisting, privacy-aware logging

## Screenshots

_Add screenshots here after running the UI locally (`frontend/src` pages: Home, Scan report, History, Dashboard)._

## Architecture

```
React (Vite)  -->  FastAPI /api/v1  -->  local engines
                                 |-->  Google Safe Browsing (optional)
                                 |-->  VirusTotal (optional)
                                 |-->  DNS / RDAP / TLS (public targets only)
                                 \-->  PostgreSQL or in-memory store
```

## Technology stack

- Frontend: React, TypeScript, Vite, Tailwind CSS, Lucide, Recharts
- Backend: Python, FastAPI, Pydantic, HTTPX, SQLAlchemy, Alembic
- Database: PostgreSQL (optional; in-memory store if `DATABASE_URL` is empty)

## Local development

### 1. Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements-dev.txt
copy ..\.env.example ..\.env
uvicorn app.main:app --reload --port 8000
```

The API is at `http://localhost:8000/api/v1/health` and OpenAPI at `http://localhost:8000/api/docs`.

Without PostgreSQL, scans still run and history lives in memory for the process lifetime.

### 2. Frontend

```powershell
cd frontend
npm install
npm run dev
```

The Vite dev server proxies `/api` to `http://localhost:8000`.

### 3. PostgreSQL (optional)

```powershell
docker compose up db
```

Set `DATABASE_URL=postgresql+psycopg2://linkshield:linkshield@localhost:5432/linkshield` in `.env`, then:

```powershell
cd backend
alembic upgrade head
```

## Environment variables

See `.env.example`. Never commit real API keys. Frontend must not contain provider secrets.

## Threat-intelligence setup

1. Enable the [Safe Browsing API](https://developers.google.com/safe-browsing/v4/lookup-api) and put the key in `GOOGLE_SAFE_BROWSING_API_KEY`.
2. Create a [VirusTotal](https://docs.virustotal.com/reference/url-info) API key and put it in `VIRUSTOTAL_API_KEY`. LinkShield only **reads** existing URL reports; it does not submit new scans in this version.
3. Restart the backend. Confirm `/api/v1/health` shows `configured`.
4. On the home form, check **Send the URL to configured third-party providers** for that scan.

If keys are missing, local checks still run and providers return `not_configured`.

## Testing

```powershell
cd backend
pytest
```

Threat-intelligence tests are mocked. Tests do not visit live malicious sites.

```powershell
cd frontend
npm run build
```

## Deployment

See `docs/deployment.md` for Render (static frontend, web service, PostgreSQL). Services and APIs may incur charges and have quotas.

## Security limitations

- No JavaScript execution or file detonation
- Lookalike detection uses a small brand list
- Intel lists are incomplete and delayed
- HTTPS is not evidence of trustworthiness
- Private/metadata destinations are blocked, not fetched
- Scores are not scientifically validated probabilities

## Privacy

Anonymous scanning is the default. History stores a redacted URL and hostname. Third-party providers receive the URL only with explicit per-scan authorization. See the in-app Privacy Policy.

## Roadmap

- Additional intel providers behind the same status enum
- Authenticated accounts for cross-device history
- Operator-configurable brand lists
- Stronger RDAP caching with documented TTLs

## Contributing

Open an issue or pull request describing the risk you are mitigating. Do not submit live malware samples into the repository. Keep secrets out of git.

## License

No license has been selected. All rights remain with the project owner until a license file is added.

## Implemented vs operator setup

**Implemented:** full scan pipeline, UI pages, tests, Docker Compose, Render notes, in-memory fallback.

**You still configure:** PostgreSQL for durable history, Google/VirusTotal keys, production CORS origins, and hosting accounts.
