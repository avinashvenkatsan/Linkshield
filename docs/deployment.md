# Deploying LinkShield on Render

Render, third-party APIs, and PostgreSQL **may incur charges**. Free tiers, if offered, are not guaranteed indefinitely. Google Safe Browsing and VirusTotal have usage quotas and their own terms.

## Services

1. **PostgreSQL** — create a Render PostgreSQL instance. Copy the internal connection string. Use a SQLAlchemy URL such as `postgresql+psycopg2://USER:PASSWORD@HOST:5432/DBNAME`.
2. **Backend web service**
   - Root directory: `backend`
   - Runtime: Python 3.12
   - Build: `pip install -r requirements.txt`
   - Start: `alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - Health check: `/api/v1/health`
3. **Frontend static site**
   - Root directory: `frontend`
   - Build: `npm install && npm run build`
   - Publish directory: `dist`
   - Environment: `VITE_API_BASE_URL=https://YOUR-BACKEND.onrender.com`

## Required environment variables (backend)

- `APP_ENV=production`
- `FRONTEND_ORIGIN=https://YOUR-FRONTEND.onrender.com`
- `DATABASE_URL=postgresql+psycopg2://...`
- `SESSION_COOKIE_SECURE=true`
- `GOOGLE_SAFE_BROWSING_API_KEY` (optional)
- `VIRUSTOTAL_API_KEY` (optional)

Never commit secrets. Restrict CORS to the frontend origin. Enable HTTPS on both services (Render does this by default).

## After deploy

Call `GET /api/v1/health` and confirm `database.ok` is true. Run a scan of `https://example.com` with third-party intel unchecked, then with it checked if keys are present.

## AWS later

The same containers in `docker-compose.yml` can run on ECS/Fargate with RDS PostgreSQL and an S3+CloudFront static frontend. Do not hard-code Render hostnames in application code.
