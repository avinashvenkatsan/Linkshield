# API

Base path: `/api/v1`

Interactive docs: `/api/docs`

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Process and integration status |
| POST | `/scans` | Analyze a URL |
| GET | `/scans` | Session-scoped history |
| GET | `/scans/{id}` | Full report |
| DELETE | `/scans/{id}` | Delete one stored scan |
| DELETE | `/scans` | Clear session history |
| GET | `/stats` | Aggregated counts |

## POST /scans body

```json
{
  "url": "https://example.com/path",
  "save_history": false,
  "allow_external_intel": false
}
```

`allow_external_intel` must be true before the URL is sent to Google Safe Browsing or VirusTotal.

Responses use standard HTTP codes. Validation failures return 400 with `{ "detail": { "message": "...", "code": "..." } }`. Rate limits return 429.
