# Security notes

- Outbound fetches pin a resolved public IP and re-check DNS before connect.
- Loopback, RFC1918, link-local, metadata, multicast, and reserved ranges are blocked.
- Only ports 80 and 443 are contacted for TLS/redirect inspection.
- Responses are capped; JavaScript is never executed.
- API keys stay in backend environment variables.
- Scan history is authorized by an HTTP-only session cookie, not by guessable URL secrecy alone (UUIDs are still unguessable but the cookie is required).
