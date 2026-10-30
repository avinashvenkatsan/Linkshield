from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient


def test_health(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["service"] == "LinkShield"
    assert body["integrations"]["google_safe_browsing"] == "not_configured"


def test_invalid_url(client: TestClient) -> None:
    response = client.post("/api/v1/scans", json={"url": "not-a-url"})
    assert response.status_code == 400


def test_unsupported_scheme(client: TestClient) -> None:
    response = client.post("/api/v1/scans", json={"url": "file:///etc/passwd"})
    assert response.status_code == 400


def test_scan_mocked_network(client: TestClient) -> None:
    async def fake_dns(parsed):
        return {"status": "ok", "a": ["93.184.216.34"], "aaaa": [], "mx": [], "ns": ["a.iana-servers.net"], "txt_count": 0, "findings": [], "registration": None}

    async def fake_tls(parsed):
        return {"status": "ok", "issuer": "CN=Example", "hostname_match": True, "findings": []}

    async def fake_redirects(parsed):
        return {"status": "ok", "chain": [], "findings": [], "hops": 0, "reason": None}

    with (
        patch("app.services.scan_orchestrator.inspect_dns", new=AsyncMock(side_effect=fake_dns)),
        patch("app.services.scan_orchestrator.inspect_tls", new=AsyncMock(side_effect=fake_tls)),
        patch("app.services.scan_orchestrator.analyze_redirects", new=AsyncMock(side_effect=fake_redirects)),
    ):
        created = client.post(
            "/api/v1/scans",
            json={"url": "https://example.com/", "save_history": True, "allow_external_intel": False},
        )
    assert created.status_code == 201
    scan = created.json()
    assert scan["hostname"] == "example.com"
    assert "secret" not in scan["display_url"].lower()
    assert scan["risk_classification"] in {"low", "medium", "high", "unknown"}
    assert scan["local_only"] is True

    fetched = client.get(f"/api/v1/scans/{scan['id']}")
    assert fetched.status_code == 200

    listed = client.get("/api/v1/scans")
    assert listed.status_code == 200
    assert listed.json()["total"] >= 1

    stats = client.get("/api/v1/stats")
    assert stats.status_code == 200
    assert stats.json()["total"] >= 1

    deleted = client.delete(f"/api/v1/scans/{scan['id']}")
    assert deleted.status_code == 204
    missing = client.get(f"/api/v1/scans/{scan['id']}")
    assert missing.status_code == 404


def test_history_isolated_between_clients(client: TestClient) -> None:
    async def ok(*args, **kwargs):
        return {"status": "ok", "a": ["1.1.1.1"], "aaaa": [], "mx": [], "ns": [], "txt_count": 0, "findings": [], "registration": None, "chain": [], "hops": 0, "reason": None, "issuer": None, "hostname_match": None}

    with (
        patch("app.services.scan_orchestrator.inspect_dns", new=AsyncMock(side_effect=ok)),
        patch("app.services.scan_orchestrator.inspect_tls", new=AsyncMock(side_effect=ok)),
        patch("app.services.scan_orchestrator.analyze_redirects", new=AsyncMock(side_effect=ok)),
    ):
        first = client.post("/api/v1/scans", json={"url": "https://example.com/"})
    scan_id = first.json()["id"]
    other = TestClient(client.app)
    denied = other.get(f"/api/v1/scans/{scan_id}")
    assert denied.status_code == 404


def test_clear_history(client: TestClient) -> None:
    async def ok(*args, **kwargs):
        return {"status": "ok", "a": ["1.1.1.1"], "aaaa": [], "mx": [], "ns": [], "txt_count": 0, "findings": [], "registration": None, "chain": [], "hops": 0, "reason": None, "issuer": None, "hostname_match": None}

    with (
        patch("app.services.scan_orchestrator.inspect_dns", new=AsyncMock(side_effect=ok)),
        patch("app.services.scan_orchestrator.inspect_tls", new=AsyncMock(side_effect=ok)),
        patch("app.services.scan_orchestrator.analyze_redirects", new=AsyncMock(side_effect=ok)),
    ):
        client.post("/api/v1/scans", json={"url": "https://example.com/"})
    cleared = client.delete("/api/v1/scans")
    assert cleared.status_code == 204
    listed = client.get("/api/v1/scans")
    assert listed.json()["total"] == 0
