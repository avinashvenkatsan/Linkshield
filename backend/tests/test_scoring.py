from app.services.scoring import compute_risk


def test_confirmed_threat_is_high() -> None:
    risk = compute_risk(
        [],
        [{"provider": "google_safe_browsing", "status": "threat_detected", "stats": {}}],
        [],
    )
    assert risk["classification"] == "high"
    assert risk["score"] >= 80


def test_low_when_clean_and_complete() -> None:
    risk = compute_risk([], [{"provider": "google_safe_browsing", "status": "no_threat_detected"}], [])
    assert risk["classification"] == "low"
    assert risk["score"] == 0


def test_incomplete_not_treated_as_safe() -> None:
    risk = compute_risk([], [{"provider": "google_safe_browsing", "status": "check_unavailable"}], ["threat_intel"])
    assert risk["classification"] == "unknown"


def test_heuristics_cap_and_dedup() -> None:
    findings = [
        {"type": "ip_hostname", "score_contribution": 20},
        {"type": "ip_hostname", "score_contribution": 20},
        {"type": "lookalike_brand", "score_contribution": 26},
    ]
    risk = compute_risk(findings, [], [])
    assert risk["score"] == 46
    assert risk["classification"] == "medium"


def test_failed_provider_does_not_count_as_clean_when_incomplete() -> None:
    risk = compute_risk([], [{"provider": "virustotal", "status": "rate_limited"}], ["threat_intel"])
    assert risk["classification"] != "low"
