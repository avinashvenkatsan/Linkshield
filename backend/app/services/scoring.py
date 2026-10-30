from __future__ import annotations

from typing import Any, Iterable

# Application-defined thresholds. These are not scientifically validated probabilities.
LOW_MAX = 24
MEDIUM_MAX = 49

# Cap any single heuristic so correlated URL tricks cannot dominate a confirmed-intel miss.
HEURISTIC_CAP = 45
CONFIRMED_THREAT_FLOOR = 80

WEIGHT_GROUPS = {
    "threat_intel": 80,
    "lookalike_brand": 26,
    "embedded_credentials": 28,
    "ip_hostname": 20,
    "punycode": 16,
    "url_shortener": 14,
    "redirect_parameter": 14,
    "excessive_subdomains": 12,
    "nested_encoding": 12,
    "unusual_port": 10,
    "redirect_domain_change": 18,
    "redirect_loop": 16,
    "certificate_hostname_mismatch": 24,
    "certificate_expired": 18,
    "young_domain": 14,
    "uncommon_tld": 6,
    "hyphenated_host": 5,
    "long_path": 4,
    "dns_failed": 0,
}


def _max_by_type(findings: Iterable[dict[str, Any]]) -> int:
    best: dict[str, int] = {}
    for finding in findings:
        kind = finding.get("type") or finding.get("title")
        contrib = int(finding.get("score_contribution") or 0)
        if contrib <= 0:
            continue
        best[kind] = max(best.get(kind, 0), contrib)
    return sum(best.values())


def compute_risk(
    findings: list[dict[str, Any]],
    provider_results: list[dict[str, Any]],
    incomplete_checks: list[str],
) -> dict[str, Any]:
    confirmed = []
    for provider in provider_results:
        if provider.get("status") == "threat_detected":
            confirmed.append(provider.get("provider"))

    heuristic_score = min(HEURISTIC_CAP, _max_by_type(findings))
    score = heuristic_score
    if confirmed:
        score = max(score, CONFIRMED_THREAT_FLOOR)
        # Additional engine detections from VirusTotal can raise toward 100, capped.
        for provider in provider_results:
            if provider.get("provider") == "virustotal" and provider.get("status") == "threat_detected":
                malicious = int((provider.get("stats") or {}).get("malicious") or 0)
                score = min(100, max(score, CONFIRMED_THREAT_FLOOR + min(20, malicious)))

    score = max(0, min(100, score))

    critical_incomplete = [c for c in incomplete_checks if c in {"threat_intel", "redirects", "dns"}]
    no_positive = score == 0 and not confirmed

    if confirmed or score >= 50:
        classification = "high"
        label = "High Risk"
    elif critical_incomplete and no_positive:
        classification = "unknown"
        label = "Unknown / Incomplete"
        score = 0
    elif score >= 25:
        classification = "medium"
        label = "Medium Risk"
    elif critical_incomplete:
        classification = "unknown"
        label = "Unknown / Incomplete"
    else:
        classification = "low"
        label = "Low Risk"

    if confirmed:
        evidence_quality = "confirmed_threat_match"
        confidence = "high"
    elif heuristic_score >= 25:
        evidence_quality = "heuristic_indicators"
        confidence = "medium"
    elif incomplete_checks:
        evidence_quality = "insufficient_evidence"
        confidence = "low"
    else:
        evidence_quality = "no_significant_indicators"
        confidence = "medium"

    methodology = (
        "The score is an application-defined 0–100 index, not a probability that the URL is malicious. "
        "Confirmed threat-intelligence matches set a floor of 80. Heuristic URL, DNS, TLS, and redirect "
        "signals are capped at 45 combined and de-duplicated by finding type so correlated tricks are not "
        "counted twice. Thresholds: 0–24 Low, 25–49 Medium, 50–100 High. "
        "Unknown/Incomplete is used when important checks failed and no confirmed threat was found. "
        "A low score only means the implemented checks did not surface strong indicators."
    )

    return {
        "score": score,
        "classification": classification,
        "label": label,
        "confidence": confidence,
        "evidence_quality": evidence_quality,
        "confirmed_threat_providers": confirmed,
        "methodology": methodology,
        "thresholds": {"low_max": LOW_MAX, "medium_max": MEDIUM_MAX, "high_min": 50},
    }
