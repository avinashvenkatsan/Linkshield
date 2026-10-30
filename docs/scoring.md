# Risk scoring

LinkShield scores are an **application-defined 0–100 index**. They are not a probability that a URL is malicious.

## Thresholds

| Classification | Score | Notes |
| --- | --- | --- |
| Low Risk | 0–24 | No significant indicators among completed checks |
| Medium Risk | 25–49 | Suspicious indicators need attention |
| High Risk | 50–100 | Strong signals, or a confirmed threat-intel match |
| Unknown / Incomplete | n/a | Important checks failed and no confirmed threat was found |

A confirmed Google Safe Browsing match (or VirusTotal malicious engine count &gt; 0) sets a **floor of 80**.

Heuristic contributions are **de-duplicated by finding type** and **capped at 45** so correlated URL tricks cannot drown out missing intel.

## Sample weights

See `backend/app/services/scoring.py` (`WEIGHT_GROUPS`) for the implemented values. HTTPS presence contributes 0.

## Confidence vs score

`evidence_quality` and `confidence` are returned separately so a high score from a list match is not confused with a pile of weak heuristics.
