from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

ProviderStatus = Literal[
    "threat_detected",
    "no_threat_detected",
    "check_unavailable",
    "rate_limited",
    "not_configured",
    "incomplete",
]


@dataclass
class ProviderResult:
    provider: str
    status: ProviderStatus
    threat_categories: list[str] = field(default_factory=list)
    summary: str = ""
    explanation: str = ""
    limitations: str = ""
    stats: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "status": self.status,
            "threat_categories": self.threat_categories,
            "summary": self.summary,
            "explanation": self.explanation,
            "limitations": self.limitations,
            "stats": self.stats,
            "error": self.error,
        }


class ThreatProvider(Protocol):
    name: str

    async def check_url(self, url: str, authorized: bool) -> ProviderResult:
        ...
