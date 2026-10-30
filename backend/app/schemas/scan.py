from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class ScanCreateRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    save_history: bool = False
    allow_external_intel: bool = False

    @field_validator("url")
    @classmethod
    def strip_url(cls, value: str) -> str:
        return value.strip()


class ScanSummary(BaseModel):
    id: str
    display_url: str
    hostname: str
    risk_score: Optional[float]
    risk_classification: str
    status: str
    created_at: str
    completed_at: Optional[str]


class ScanListResponse(BaseModel):
    items: list[ScanSummary]
    total: int


class StatsResponse(BaseModel):
    total: int
    high: int
    medium: int
    low: int
    unknown: int
    incomplete: int
    recent: list[ScanSummary]
    persistence: str
