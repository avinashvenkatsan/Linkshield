from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class ScanModel(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(36), index=True)
    display_url: Mapped[str] = mapped_column(String(512))
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    url_hash: Mapped[str] = mapped_column(String(64), index=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_classification: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    persisted: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    result_json: Mapped[str] = mapped_column(Text)

    findings: Mapped[list["FindingModel"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    provider_results: Mapped[list["ProviderResultModel"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class FindingModel(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    finding_type: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    evidence_summary: Mapped[str] = mapped_column(Text)
    explanation: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(64))

    scan: Mapped[ScanModel] = relationship(back_populates="findings")


class ProviderResultModel(Base):
    __tablename__ = "provider_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))
    threat_categories: Mapped[str] = mapped_column(String(255), default="")
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(String(128), nullable=True)

    scan: Mapped[ScanModel] = relationship(back_populates="provider_results")
