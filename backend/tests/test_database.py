from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.database.base import Base
from app.models.scan import FindingModel, ScanModel


def test_scan_and_finding_crud() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session: Session = SessionLocal()
    now = datetime.now(timezone.utc)
    scan = ScanModel(
        id="11111111-1111-1111-1111-111111111111",
        client_id="22222222-2222-2222-2222-222222222222",
        display_url="https://example.com/",
        hostname="example.com",
        url_hash="abc",
        risk_score=10,
        risk_classification="low",
        status="completed",
        persisted=0,
        created_at=now,
        completed_at=now,
        expires_at=now + timedelta(hours=24),
        result_json="{}",
    )
    scan.findings.append(
        FindingModel(
            finding_type="ip_hostname",
            severity="medium",
            evidence_summary="host is ip",
            explanation="test",
            source="local_heuristics",
        )
    )
    session.add(scan)
    session.commit()

    loaded = session.scalar(select(ScanModel).where(ScanModel.hostname == "example.com"))
    assert loaded is not None
    assert loaded.findings[0].finding_type == "ip_hostname"

    session.delete(loaded)
    session.commit()
    assert session.scalar(select(ScanModel)) is None
    session.close()
