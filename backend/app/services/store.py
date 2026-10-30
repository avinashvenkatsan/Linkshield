from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from sqlalchemy import func, select

from app.core.config import get_settings
from app.database.session import SessionLocal, get_engine
from app.models.scan import FindingModel, ProviderResultModel, ScanModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanStore(Protocol):
    def save(self, record: dict[str, Any]) -> None: ...
    def get(self, scan_id: str, client_id: str) -> dict[str, Any] | None: ...
    def list_for_client(self, client_id: str) -> list[dict[str, Any]]: ...
    def delete(self, scan_id: str, client_id: str) -> bool: ...
    def clear_client(self, client_id: str) -> int: ...
    def stats(self) -> dict[str, Any]: ...


class MemoryStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: dict[str, dict[str, Any]] = {}

    def _purge(self) -> None:
        now = utcnow().isoformat()
        expired = [k for k, v in self._data.items() if v.get("expires_at", now) <= now]
        for k in expired:
            self._data.pop(k, None)

    def save(self, record: dict[str, Any]) -> None:
        with self._lock:
            self._purge()
            self._data[record["id"]] = record

    def get(self, scan_id: str, client_id: str) -> dict[str, Any] | None:
        with self._lock:
            self._purge()
            item = self._data.get(scan_id)
            if not item or item["client_id"] != client_id:
                return None
            return item

    def list_for_client(self, client_id: str) -> list[dict[str, Any]]:
        with self._lock:
            self._purge()
            items = [v for v in self._data.values() if v["client_id"] == client_id]
            return sorted(items, key=lambda x: x["created_at"], reverse=True)

    def delete(self, scan_id: str, client_id: str) -> bool:
        with self._lock:
            item = self._data.get(scan_id)
            if not item or item["client_id"] != client_id:
                return False
            del self._data[scan_id]
            return True

    def clear_client(self, client_id: str) -> int:
        with self._lock:
            keys = [k for k, v in self._data.items() if v["client_id"] == client_id]
            for k in keys:
                del self._data[k]
            return len(keys)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            self._purge()
            values = list(self._data.values())
        return _summarize(values, persistence="memory")


class DatabaseStore:
    def save(self, record: dict[str, Any]) -> None:
        session = SessionLocal()
        try:
            existing = session.get(ScanModel, record["id"])
            if existing:
                session.delete(existing)
                session.flush()
            model = ScanModel(
                id=record["id"],
                client_id=record["client_id"],
                display_url=record["display_url"],
                hostname=record["hostname"],
                url_hash=record["url_hash"],
                risk_score=record.get("risk_score"),
                risk_classification=record.get("risk_classification") or "unknown",
                status=record["status"],
                persisted=1 if record.get("save_history") else 0,
                created_at=datetime.fromisoformat(record["created_at"]),
                completed_at=datetime.fromisoformat(record["completed_at"]) if record.get("completed_at") else None,
                expires_at=datetime.fromisoformat(record["expires_at"]),
                result_json=json.dumps(record, default=str),
            )
            session.add(model)
            for finding in record.get("findings") or []:
                session.add(
                    FindingModel(
                        scan_id=record["id"],
                        finding_type=finding.get("type", "unknown"),
                        severity=finding.get("severity", "info"),
                        evidence_summary=(finding.get("evidence") or "")[:2000],
                        explanation=(finding.get("explanation") or "")[:4000],
                        source=finding.get("source", "local"),
                    )
                )
            now = utcnow()
            for provider in record.get("providers") or []:
                session.add(
                    ProviderResultModel(
                        scan_id=record["id"],
                        provider=provider.get("provider", "unknown"),
                        status=provider.get("status", "incomplete"),
                        threat_categories=",".join(provider.get("threat_categories") or []),
                        checked_at=now,
                        error=(provider.get("error") or None),
                    )
                )
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get(self, scan_id: str, client_id: str) -> dict[str, Any] | None:
        session = SessionLocal()
        try:
            row = session.get(ScanModel, scan_id)
            if not row or row.client_id != client_id:
                return None
            if row.expires_at.replace(tzinfo=timezone.utc) < utcnow():
                session.delete(row)
                session.commit()
                return None
            return json.loads(row.result_json)
        finally:
            session.close()

    def list_for_client(self, client_id: str) -> list[dict[str, Any]]:
        session = SessionLocal()
        try:
            rows = session.scalars(
                select(ScanModel)
                .where(ScanModel.client_id == client_id, ScanModel.expires_at > utcnow())
                .order_by(ScanModel.created_at.desc())
            ).all()
            return [json.loads(r.result_json) for r in rows]
        finally:
            session.close()

    def delete(self, scan_id: str, client_id: str) -> bool:
        session = SessionLocal()
        try:
            row = session.get(ScanModel, scan_id)
            if not row or row.client_id != client_id:
                return False
            session.delete(row)
            session.commit()
            return True
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def clear_client(self, client_id: str) -> int:
        session = SessionLocal()
        try:
            rows = session.scalars(select(ScanModel).where(ScanModel.client_id == client_id)).all()
            count = len(rows)
            for row in rows:
                session.delete(row)
            session.commit()
            return count
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def stats(self) -> dict[str, Any]:
        session = SessionLocal()
        try:
            total = session.scalar(select(func.count()).select_from(ScanModel)) or 0
            def _count(label: str) -> int:
                return session.scalar(
                    select(func.count()).where(ScanModel.risk_classification == label)
                ) or 0

            recent_rows = session.scalars(select(ScanModel).order_by(ScanModel.created_at.desc()).limit(8)).all()
            recent = [
                {
                    "id": r.id,
                    "display_url": r.display_url,
                    "hostname": r.hostname,
                    "risk_score": r.risk_score,
                    "risk_classification": r.risk_classification,
                    "status": r.status,
                    "created_at": r.created_at.isoformat(),
                    "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                }
                for r in recent_rows
            ]
            incomplete = session.scalar(select(func.count()).where(ScanModel.status != "completed")) or 0
            return {
                "total": int(total),
                "high": int(_count("high")),
                "medium": int(_count("medium")),
                "low": int(_count("low")),
                "unknown": int(_count("unknown")),
                "incomplete": int(incomplete),
                "recent": recent,
                "persistence": "postgresql",
            }
        finally:
            session.close()


def _summarize(values: list[dict[str, Any]], persistence: str) -> dict[str, Any]:
    def cls_count(name: str) -> int:
        return sum(1 for v in values if v.get("risk_classification") == name)

    recent = sorted(values, key=lambda x: x.get("created_at", ""), reverse=True)[:8]
    return {
        "total": len(values),
        "high": cls_count("high"),
        "medium": cls_count("medium"),
        "low": cls_count("low"),
        "unknown": cls_count("unknown"),
        "incomplete": sum(1 for v in values if v.get("status") != "completed"),
        "recent": [
            {
                "id": r["id"],
                "display_url": r["display_url"],
                "hostname": r["hostname"],
                "risk_score": r.get("risk_score"),
                "risk_classification": r.get("risk_classification"),
                "status": r["status"],
                "created_at": r["created_at"],
                "completed_at": r.get("completed_at"),
            }
            for r in recent
        ],
        "persistence": persistence,
    }


_store: ScanStore | None = None


def get_store() -> ScanStore:
    global _store
    if _store is None:
        if get_settings().database_enabled and get_engine() is not None:
            _store = DatabaseStore()
        else:
            _store = MemoryStore()
    return _store


def ttl_for(save_history: bool) -> timedelta:
    settings = get_settings()
    if save_history:
        return timedelta(days=settings.persisted_scan_ttl_days)
    return timedelta(hours=settings.default_scan_ttl_hours)
