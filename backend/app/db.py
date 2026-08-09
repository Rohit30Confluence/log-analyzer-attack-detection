"""
SQLite persistence layer. Zero external services — just a local file
(logsentinel.db) via SQLAlchemy. This is what gives the anomaly detector
a real historical baseline instead of only looking at whatever batch of
logs happens to be in memory.
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Integer,
    String,
    create_engine,
    func,
)
from sqlalchemy.orm import declarative_base, sessionmaker

DB_PATH = os.getenv("LOGSENTINEL_DB", "logsentinel.db")
ENGINE = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=ENGINE, autoflush=False, autocommit=False)
Base = declarative_base()


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(String, index=True, nullable=False)
    ip = Column(String, index=True)
    detail = Column(String)
    pattern = Column(String)
    severity = Column(String, default="medium")
    created_at = Column(DateTime, server_default=func.now(), index=True)


class IPTraffic(Base):
    """Rolling per-IP-per-window request counts, used as the anomaly baseline."""

    __tablename__ = "ip_traffic"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String, index=True, nullable=False)
    window_start = Column(Integer, index=True, nullable=False)  # unix epoch, floored to window
    count = Column(Integer, default=0)


def init_db() -> None:
    Base.metadata.create_all(ENGINE)


def save_alerts(alerts: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    session = SessionLocal()
    saved = []
    try:
        for a in alerts:
            row = Alert(
                type=a.get("type", "Unknown"),
                ip=a.get("ip"),
                detail=a.get("detail"),
                pattern=a.get("pattern"),
                severity=a.get("severity", "medium"),
            )
            session.add(row)
            session.flush()
            saved.append({
                "id": row.id,
                "type": row.type,
                "ip": row.ip,
                "detail": row.detail,
                "pattern": row.pattern,
                "severity": row.severity,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            })
        session.commit()
    finally:
        session.close()
    return saved


def get_alerts(limit: int = 100, alert_type: Optional[str] = None) -> List[Dict[str, Any]]:
    session = SessionLocal()
    try:
        q = session.query(Alert).order_by(Alert.id.desc())
        if alert_type:
            q = q.filter(Alert.type == alert_type)
        rows = q.limit(limit).all()
        return [
            {
                "id": r.id,
                "type": r.type,
                "ip": r.ip,
                "detail": r.detail,
                "pattern": r.pattern,
                "severity": r.severity,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]
    finally:
        session.close()


def get_stats() -> Dict[str, Any]:
    session = SessionLocal()
    try:
        total = session.query(func.count(Alert.id)).scalar() or 0
        by_type = dict(
            session.query(Alert.type, func.count(Alert.id)).group_by(Alert.type).all()
        )
        top_ips = (
            session.query(Alert.ip, func.count(Alert.id).label("c"))
            .filter(Alert.ip.isnot(None))
            .group_by(Alert.ip)
            .order_by(func.count(Alert.id).desc())
            .limit(5)
            .all()
        )
        return {
            "total_alerts": total,
            "by_type": by_type,
            "top_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
        }
    finally:
        session.close()


WINDOW_SECONDS = 60


def record_ip_traffic(ip_counts: Dict[str, int]) -> None:
    """Add this batch's per-IP counts into the current time window's bucket."""
    session = SessionLocal()
    window_start = int(time.time() // WINDOW_SECONDS * WINDOW_SECONDS)
    try:
        for ip, count in ip_counts.items():
            row = (
                session.query(IPTraffic)
                .filter(IPTraffic.ip == ip, IPTraffic.window_start == window_start)
                .first()
            )
            if row:
                row.count += count
            else:
                session.add(IPTraffic(ip=ip, window_start=window_start, count=count))
        session.commit()
    finally:
        session.close()


def get_ip_history(ip: str, windows: int = 20) -> List[int]:
    """Past N window counts for an IP, most recent last. Used as the baseline."""
    session = SessionLocal()
    try:
        rows = (
            session.query(IPTraffic.count)
            .filter(IPTraffic.ip == ip)
            .order_by(IPTraffic.window_start.desc())
            .limit(windows)
            .all()
        )
        return [r[0] for r in reversed(rows)]
    finally:
        session.close()
