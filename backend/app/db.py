"""
SQLite persistence layer.

SecurityEvent is the canonical persistence contract. The legacy API fields
(type/ip/detail/pattern) are generated only at the presentation boundary.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, Iterable, List, Optional
from uuid import uuid4

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Integer,
    JSON,
    String,
    create_engine,
    func,
    inspect,
    text,
)
from sqlalchemy.orm import declarative_base, sessionmaker

DB_PATH = os.getenv("LOGSENTINEL_DB", "logsentinel.db")
ENGINE = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=ENGINE, autoflush=False, autocommit=False)
Base = declarative_base()


class Alert(Base):
    """Canonical persisted security event."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)

    event_id = Column(String, unique=True, index=True, nullable=False)
    event_version = Column(String, nullable=False, default="1.0")
    observed_at = Column(String, nullable=False)

    event_type = Column(String, index=True, nullable=False)
    detector = Column(String, index=True, nullable=False)
    rule_id = Column(String, index=True, nullable=False)

    severity = Column(String, index=True, nullable=False, default="medium")
    confidence = Column(Float, nullable=False, default=0.0)

    source_ip = Column(String, index=True)
    target = Column(String)
    evidence = Column(String)
    detail = Column(String)
    pattern = Column(String)

    event_metadata = Column("metadata", JSON, nullable=False, default=dict)

    # Existing API/database compatibility field.
    created_at = Column(DateTime, server_default=func.now(), index=True)


class IPTraffic(Base):
    """Rolling per-IP-per-window request counts."""

    __tablename__ = "ip_traffic"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String, index=True, nullable=False)
    window_start = Column(Integer, index=True, nullable=False)
    count = Column(Integer, default=0)


# Existing databases created before the SecurityEvent model need additive
# migration because SQLAlchemy create_all() does not alter existing tables.
_EVENT_COLUMNS = {
    "event_id": "VARCHAR",
    "event_version": "VARCHAR",
    "observed_at": "VARCHAR",
    "event_type": "VARCHAR",
    "detector": "VARCHAR",
    "rule_id": "VARCHAR",
    "severity": "VARCHAR",
    "confidence": "FLOAT",
    "source_ip": "VARCHAR",
    "target": "VARCHAR",
    "evidence": "VARCHAR",
    "detail": "VARCHAR",
    "pattern": "VARCHAR",
    "metadata": "JSON",
}


def _migrate_alerts_table() -> None:
    """Upgrade legacy alerts tables without assuming legacy columns exist."""
    with ENGINE.begin() as connection:
        rows = connection.execute(
            text("PRAGMA table_info(alerts)")
        ).fetchall()

        columns = {row[1] for row in rows}

        if not columns:
            return

        required_columns = {
            "event_id": "TEXT",
            "event_version": "TEXT",
            "event_type": "TEXT",
            "detector": "TEXT",
            "rule_id": "TEXT",
            "severity": "TEXT",
            "confidence": "REAL",
            "source_ip": "TEXT",
            "target": "TEXT",
            "evidence": "TEXT",
            "observed_at": "TEXT",
            "metadata": "TEXT",
        }

        for column, sql_type in required_columns.items():
            if column not in columns:
                connection.execute(
                    text(
                        f"ALTER TABLE alerts "
                        f"ADD COLUMN {column} {sql_type}"
                    )
                )

        # Re-read the schema after ALTER TABLE operations.
        rows = connection.execute(
            text("PRAGMA table_info(alerts)")
        ).fetchall()
        columns = {row[1] for row in rows}

        def expr(column: str, fallback: str) -> str:
            return column if column in columns else fallback

        legacy_type = expr("type", "'Unknown'")
        legacy_ip = expr("ip", "NULL")
        legacy_pattern = expr("pattern", "NULL")
        legacy_detail = expr("detail", "NULL")

        connection.execute(
            text(
                f"""
                UPDATE alerts
                SET event_id = COALESCE(
                        event_id,
                        'legacy-' || id
                    ),
                    event_version = COALESCE(
                        event_version,
                        '1.0'
                    ),
                    observed_at = COALESCE(
                        observed_at,
                        created_at,
                        datetime('now')
                    ),
                    event_type = COALESCE(
                        event_type,
                        {legacy_type},
                        'Unknown'
                    ),
                    detector = COALESCE(
                        detector,
                        CASE {legacy_type}
                            WHEN 'Brute Force'
                                THEN 'legacy.brute_force'
                            WHEN 'SQL Injection'
                                THEN 'legacy.sql_injection'
                            WHEN 'XSS'
                                THEN 'legacy.xss'
                            WHEN 'Path Traversal'
                                THEN 'legacy.path_traversal'
                            WHEN 'Traffic Anomaly'
                                THEN 'legacy.anomaly'
                            ELSE 'legacy.unknown'
                        END
                    ),
                    rule_id = COALESCE(
                        rule_id,
                        CASE {legacy_type}
                            WHEN 'Brute Force'
                                THEN 'auth.brute_force'
                            WHEN 'SQL Injection'
                                THEN 'web.sql_injection'
                            WHEN 'XSS'
                                THEN 'web.xss'
                            WHEN 'Path Traversal'
                                THEN 'web.path_traversal'
                            WHEN 'Traffic Anomaly'
                                THEN 'traffic.volume_anomaly'
                            ELSE 'legacy.unknown'
                        END
                    ),
                    severity = COALESCE(
                        severity,
                        'medium'
                    ),
                    confidence = COALESCE(
                        confidence,
                        0.0
                    ),
                    source_ip = COALESCE(
                        source_ip,
                        {legacy_ip}
                    ),
                    evidence = COALESCE(
                        evidence,
                        {legacy_pattern},
                        {legacy_detail}
                    ),
                    metadata = COALESCE(
                        metadata,
                        '{{}}'
                    )
                """
            )
        )

def init_db() -> None:
    Base.metadata.create_all(ENGINE)
    _migrate_alerts_table()


def _canonical_event(a: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a detector event into the SecurityEvent persistence shape."""

    event_type = a.get("event_type") or a.get("type") or "Unknown"
    source_ip = a.get("source_ip", a.get("ip"))

    return {
        "event_id": a.get("event_id") or str(uuid4()),
        "event_version": a.get("event_version", "1.0"),
        "observed_at": a.get("observed_at") or "",
        "event_type": event_type,
        "detector": a.get("detector", "legacy.unknown"),
        "rule_id": a.get("rule_id", "legacy.unknown"),
        "severity": a.get("severity", "medium"),
        "confidence": float(a.get("confidence", 0.0)),
        "source_ip": source_ip,
        "target": a.get("target"),
        "evidence": a.get("evidence"),
        "detail": a.get("detail"),
        "pattern": a.get("pattern") or a.get("evidence"),
        "event_metadata": a.get("metadata") or {},
    }


def _presentation(row: Alert) -> Dict[str, Any]:
    """Return API/dashboard representation without changing the DB model."""

    return {
        "id": row.id,
        "event_id": row.event_id,
        "event_version": row.event_version,
        "observed_at": row.observed_at,
        "event_type": row.event_type,
        "detector": row.detector,
        "rule_id": row.rule_id,
        "severity": row.severity,
        "confidence": row.confidence,
        "source_ip": row.source_ip,
        "target": row.target,
        "evidence": row.evidence,
        "detail": row.detail,
        "pattern": row.pattern or row.evidence,

        # Legacy API/dashboard compatibility.
        "type": row.event_type,
        "ip": row.source_ip,

        "metadata": row.event_metadata or {},
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def save_alerts(alerts: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    session = SessionLocal()
    saved: List[Dict[str, Any]] = []

    try:
        for raw in alerts:
            a = _canonical_event(raw)

            row = Alert(**a)
            session.add(row)
            session.flush()

            saved.append(_presentation(row))

        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    return saved


def get_alerts(
    limit: int = 100,
    alert_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    session = SessionLocal()

    try:
        query = session.query(Alert).order_by(Alert.id.desc())

        if alert_type:
            query = query.filter(Alert.event_type == alert_type)

        rows = query.limit(limit).all()
        return [_presentation(row) for row in rows]
    finally:
        session.close()


def get_stats() -> Dict[str, Any]:
    session = SessionLocal()

    try:
        total = session.query(func.count(Alert.id)).scalar() or 0

        by_type = dict(
            session.query(
                Alert.event_type,
                func.count(Alert.id),
            )
            .group_by(Alert.event_type)
            .all()
        )

        top_ips = (
            session.query(
                Alert.source_ip,
                func.count(Alert.id).label("c"),
            )
            .filter(Alert.source_ip.isnot(None))
            .group_by(Alert.source_ip)
            .order_by(func.count(Alert.id).desc())
            .limit(5)
            .all()
        )

        return {
            "total_alerts": total,
            "by_type": by_type,
            "top_ips": [
                {"ip": ip, "count": count}
                for ip, count in top_ips
            ],
        }
    finally:
        session.close()


WINDOW_SECONDS = 60


def record_ip_traffic(ip_counts: Dict[str, int]) -> None:
    """Add this batch's per-IP counts into the current time window."""
    session = SessionLocal()
    window_start = int(
        time.time() // WINDOW_SECONDS * WINDOW_SECONDS
    )

    try:
        for ip, count in ip_counts.items():
            row = (
                session.query(IPTraffic)
                .filter(
                    IPTraffic.ip == ip,
                    IPTraffic.window_start == window_start,
                )
                .first()
            )

            if row:
                row.count += count
            else:
                session.add(
                    IPTraffic(
                        ip=ip,
                        window_start=window_start,
                        count=count,
                    )
                )

        session.commit()
    finally:
        session.close()


def get_ip_history(ip: str, windows: int = 20) -> List[int]:
    """Past N window counts for an IP, most recent last."""
    session = SessionLocal()

    try:
        rows = (
            session.query(IPTraffic.count)
            .filter(IPTraffic.ip == ip)
            .order_by(IPTraffic.window_start.desc())
            .limit(windows)
            .all()
        )

        return [row[0] for row in reversed(rows)]
    finally:
        session.close()
