from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.incident import Incident


ATTACK_RELEVANT_KEYWORDS = [
    "SCAN",
    "EXPLOIT",
    "EXPLOITATION",
    "BRUTE FORCE",
    "COMMAND INJECTION",
    "SQL INJECTION",
    "REMOTE CODE EXECUTION",
    "MALWARE",
    "SHELL",
]


def is_attack_relevant(alert: Alert) -> bool:
    text = " ".join([alert.message or "", alert.classification or ""]).upper()
    return any(keyword in text for keyword in ATTACK_RELEVANT_KEYWORDS)


def has_sufficient_severity(alert: Alert) -> bool:
    if alert.priority is None:
        return False
    return alert.priority <= 2


def get_asset_by_ip(db: Session, ip: str):
    if not ip:
        return None
    return db.query(Asset).filter(Asset.ip_address == ip).first()


def find_existing_incident(db: Session, source_asset_id, current_asset_id):
    cutoff = datetime.utcnow() - timedelta(minutes=15)
    return (
        db.query(Incident)
        .filter(
            Incident.status.in_(["detected", "progressing"]),
            Incident.source_asset_id == source_asset_id,
            Incident.current_asset_id == current_asset_id,
            Incident.last_seen >= cutoff,
        )
        .order_by(Incident.last_seen.desc())
        .first()
    )


def create_incident_from_alert(db: Session, alert: Alert) -> Incident | None:
    if not is_attack_relevant(alert):
        return None
    if not has_sufficient_severity(alert):
        return None

    source = get_asset_by_ip(db, alert.source_ip)
    target = get_asset_by_ip(db, alert.destination_ip)

    if not target:
        return None

    existing = find_existing_incident(db, source.id if source else None, target.id)
    if existing:
        existing.last_seen = datetime.utcnow()
        db.commit()
        db.refresh(existing)
        return existing

    incident = Incident(
        status="detected",
        source_asset_id=source.id if source else None,
        current_asset_id=target.id,
        target_asset_id=target.id,
        confidence=0.5,
        current_step=1,
        total_steps=1,
        technique_id=None,
        started_at=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        metadata_json={"trigger_alert_id": alert.id, "message": alert.message},
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident
