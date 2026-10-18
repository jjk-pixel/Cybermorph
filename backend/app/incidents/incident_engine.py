from datetime import datetime, timedelta, UTC
from sqlalchemy.orm import Session
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.incident import Incident
from app.models.attack_technique import AttackTechnique, AlertTechniqueMapping


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

ACTIVE_STATUSES = ("detected", "progressing")

# Fenêtre de rattachement d'une alerte à un incident existant
CORRELATION_WINDOW = timedelta(minutes=15)

# Au-delà de ce délai sans nouvelle activité, un incident actif passe en "dormant"
# (il n'est pas clos : seul un analyste peut décider qu'un incident est résolu)
DORMANT_AFTER = timedelta(hours=1)


def utcnow() -> datetime:
    """Horodatage UTC naïf, cohérent avec les colonnes DateTime sans fuseau des incidents."""
    return datetime.now(UTC).replace(tzinfo=None)


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


def find_existing_incident(db: Session, source_asset_id, target_asset_id):
    # Rattachement par (source, cible d'origine) : current_asset_id change quand l'incident progresse
    cutoff = utcnow() - CORRELATION_WINDOW
    source_filter = (
        Incident.source_asset_id.is_(None) if source_asset_id is None
        else Incident.source_asset_id == source_asset_id
    )
    return (
        db.query(Incident)
        .filter(
            Incident.status.in_(ACTIVE_STATUSES),
            source_filter,
            Incident.target_asset_id == target_asset_id,
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
        existing.last_seen = utcnow()
        db.commit()
        db.refresh(existing)
        return existing

    technique_id = None
    mapping = db.query(AlertTechniqueMapping).filter(AlertTechniqueMapping.alert_id == alert.id).first()
    if mapping:
        technique = db.query(AttackTechnique).filter(AttackTechnique.id == mapping.technique_id).first()
        technique_id = technique.technique_id if technique else None

    incident = Incident(
        status="detected",
        source_asset_id=source.id if source else None,
        current_asset_id=target.id,
        target_asset_id=target.id,
        confidence=0.5,
        current_step=1,
        total_steps=1,
        technique_id=technique_id,
        started_at=utcnow(),
        last_seen=utcnow(),
        metadata_json={"trigger_alert_id": alert.id, "message": alert.message},
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


def mark_dormant_incidents(db: Session) -> int:
    """Passe en "dormant" les incidents actifs sans activité depuis DORMANT_AFTER. Aucune suppression."""
    cutoff = utcnow() - DORMANT_AFTER
    stale = (
        db.query(Incident)
        .filter(Incident.status.in_(ACTIVE_STATUSES), Incident.last_seen < cutoff)
        .all()
    )
    for incident in stale:
        incident.status = "dormant"
    db.commit()
    return len(stale)
