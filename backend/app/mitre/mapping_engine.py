from sqlalchemy.orm import Session
from app.models.alert import Alert
from app.models.attack_technique import AttackTechnique, AlertTechniqueMapping

from app.mitre.technique_catalog import DEVIATION_RULES, MAPPING_RULES, MIN_OBSERVATIONS, TECHNIQUES
from app.models.behavior import Deviation
from app.models.correlation import TechniqueEvidence


def seed_techniques(db: Session):
    """Insère le référentiel de techniques s'il n'existe pas encore."""
    for t in TECHNIQUES:
        existing = db.query(AttackTechnique).filter(AttackTechnique.technique_id == t["technique_id"]).first()
        if not existing:
            db.add(AttackTechnique(**t))
    db.commit()


def match_technique_for_alert(alert: Alert) -> dict | None:
    """
    Cherche une correspondance entre le contenu de l'alerte et une règle de mapping.
    Ne force jamais une correspondance : retourne None si rien ne matche clairement,
    plutôt que d'assigner une technique par défaut peu fiable.
    """
    haystack = f"{alert.message or ''} {alert.classification or ''}".lower()

    for rule in MAPPING_RULES:
        if any(keyword in haystack for keyword in rule["keywords"]):
            return rule

    return None


def _upsert_evidence(db: Session, technique: AttackTechnique, event_type: str, event_id: int, *, status: str,
                     source: str, confidence: float, reason: str, observations: int, first_seen, last_seen) -> bool:
    evidence = db.query(TechniqueEvidence).filter_by(technique_ref=technique.id, event_type=event_type, event_id=event_id).first()
    created = evidence is None
    if created:
        evidence = TechniqueEvidence(technique_ref=technique.id, event_type=event_type, event_id=event_id)
        db.add(evidence)
    evidence.status, evidence.source, evidence.confidence, evidence.reason = status, source, confidence, reason
    evidence.observations, evidence.first_seen, evidence.last_seen = observations, first_seen, last_seen
    return created


def alert_status(occurrences: int | None) -> str:
    """Signature IDS : technique inférée si l'événement se répète, non confirmée s'il est isolé."""
    return "inferred" if (occurrences or 0) >= MIN_OBSERVATIONS else "unconfirmed"


def refresh_technique_evidence(db: Session) -> dict:
    """Preuves ATT&CK à jour : alertes déjà rapprochées (compteurs) et écarts mesurés dans les flux."""
    techniques = {t.technique_id: t for t in db.query(AttackTechnique).all()}
    stats = {"alert_evidence_new": 0, "deviation_evidence_new": 0}
    alerts = {a.id: a for a in db.query(Alert).all()}
    for mapping in db.query(AlertTechniqueMapping).all():
        technique = db.get(AttackTechnique, mapping.technique_id)
        alert = alerts.get(mapping.alert_id)
        if not technique or not alert:
            continue
        if _upsert_evidence(db, technique, "alert", alert.id, status=alert_status(alert.occurrence_count),
                            source="suricata_signature", confidence=mapping.confidence, reason=mapping.matched_on,
                            observations=alert.occurrence_count or 1, first_seen=alert.first_seen, last_seen=alert.last_seen):
            stats["alert_evidence_new"] += 1
    for deviation in db.query(Deviation).filter(Deviation.kind.in_(list(DEVIATION_RULES))).all():
        rule = DEVIATION_RULES[deviation.kind]
        technique = techniques.get(rule["technique_id"])
        if not technique:
            continue
        if _upsert_evidence(db, technique, "deviation", deviation.id, status="observed", source="flow_analysis",
                            confidence=rule["confidence"], reason=rule["reason"], observations=deviation.occurrences or 1,
                            first_seen=deviation.first_seen, last_seen=deviation.last_seen):
            stats["deviation_evidence_new"] += 1
    db.flush()
    return stats


def apply_mitre_mapping(db: Session):
    """Parcourt les alertes non encore mappées et tente de les associer à une technique ATT&CK."""
    seed_techniques(db)

    alerts = db.query(Alert).all()
    new_mappings = 0

    for alert in alerts:
        already_mapped = (
            db.query(AlertTechniqueMapping)
            .filter(AlertTechniqueMapping.alert_id == alert.id)
            .first()
        )
        if already_mapped:
            continue

        rule = match_technique_for_alert(alert)
        if not rule:
            continue

        technique = db.query(AttackTechnique).filter(AttackTechnique.technique_id == rule["technique_id"]).first()
        if not technique:
            continue

        mapping = AlertTechniqueMapping(
            alert_id=alert.id,
            technique_id=technique.id,
            confidence=rule["confidence"],
            matched_on=rule["reason"],
        )
        db.add(mapping)
        new_mappings += 1
        print(f"[CYBERMORPH][MITRE] Alerte #{alert.id} ({alert.message[:40]}...) → {technique.technique_id} ({technique.name}), confiance={rule['confidence']}")

    db.flush()
    stats = refresh_technique_evidence(db)
    db.commit()
    print(f"[CYBERMORPH][MITRE] {new_mappings} nouveau(x) mapping(s) créé(s).")
    return {"mappings_new": new_mappings, **stats}


if __name__ == "__main__":
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        apply_mitre_mapping(db)
    finally:
        db.close()
