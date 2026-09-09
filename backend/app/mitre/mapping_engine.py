from sqlalchemy.orm import Session
from app.models.alert import Alert
from app.models.attack_technique import AttackTechnique, AlertTechniqueMapping
from app.mitre.technique_catalog import TECHNIQUES, MAPPING_RULES


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

    db.commit()
    print(f"[CYBERMORPH][MITRE] {new_mappings} nouveau(x) mapping(s) créé(s).")


if __name__ == "__main__":
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        apply_mitre_mapping(db)
    finally:
        db.close()
