from sqlalchemy.orm import Session
from app.attack_graph.graph_engine import build_graph
from app.incidents.incident_engine import utcnow, is_attack_relevant
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.incident import Incident
from app.models.attack_path_step import AttackPathStep
from app.models.attack_technique import AttackTechnique, AlertTechniqueMapping


def get_possible_next_assets(db: Session, current_asset_id: int):
    graph = build_graph(db)
    if current_asset_id not in graph:
        return []
    return list(graph.successors(current_asset_id))


def create_potential_steps(db: Session, incident: Incident):
    next_assets = get_possible_next_assets(db, incident.current_asset_id)

    existing_destinations = {
        step.destination_asset_id
        for step in db.query(AttackPathStep).filter(AttackPathStep.incident_id == incident.id).all()
    }

    for destination_id in next_assets:
        if destination_id in existing_destinations or destination_id == incident.current_asset_id:
            continue
        step = AttackPathStep(
            incident_id=incident.id,
            sequence=incident.current_step + 1,
            source_asset_id=incident.current_asset_id,
            destination_asset_id=destination_id,
            status="potential",
            confidence=0.3,
        )
        db.add(step)
    db.flush()
    incident.total_steps = max(
        [incident.current_step]
        + [s.sequence for s in db.query(AttackPathStep).filter(AttackPathStep.incident_id == incident.id).all()]
    )
    db.commit()


def confirm_step(db: Session, incident: Incident, destination_asset_id: int,
                  evidence_type: str, confidence: float, technique_id: str | None = None):
    step = (
        db.query(AttackPathStep)
        .filter(
            AttackPathStep.incident_id == incident.id,
            AttackPathStep.source_asset_id == incident.current_asset_id,
            AttackPathStep.destination_asset_id == destination_asset_id,
            AttackPathStep.status == "potential",
        )
        .first()
    )
    if not step:
        return None

    step.status = "confirmed"
    step.evidence_type = evidence_type
    step.confidence = confidence
    step.technique_id = technique_id

    incident.current_asset_id = destination_asset_id
    incident.current_step += 1
    incident.status = "progressing"
    incident.confidence = max(incident.confidence or 0.0, confidence)
    incident.last_seen = utcnow()

    db.commit()
    return step


def _technique_for_alert(db: Session, alert: Alert) -> tuple[str | None, float]:
    mapping = db.query(AlertTechniqueMapping).filter(AlertTechniqueMapping.alert_id == alert.id).first()
    if not mapping:
        return None, 0.0
    technique = db.query(AttackTechnique).filter(AttackTechnique.id == mapping.technique_id).first()
    return (technique.technique_id if technique else None), mapping.confidence


def advance_incident(db: Session, incident: Incident) -> AttackPathStep | None:
    """
    Confirme une étape potentielle quand une alerte IDS pertinente montre l'asset courant
    attaquant l'une de ses destinations possibles, après le début de l'incident.
    """
    current = db.query(Asset).filter(Asset.id == incident.current_asset_id).first()
    if not current:
        return None

    potential_steps = (
        db.query(AttackPathStep)
        .filter(
            AttackPathStep.incident_id == incident.id,
            AttackPathStep.source_asset_id == incident.current_asset_id,
            AttackPathStep.status == "potential",
        )
        .all()
    )
    if not potential_steps:
        return None

    destinations = {
        a.ip_address: a.id
        for a in db.query(Asset).filter(Asset.id.in_([s.destination_asset_id for s in potential_steps])).all()
    }

    candidate_alerts = (
        db.query(Alert)
        .filter(Alert.source_ip == current.ip_address, Alert.destination_ip.in_(list(destinations)))
        .order_by(Alert.priority.asc(), Alert.last_seen.desc())
        .all()
    )

    started_at = incident.started_at
    for alert in candidate_alerts:
        if not is_attack_relevant(alert):
            continue
        last_seen = alert.last_seen.replace(tzinfo=None) if alert.last_seen else None
        if started_at and last_seen and last_seen < started_at:
            continue

        technique_id, mapping_confidence = _technique_for_alert(db, alert)
        confidence = round(max(0.6, mapping_confidence), 2)
        step = confirm_step(
            db, incident, destinations[alert.destination_ip],
            evidence_type="ids_alert", confidence=confidence, technique_id=technique_id,
        )
        if step:
            return step

    return None
