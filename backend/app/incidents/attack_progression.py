from datetime import datetime
from sqlalchemy.orm import Session
from app.attack_graph.graph_engine import build_graph
from app.models.incident import Incident
from app.models.attack_path_step import AttackPathStep


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
        if destination_id in existing_destinations:
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
    incident.last_seen = datetime.utcnow()

    db.commit()
    return step
