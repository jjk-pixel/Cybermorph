from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.incident import Incident
from app.models.attack_path_step import AttackPathStep

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


@router.get("/")
def list_incidents(db: Session = Depends(get_db), limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    incidents = db.query(Incident).order_by(Incident.last_seen.desc(), Incident.id.desc()).offset(offset).limit(limit).all()
    return [
        {
            "id": i.id, "status": i.status, "source_asset_id": i.source_asset_id,
            "current_asset_id": i.current_asset_id, "target_asset_id": i.target_asset_id,
            "technique_id": i.technique_id, "confidence": i.confidence,
            "current_step": i.current_step, "total_steps": i.total_steps,
            "started_at": i.started_at, "last_seen": i.last_seen,
        }
        for i in incidents
    ]


@router.get("/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    steps = (
        db.query(AttackPathStep)
        .filter(AttackPathStep.incident_id == incident.id)
        .order_by(AttackPathStep.sequence)
        .all()
    )

    return {
        "id": incident.id, "status": incident.status, "source_asset_id": incident.source_asset_id,
        "current_asset_id": incident.current_asset_id, "target_asset_id": incident.target_asset_id,
        "technique_id": incident.technique_id, "confidence": incident.confidence,
        "current_step": incident.current_step, "total_steps": incident.total_steps,
        "started_at": incident.started_at, "last_seen": incident.last_seen,
        "steps": [
            {
                "id": s.id, "sequence": s.sequence, "source_asset_id": s.source_asset_id,
                "destination_asset_id": s.destination_asset_id, "status": s.status,
                "technique_id": s.technique_id, "evidence_type": s.evidence_type,
                "confidence": s.confidence, "detected_at": s.detected_at,
            }
            for s in steps
        ],
    }
