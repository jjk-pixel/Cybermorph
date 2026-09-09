from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.attack_technique import AttackTechnique, AlertTechniqueMapping
from app.models.alert import Alert

router = APIRouter(prefix="/api/attack-techniques", tags=["mitre-attack"])


@router.get("/")
def list_techniques(db: Session = Depends(get_db)):
    techniques = db.query(AttackTechnique).all()
    return [
        {
            "technique_id": t.technique_id,
            "name": t.name,
            "tactic": t.tactic,
            "description": t.description,
            "platform": t.platform,
        }
        for t in techniques
    ]


@router.get("/observed")
def list_observed_techniques(db: Session = Depends(get_db)):
    """Techniques réellement observées dans ce lab, avec le détail des alertes corroborantes."""
    mappings = db.query(AlertTechniqueMapping).all()
    result = {}

    for m in mappings:
        technique = db.query(AttackTechnique).filter(AttackTechnique.id == m.technique_id).first()
        alert = db.query(Alert).filter(Alert.id == m.alert_id).first()
        if not technique or not alert:
            continue

        key = technique.technique_id
        if key not in result:
            result[key] = {
                "technique_id": technique.technique_id,
                "name": technique.name,
                "tactic": technique.tactic,
                "alerts": [],
            }

        result[key]["alerts"].append({
            "alert_id": alert.id,
            "message": alert.message,
            "occurrence_count": alert.occurrence_count,
            "confidence": m.confidence,
            "matched_on": m.matched_on,
        })

    return list(result.values())
