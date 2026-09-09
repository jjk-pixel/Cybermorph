from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.alert import Alert

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("/")
def list_alerts(db: Session = Depends(get_db), limit: int = 50):
    alerts = db.query(Alert).order_by(Alert.last_seen.desc()).limit(limit).all()
    return [
        {
            "id": a.id,
            "source_ip": a.source_ip,
            "destination_ip": a.destination_ip,
            "protocol": a.protocol,
            "message": a.message,
            "classification": a.classification,
            "priority": a.priority,
            "occurrence_count": a.occurrence_count,
            "first_seen": a.first_seen,
            "last_seen": a.last_seen,
        }
        for a in alerts
    ]
