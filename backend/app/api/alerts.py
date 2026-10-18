from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.alert import Alert

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("/")
def list_alerts(
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    min_priority: int | None = Query(None, ge=1, le=4, description="Priorité Suricata maximale incluse (1 = la plus sévère)"),
):
    query = db.query(Alert)
    if min_priority is not None:
        query = query.filter(Alert.priority <= min_priority)
    alerts = query.order_by(Alert.last_seen.desc().nullslast(), Alert.id.desc()).offset(offset).limit(limit).all()
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
