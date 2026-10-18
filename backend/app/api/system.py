from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.collector import CollectorRun
from app.monitoring.health import system_health

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/health")
def get_system_health(db: Session = Depends(get_db)):
    """Santé de la collecte : cycles, étapes, capteurs, fraîcheur par actif, problèmes à traiter."""
    return system_health(db)


@router.get("/runs")
def list_runs(
    db: Session = Depends(get_db),
    collector: str | None = Query(None, pattern="^[a-z_]{2,32}$"),
    status: str | None = Query(None, pattern="^(success|partial|failed|interrupted|skipped)$"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    query = db.query(CollectorRun)
    if collector:
        query = query.filter(CollectorRun.collector == collector)
    if status:
        query = query.filter(CollectorRun.status == status)
    rows = query.order_by(CollectorRun.started_at.desc(), CollectorRun.id.desc()).offset(offset).limit(limit).all()
    return [
        {"id": r.id, "cycle_id": r.cycle_id, "collector": r.collector, "status": r.status, "started_at": r.started_at,
         "finished_at": r.finished_at, "duration_s": r.duration_s, "error": r.error, "stats": r.stats}
        for r in rows
    ]
