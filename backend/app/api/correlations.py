from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.correlation import Correlation

router = APIRouter(prefix="/api/correlations", tags=["correlation"])

RELATION_LABEL = {
    "temporal": "Corrélation temporelle (causalité non démontrée)",
    "same_target": "Même source et même cible",
    "same_address": "Même adresse",
}


def correlation_out(c: Correlation) -> dict:
    return {
        "id": c.id, "kind": c.kind, "asset_id": c.asset_id, "ip": c.ip, "window_start": c.window_start,
        "window_end": c.window_end, "events": c.events, "event_count": c.event_count, "reasoning": c.reasoning,
        "relation": c.relation, "relation_label": RELATION_LABEL.get(c.relation, c.relation), "confidence": c.confidence,
        "techniques": c.techniques or [], "created_at": c.created_at, "updated_at": c.updated_at,
    }


@router.get("/")
def list_correlations(
    db: Session = Depends(get_db),
    asset_id: int | None = Query(None, gt=0),
    kind: str | None = Query(None, pattern="^(port_probe|new_service_activity|profile_change|address_activity)$"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    query = db.query(Correlation)
    if asset_id is not None:
        query = query.filter(Correlation.asset_id == asset_id)
    if kind:
        query = query.filter(Correlation.kind == kind)
    rows = query.order_by(Correlation.window_end.desc(), Correlation.id.desc()).offset(offset).limit(limit).all()
    return [correlation_out(c) for c in rows]


@router.get("/{correlation_id}")
def get_correlation(correlation_id: int, db: Session = Depends(get_db)):
    c = db.get(Correlation, correlation_id)
    if not c:
        raise HTTPException(status_code=404, detail="Corrélation introuvable")
    return correlation_out(c)
