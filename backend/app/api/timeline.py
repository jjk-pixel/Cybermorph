from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, defer
from app.database import get_db
from app.models.snapshot import Snapshot

router = APIRouter(prefix="/api/timeline", tags=["timeline"])


@router.get("/")
def list_snapshots(db: Session = Depends(get_db), limit: int = Query(50, ge=1, le=2016), offset: int = Query(0, ge=0)):
    rows = (
        db.query(Snapshot, Snapshot.state.isnot(None).label("has_state"))
        .options(defer(Snapshot.state))
        .order_by(Snapshot.captured_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [
        {
            "id": s.id, "captured_at": s.captured_at, "assets_count": len(s.assets_summary),
            "connections_count": s.connections_count, "attack_paths_count": s.attack_paths_count,
            "highest_path_score": s.highest_path_score,
            "has_state": bool(has_state),
        }
        for s, has_state in rows
    ]


@router.get("/{snapshot_id}")
def get_snapshot(snapshot_id: int, db: Session = Depends(get_db)):
    s = db.query(Snapshot).filter(Snapshot.id == snapshot_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Snapshot introuvable")
    return {
        "id": s.id, "captured_at": s.captured_at, "assets_summary": s.assets_summary,
        "connections_count": s.connections_count, "alerts_summary": s.alerts_summary,
        "attack_paths_count": s.attack_paths_count, "highest_path_score": s.highest_path_score,
        # Topologie et inventaire complets ; absent (null) pour les snapshots antérieurs au lot 4
        "state": s.state,
    }
