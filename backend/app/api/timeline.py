from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.snapshot import Snapshot

router = APIRouter(prefix="/api/timeline", tags=["timeline"])


@router.get("/")
def list_snapshots(db: Session = Depends(get_db), limit: int = 50):
    snapshots = db.query(Snapshot).order_by(Snapshot.captured_at.desc()).limit(limit).all()
    return [
        {
            "id": s.id, "captured_at": s.captured_at, "assets_count": len(s.assets_summary),
            "connections_count": s.connections_count, "attack_paths_count": s.attack_paths_count,
            "highest_path_score": s.highest_path_score,
        }
        for s in snapshots
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
    }
