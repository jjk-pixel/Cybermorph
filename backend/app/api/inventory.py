from datetime import datetime, timedelta, UTC

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.inventory.observations import SOURCE_LABEL, as_utc, identity_summary, learning_window
from app.models.asset import Asset
from app.models.observation import AssetChange, AssetObservation

router = APIRouter(tags=["inventory"])

SEVERITY_RANK = {"info": 0, "notice": 1, "warning": 2}
CONFLICT_TYPES = ("identity_conflict", "mac_shared")


def change_out(c: AssetChange) -> dict:
    return {
        "id": c.id, "asset_id": c.asset_id, "ip": c.ip, "change_type": c.change_type, "attribute": c.attribute,
        "old_value": c.old_value, "new_value": c.new_value, "source": c.source,
        "source_label": SOURCE_LABEL.get(c.source, c.source) if c.source else None,
        "severity": c.severity, "explanation": c.explanation, "evidence": c.evidence,
        "detected_at": as_utc(c.detected_at), "acknowledged_at": as_utc(c.acknowledged_at),
    }


def observation_out(o: AssetObservation) -> dict:
    return {
        "id": o.id, "source": o.source, "source_label": SOURCE_LABEL.get(o.source, o.source),
        "attribute": o.attribute, "value": o.value, "first_seen": as_utc(o.first_seen),
        "last_seen": as_utc(o.last_seen), "seen_count": o.seen_count, "retired_at": as_utc(o.retired_at),
    }


def _open_conflicts(db: Session) -> dict[int, int]:
    counts: dict[int, int] = {}
    for c in db.query(AssetChange).filter(AssetChange.change_type.in_(CONFLICT_TYPES), AssetChange.acknowledged_at.is_(None)).all():
        ids = (c.evidence or {}).get("asset_ids") or [c.asset_id]
        for asset_id in ids:
            counts[asset_id] = counts.get(asset_id, 0) + 1
    return counts


def inventory_entries(db: Session) -> list[dict]:
    observations: dict[int, list[AssetObservation]] = {}
    for o in db.query(AssetObservation).filter(AssetObservation.asset_id.isnot(None)).all():
        observations.setdefault(o.asset_id, []).append(o)
    conflicts = _open_conflicts(db)
    since = datetime.now(UTC) - timedelta(hours=24)
    recent: dict[int, int] = {}
    for (asset_id,) in db.query(AssetChange.asset_id).filter(AssetChange.detected_at >= since).all():
        recent[asset_id] = recent.get(asset_id, 0) + 1

    return [
        {
            "id": a.id, "ip": a.ip_address, "name": a.name, "asset_type": a.asset_type, "status": a.status,
            "authorization": a.authorization, "authorization_source": a.authorization_source,
            "is_scanner": bool(a.is_scanner), "scanner_reason": a.scanner_reason,
            "first_seen": as_utc(a.created_at), "last_seen": as_utc(a.last_seen),
            "identity": identity_summary(a, observations.get(a.id, []), conflicts.get(a.id, 0)),
            "observation_count": len(observations.get(a.id, [])),
            "changes_24h": recent.get(a.id, 0),
        }
        for a in db.query(Asset).order_by(Asset.id).all()
    ]


@router.get("/api/inventory/")
def get_inventory(db: Session = Depends(get_db)):
    """Inventaire rapproché : identité, sources, autorisation, drapeau scanner, activité récente."""
    entries = inventory_entries(db)
    learning = learning_window(db)
    db.commit()  # la fenêtre d'apprentissage est créée à la première lecture
    since = datetime.now(UTC) - timedelta(hours=24)
    return {
        "learning": learning,
        "assets": entries,
        "stats": {
            "assets": len(entries),
            "unauthorized": sum(1 for e in entries if e["authorization"] == "unauthorized"),
            "pending": sum(1 for e in entries if e["authorization"] is None),
            "scanners": sum(1 for e in entries if e["is_scanner"]),
            "conflicts": sum(1 for e in entries if e["identity"]["open_conflicts"]),
            "new_24h": sum(1 for e in entries if e["first_seen"] and e["first_seen"] >= since),
            "changes_24h": db.query(AssetChange).filter(AssetChange.detected_at >= since).count(),
        },
    }


@router.get("/api/inventory/{asset_id}")
def get_inventory_asset(asset_id: int, db: Session = Depends(get_db)):
    """Tous les faits observés sur un actif, par attribut et par source, et l'historique de ses changements."""
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset introuvable")
    obs = db.query(AssetObservation).filter(AssetObservation.asset_id == asset_id).order_by(
        AssetObservation.attribute, AssetObservation.last_seen.desc()).all()
    changes = db.query(AssetChange).filter(AssetChange.asset_id == asset_id).order_by(AssetChange.detected_at.desc()).limit(200).all()
    return {
        "asset_id": asset_id,
        "ip": asset.ip_address,
        "identity": identity_summary(asset, obs, _open_conflicts(db).get(asset_id, 0)),
        "observations": [observation_out(o) for o in obs],
        "changes": [change_out(c) for c in changes],
    }


@router.get("/api/changes/")
def list_changes(
    db: Session = Depends(get_db),
    limit: int = Query(200, ge=1, le=1000),
    asset_id: int | None = None,
    min_severity: str = Query("info", pattern="^(info|notice|warning)$"),
    include_acknowledged: bool = True,
    since: datetime | None = None,
    until: datetime | None = None,
):
    query = db.query(AssetChange)
    if since is not None:
        query = query.filter(AssetChange.detected_at > since)
    if until is not None:
        query = query.filter(AssetChange.detected_at <= until)
    if asset_id is not None:
        query = query.filter(AssetChange.asset_id == asset_id)
    if not include_acknowledged:
        query = query.filter(AssetChange.acknowledged_at.is_(None))
    allowed = [s for s, rank in SEVERITY_RANK.items() if rank >= SEVERITY_RANK[min_severity]]
    query = query.filter(AssetChange.severity.in_(allowed))
    return [change_out(c) for c in query.order_by(AssetChange.detected_at.desc(), AssetChange.id.desc()).limit(limit).all()]


@router.post("/api/changes/{change_id}/acknowledge")
def acknowledge_change(change_id: int, db: Session = Depends(get_db)):
    """L'opérateur a pris connaissance du changement (il reste dans l'historique)."""
    change = db.get(AssetChange, change_id)
    if not change:
        raise HTTPException(status_code=404, detail="Changement introuvable")
    if change.acknowledged_at is None:
        change.acknowledged_at = datetime.now(UTC)
        db.commit()
    return change_out(change)
