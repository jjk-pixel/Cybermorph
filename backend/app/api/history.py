"""
Reconstitution de l'état du réseau à une date donnée, à partir des preuves conservées :
- le snapshot du cycle (résumé depuis septembre ; topologie et inventaire complets depuis le lot 4) ;
- le journal d'observations (ports, MAC, noms : valeurs courantes à cette date) ;
- les activités et écarts connus à cette date.
La couverture de chaque source est publiée : avant leur mise en service, l'information n'existe pas et n'est pas inventée.
"""
from datetime import datetime, UTC

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.inventory import change_out
from app.database import get_db
from app.inventory.observations import as_utc
from app.models.behavior import Communication, Deviation
from app.models.observation import AssetChange, AssetObservation
from app.models.snapshot import Snapshot

router = APIRouter(prefix="/api/history", tags=["history"])


def _valid_at(o: AssetObservation, at: datetime) -> bool:
    return as_utc(o.first_seen) <= at and (o.retired_at is None or as_utc(o.retired_at) > at)


@router.get("/state")
def state_at(at: datetime = Query(..., description="Date ISO 8601"), db: Session = Depends(get_db)):
    at = at if at.tzinfo else at.replace(tzinfo=UTC)
    snapshot = db.query(Snapshot).filter(Snapshot.captured_at <= at).order_by(Snapshot.captured_at.desc()).first()
    if not snapshot:
        raise HTTPException(status_code=404, detail="Aucun snapshot avant cette date")
    previous = (
        db.query(Snapshot.id, Snapshot.captured_at)
        .filter(Snapshot.captured_at < snapshot.captured_at)
        .order_by(Snapshot.captured_at.desc())
        .first()
    )

    first_observation = db.query(AssetObservation.first_seen).order_by(AssetObservation.first_seen).first()
    first_communication = db.query(Communication.first_seen).order_by(Communication.first_seen).first()
    observations_since = as_utc(first_observation[0]) if first_observation else None
    communications_since = as_utc(first_communication[0]) if first_communication else None

    inventory: dict[int, dict] = {}
    if observations_since and at >= observations_since:
        for o in db.query(AssetObservation).filter(AssetObservation.asset_id.isnot(None)).all():
            if not _valid_at(o, at):
                continue
            entry = inventory.setdefault(o.asset_id, {"open_ports": set(), "mac": set(), "hostname": set(), "os": set()})
            if o.attribute == "open_port":
                entry["open_ports"].add(int(o.value) if o.value.isdigit() else o.value)
            elif o.attribute in entry:
                entry[o.attribute].add(o.value)

    communications = []
    if communications_since and at >= communications_since:
        communications = [
            {"id": c.id, "src_ip": c.src_ip, "dst_key": c.dst_key, "dst_scope": c.dst_scope, "proto": c.proto,
             "dst_port": None if c.dst_port == -1 else c.dst_port, "app_proto": c.app_proto or None,
             "baseline_state": c.baseline_state}
            for c in db.query(Communication).filter(Communication.first_seen <= at).all()
        ]
    open_deviations = [
        {"id": d.id, "kind": d.kind, "severity": d.severity, "explanation": d.explanation,
         "src_asset_id": d.src_asset_id, "dst_asset_id": d.dst_asset_id}
        for d in db.query(Deviation).filter(Deviation.first_seen <= at).all()
        if d.reviewed_at is None or as_utc(d.reviewed_at) > at
    ]
    window_start = as_utc(previous[1]) if previous else None
    changes_query = db.query(AssetChange).filter(AssetChange.detected_at <= snapshot.captured_at)
    if window_start:
        changes_query = changes_query.filter(AssetChange.detected_at > window_start)

    return {
        "at": at,
        "snapshot": {
            "id": snapshot.id, "captured_at": as_utc(snapshot.captured_at), "assets_summary": snapshot.assets_summary,
            "connections_count": snapshot.connections_count, "attack_paths_count": snapshot.attack_paths_count,
            "highest_path_score": snapshot.highest_path_score, "state": snapshot.state,
        },
        "inventory": {
            str(asset_id): {k: sorted(v, key=lambda x: (0, x, "") if isinstance(x, int) else (1, 0, str(x))) for k, v in entry.items()}
            for asset_id, entry in inventory.items()
        },
        "communications": communications,
        "open_deviations": open_deviations,
        "changes_since_previous": [change_out(c) for c in changes_query.order_by(AssetChange.detected_at).all()],
        "coverage": {
            "topology": snapshot.state is not None,
            "observations_since": observations_since,
            "communications_since": communications_since,
            "notes": [
                note for note in [
                    None if snapshot.state is not None else
                    "Snapshot antérieur au suivi de la topologie : seuls le risque et le statut des actifs sont connus.",
                    None if observations_since and at >= observations_since else
                    "Journal d'observations pas encore en service à cette date : ports et identifiants non reconstitués.",
                    None if communications_since and at >= communications_since else
                    "Flux Suricata pas encore ingérés à cette date : aucune activité reconstituée.",
                ] if note
            ],
        },
    }
