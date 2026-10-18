from datetime import datetime, UTC

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.behavior.baseline import (
    ASSET_LEARNING, EVE_PATH, HOST_SWEEP_THRESHOLD, PORT_SCAN_THRESHOLD, learn_deviation,
)
from app.database import get_db
from app.inventory.observations import as_utc, get_setting, learning_window
from app.models.behavior import Communication, Deviation

router = APIRouter(prefix="/api/behavior", tags=["behavior"])

DEVIATION_STATUSES = ("open", "acknowledged", "learned")


def communication_out(c: Communication) -> dict:
    return {
        "id": c.id, "src_ip": c.src_ip, "dst_key": c.dst_key, "dst_scope": c.dst_scope,
        "src_asset_id": c.src_asset_id, "dst_asset_id": c.dst_asset_id, "proto": c.proto,
        "dst_port": None if c.dst_port == -1 else c.dst_port, "app_proto": c.app_proto or None,
        "first_seen": as_utc(c.first_seen), "last_seen": as_utc(c.last_seen), "flow_count": c.flow_count,
        "established_count": c.established_count, "bytes_toserver": c.bytes_toserver, "bytes_toclient": c.bytes_toclient,
        "baseline_state": c.baseline_state, "learned_via": c.learned_via, "details": c.details or {},
    }


def deviation_out(d: Deviation) -> dict:
    return {
        "id": d.id, "kind": d.kind, "severity": d.severity, "status": d.status, "src_ip": d.src_ip, "dst_ip": d.dst_ip,
        "src_asset_id": d.src_asset_id, "dst_asset_id": d.dst_asset_id, "communication_id": d.communication_id,
        "explanation": d.explanation, "reasons": d.reasons or [], "evidence": d.evidence or {},
        "first_seen": as_utc(d.first_seen), "last_seen": as_utc(d.last_seen), "occurrences": d.occurrences,
        "reviewed_at": as_utc(d.reviewed_at),
    }


@router.get("/")
def behavior_summary(db: Session = Depends(get_db)):
    """État de la référence comportementale et du capteur de flux : ce qui est appris, ce qui s'en écarte."""
    learning = learning_window(db)
    db.commit()
    states = {s: 0 for s in ("baseline", "new", "accepted")}
    for (state,) in db.query(Communication.baseline_state).all():
        states[state] = states.get(state, 0) + 1
    deviations = {s: db.query(Deviation).filter(Deviation.status == s).count() for s in DEVIATION_STATUSES}
    last_run = get_setting(db, "eve_last_run")
    return {
        "learning": learning,
        "asset_learning_hours": ASSET_LEARNING.total_seconds() / 3600,
        "sensor": {
            "path": EVE_PATH,
            "last_run": last_run,
            "healthy": bool(last_run) and "error" not in last_run,
            "thresholds": {"port_scan_ports": PORT_SCAN_THRESHOLD, "host_sweep_hosts": HOST_SWEEP_THRESHOLD},
        },
        "communications": states,
        "deviations": deviations,
        "method": [
            "Une activité = flux agrégés par source, destination, protocole, port de service et protocole applicatif.",
            "Pendant l'apprentissage, toute activité nouvelle entre dans la référence ; ensuite, c'est un écart.",
            "Les sondes de l'actif scanner vers le réseau local et les tentatives TCP sans poignée de main ne sont jamais apprises.",
            "La sévérité d'un écart est fixée par des faits (port à risque, cible critique, source non autorisée, alerte IDS sur la paire) et atténuée si une activité semblable est déjà connue.",
            "La référence porte sur l'existence des activités, pas sur leurs volumes : aucune détection statistique n'est revendiquée.",
        ],
    }


@router.get("/communications")
def list_communications(
    db: Session = Depends(get_db),
    asset_id: int | None = None,
    state: str | None = Query(None, pattern="^(baseline|new|accepted)$"),
    limit: int = Query(500, ge=1, le=2000),
):
    query = db.query(Communication)
    if asset_id is not None:
        query = query.filter(or_(Communication.src_asset_id == asset_id, Communication.dst_asset_id == asset_id))
    if state:
        query = query.filter(Communication.baseline_state == state)
    return [communication_out(c) for c in query.order_by(Communication.last_seen.desc()).limit(limit).all()]


@router.get("/deviations")
def list_deviations(
    db: Session = Depends(get_db),
    status: str | None = Query(None, pattern="^(open|acknowledged|learned)$"),
    asset_id: int | None = None,
    limit: int = Query(200, ge=1, le=1000),
):
    query = db.query(Deviation)
    if status:
        query = query.filter(Deviation.status == status)
    if asset_id is not None:
        query = query.filter(or_(Deviation.src_asset_id == asset_id, Deviation.dst_asset_id == asset_id))
    return [deviation_out(d) for d in query.order_by(Deviation.last_seen.desc(), Deviation.id.desc()).limit(limit).all()]


def _get_deviation(db: Session, deviation_id: int) -> Deviation:
    deviation = db.get(Deviation, deviation_id)
    if not deviation:
        raise HTTPException(status_code=404, detail="Écart introuvable")
    return deviation


@router.post("/deviations/{deviation_id}/learn")
def learn(deviation_id: int, db: Session = Depends(get_db)):
    """Valider l'écart : l'activité est ajoutée à la référence et n'alertera plus."""
    deviation = _get_deviation(db, deviation_id)
    if deviation.kind != "new_communication":
        raise HTTPException(status_code=400, detail="Seule une nouvelle activité peut être apprise ; un balayage s'acquitte.")
    learn_deviation(db, deviation)
    db.commit()
    return deviation_out(deviation)


@router.post("/deviations/{deviation_id}/acknowledge")
def acknowledge(deviation_id: int, db: Session = Depends(get_db)):
    """Prendre connaissance de l'écart sans l'apprendre : l'activité reste hors référence."""
    deviation = _get_deviation(db, deviation_id)
    if deviation.status == "open":
        deviation.status = "acknowledged"
        deviation.reviewed_at = datetime.now(UTC)
        db.commit()
    return deviation_out(deviation)
