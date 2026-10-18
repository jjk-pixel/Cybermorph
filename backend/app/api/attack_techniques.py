from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.mitre.technique_catalog import ATTACK_VERSION
from app.models.alert import Alert
from app.models.attack_technique import AttackTechnique
from app.models.behavior import Deviation
from app.models.correlation import TechniqueEvidence

router = APIRouter(prefix="/api/attack-techniques", tags=["mitre-attack"])

STATUS_RANK = {"observed": 3, "inferred": 2, "unconfirmed": 1}
STATUS_LABEL = {"observed": "observée", "inferred": "inférée", "unconfirmed": "non confirmée"}


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
            "reference": f"https://attack.mitre.org/techniques/{t.technique_id}/",
        }
        for t in techniques
    ]


def _evidence_out(e: TechniqueEvidence, alerts: dict, deviations: dict) -> dict:
    out = {"id": e.id, "event_type": e.event_type, "event_id": e.event_id, "status": e.status,
           "status_label": STATUS_LABEL.get(e.status, e.status), "source": e.source, "confidence": e.confidence,
           "reason": e.reason, "observations": e.observations, "first_seen": e.first_seen, "last_seen": e.last_seen}
    if e.event_type == "alert" and e.event_id in alerts:
        a = alerts[e.event_id]
        out["event"] = {"message": a.message, "source_ip": a.source_ip, "destination_ip": a.destination_ip, "priority": a.priority}
    elif e.event_type == "deviation" and e.event_id in deviations:
        d = deviations[e.event_id]
        out["event"] = {"message": d.explanation, "source_ip": d.src_ip, "destination_ip": d.dst_ip, "kind": d.kind}
    return out


def _grouped(db: Session, technique: AttackTechnique | None = None) -> list[dict]:
    query = db.query(TechniqueEvidence, AttackTechnique).join(AttackTechnique, AttackTechnique.id == TechniqueEvidence.technique_ref)
    if technique is not None:
        query = query.filter(TechniqueEvidence.technique_ref == technique.id)
    rows = query.order_by(TechniqueEvidence.id).all()
    alert_ids = [e.event_id for e, _ in rows if e.event_type == "alert"]
    deviation_ids = [e.event_id for e, _ in rows if e.event_type == "deviation"]
    alerts = {a.id: a for a in db.query(Alert).filter(Alert.id.in_(alert_ids)).all()} if alert_ids else {}
    deviations = {d.id: d for d in db.query(Deviation).filter(Deviation.id.in_(deviation_ids)).all()} if deviation_ids else {}

    result: dict[str, dict] = {}
    for e, t in rows:
        entry = result.setdefault(t.technique_id, {
            "technique_id": t.technique_id, "name": t.name, "tactic": t.tactic,
            "reference": f"https://attack.mitre.org/techniques/{t.technique_id}/", "attack_version": ATTACK_VERSION,
            "status": "unconfirmed", "observations": 0, "first_seen": None, "last_seen": None,
            "sources": set(), "evidence": [], "alerts": [],
        })
        out = _evidence_out(e, alerts, deviations)
        entry["evidence"].append(out)
        entry["observations"] += e.observations or 0
        entry["sources"].add(e.source)
        if STATUS_RANK.get(e.status, 0) > STATUS_RANK.get(entry["status"], 0):
            entry["status"] = e.status
        for key, pick in (("first_seen", min), ("last_seen", max)):
            value = getattr(e, key)
            if value is not None:
                entry[key] = value if entry[key] is None else pick(entry[key], value)
        if e.event_type == "alert" and e.event_id in alerts:
            # Format historique, conservé pour les écrans existants
            a = alerts[e.event_id]
            entry["alerts"].append({"alert_id": a.id, "message": a.message, "occurrence_count": a.occurrence_count,
                                    "confidence": e.confidence, "matched_on": e.reason, "status": e.status})
    for entry in result.values():
        entry["sources"] = sorted(entry["sources"])
        entry["status_label"] = STATUS_LABEL.get(entry["status"], entry["status"])
        entry["note"] = "Rapprochement avec une technique : indice d'activité, pas une preuve de compromission."
    return sorted(result.values(), key=lambda r: (-STATUS_RANK.get(r["status"], 0), r["technique_id"]))


@router.get("/observed")
def list_observed_techniques(db: Session = Depends(get_db)):
    """Techniques rattachées à des événements du lab, avec leur statut et leurs preuves sources."""
    return _grouped(db)


@router.get("/{technique_id}/evidence")
def technique_evidence(technique_id: str, db: Session = Depends(get_db)):
    """D'une technique à ses observations sources (alertes, écarts), pour remonter à la preuve brute (/api/trace)."""
    technique = db.query(AttackTechnique).filter(AttackTechnique.technique_id == technique_id).first()
    if not technique:
        raise HTTPException(status_code=404, detail="Technique inconnue du catalogue CYBERMORPH")
    grouped = _grouped(db, technique)
    return grouped[0] if grouped else {"technique_id": technique.technique_id, "name": technique.name, "tactic": technique.tactic,
                                       "status": None, "evidence": [], "alerts": [], "observations": 0}
