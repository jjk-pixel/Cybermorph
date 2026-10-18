"""
Traçabilité : chaque conclusion de CYBERMORPH remonte à ses preuves sources.

alerte  → ligne fast.log (fichier, position) et flow_id Suricata (eve.json)
        → activité observée portant ce flow_id (lien exact) ou, à défaut, activités de la même paire (lien par paire)
        → mapping MITRE (règle et confiance), écarts et incidents qui la citent, chemins d'attaque qui passent par la paire
incident → alerte déclenchante → (chaîne ci-dessus) ; étapes et leur statut
écart   → activité, flow_id, alertes corrélées
Chaque lien indique sa nature (« exact », « même paire », « déclencheur »…) pour distinguer fait et rapprochement.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.behavior import communication_out, deviation_out
from app.attack_graph.graph_engine import build_graph, find_paths_on_graph
from app.database import get_db
from app.inventory.observations import as_utc
from app.models.alert import Alert
from app.models.attack_path_step import AttackPathStep
from app.models.attack_technique import AlertTechniqueMapping, AttackTechnique
from app.models.behavior import Communication, Deviation
from app.models.incident import Incident

router = APIRouter(prefix="/api/trace", tags=["traceability"])


def _alert_out(a: Alert) -> dict:
    return {
        "id": a.id, "source_ip": a.source_ip, "destination_ip": a.destination_ip, "source_asset_id": a.source_asset_id,
        "destination_asset_id": a.destination_asset_id, "protocol": a.protocol, "signature_id": a.signature_id,
        "message": a.message, "classification": a.classification, "priority": a.priority,
        "occurrence_count": a.occurrence_count, "first_seen": as_utc(a.first_seen), "last_seen": as_utc(a.last_seen),
    }


def trace_alert_data(db: Session, alert: Alert, include_paths: bool = True) -> dict:
    evidence = alert.evidence or {}
    flow_ids = set(evidence.get("flow_ids", []))

    mappings = (
        db.query(AlertTechniqueMapping, AttackTechnique)
        .join(AttackTechnique, AttackTechnique.id == AlertTechniqueMapping.technique_id)
        .filter(AlertTechniqueMapping.alert_id == alert.id)
        .all()
    )
    pair = db.query(Communication).filter(
        or_(
            (Communication.src_ip == alert.source_ip) & (Communication.dst_key == alert.destination_ip),
            (Communication.src_ip == alert.destination_ip) & (Communication.dst_key == alert.source_ip),
        )
    ).all()
    communications = []
    for c in pair:
        exact = bool(flow_ids & set((c.details or {}).get("flow_ids", [])))
        communications.append({**communication_out(c), "link": "exact (flow_id)" if exact else "même paire"})
    communications.sort(key=lambda c: c["link"] != "exact (flow_id)")

    deviations = [deviation_out(d) for d in db.query(Deviation).all() if alert.id in ((d.evidence or {}).get("alert_ids") or [])]
    incidents = [
        {"id": i.id, "status": i.status, "technique_id": i.technique_id, "confidence": i.confidence,
         "link": "déclencheur" if (i.metadata_json or {}).get("trigger_alert_id") == alert.id else "même source"}
        for i in db.query(Incident).all()
        if (i.metadata_json or {}).get("trigger_alert_id") == alert.id
        or (alert.source_asset_id is not None and i.source_asset_id == alert.source_asset_id and i.technique_id is not None
            and any(t.technique_id == i.technique_id for _, t in mappings))
    ]

    paths = []
    if include_paths and alert.source_asset_id is not None and alert.destination_asset_id is not None:
        graph = build_graph(db)
        edge = (alert.source_asset_id, alert.destination_asset_id)
        if graph.has_edge(*edge):
            for p in find_paths_on_graph(graph, min_score=25):
                if any((p["nodes"][i], p["nodes"][i + 1]) == edge for i in range(len(p["nodes"]) - 1)):
                    paths.append({"nodes": p["nodes"], "score": p["score"], "evidence_level": p["evidence_level"]})

    return {
        "alert": _alert_out(alert),
        "sources": {
            "fast_log_first": evidence.get("fast_log_first"),
            "fast_log_last": evidence.get("fast_log_last"),
            "eve_flow_ids": sorted(flow_ids),
            "eve_last": evidence.get("eve_last"),
            "note": None if evidence else "Alerte enregistrée avant le suivi des preuves sources : seule la ligne agrégée est connue.",
        },
        "mitre": [
            {"technique_id": t.technique_id, "name": t.name, "tactic": t.tactic, "confidence": m.confidence,
             "matched_on": m.matched_on}
            for m, t in mappings
        ],
        "communications": communications,
        "deviations": deviations,
        "incidents": incidents,
        "attack_paths": paths,
    }


@router.get("/alert/{alert_id}")
def trace_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alerte introuvable")
    return trace_alert_data(db, alert)


@router.get("/incident/{incident_id}")
def trace_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident introuvable")
    trigger_id = (incident.metadata_json or {}).get("trigger_alert_id")
    trigger = db.get(Alert, trigger_id) if trigger_id else None
    steps = db.query(AttackPathStep).filter(AttackPathStep.incident_id == incident.id).order_by(AttackPathStep.sequence).all()
    return {
        "incident": {
            "id": incident.id, "status": incident.status, "technique_id": incident.technique_id,
            "confidence": incident.confidence, "source_asset_id": incident.source_asset_id,
            "current_asset_id": incident.current_asset_id, "started_at": as_utc(incident.started_at),
            "last_seen": as_utc(incident.last_seen),
        },
        "trigger": trace_alert_data(db, trigger, include_paths=False) if trigger else None,
        "steps": [
            {"sequence": s.sequence, "source_asset_id": s.source_asset_id, "destination_asset_id": s.destination_asset_id,
             "status": s.status, "confidence": s.confidence, "evidence_type": s.evidence_type,
             "detected_at": as_utc(s.detected_at)}
            for s in steps
        ],
    }


@router.get("/deviation/{deviation_id}")
def trace_deviation(deviation_id: int, db: Session = Depends(get_db)):
    deviation = db.get(Deviation, deviation_id)
    if not deviation:
        raise HTTPException(status_code=404, detail="Écart introuvable")
    comm = db.get(Communication, deviation.communication_id) if deviation.communication_id else None
    alert_ids = (deviation.evidence or {}).get("alert_ids") or []
    alerts = db.query(Alert).filter(Alert.id.in_(alert_ids)).all() if alert_ids else []
    return {
        "deviation": deviation_out(deviation),
        "communication": communication_out(comm) if comm else None,
        "alerts": [_alert_out(a) for a in alerts],
    }
