import asyncio
import json
from app.models.incident import Incident
from app.models.attack_path_step import AttackPathStep
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.asset import Asset
from app.models.network_connection import NetworkConnection
from app.attack_graph.graph_engine import find_attack_paths

router = APIRouter(tags=["live"])

CONNECTED_CLIENTS: set[WebSocket] = set()

def get_active_incidents(db: Session) -> list[dict]:
    """Incidents actifs (non résolus), avec leurs étapes, pour le flux temps réel."""
    incidents = (
        db.query(Incident)
        .filter(Incident.status.in_(["detected", "progressing"]))
        .order_by(Incident.last_seen.desc())
        .all()
    )

    result = []
    for incident in incidents:
        steps = (
            db.query(AttackPathStep)
            .filter(AttackPathStep.incident_id == incident.id)
            .order_by(AttackPathStep.sequence)
            .all()
        )
        result.append({
            "incident_id": incident.id,
            "status": incident.status,
            "source_asset_id": incident.source_asset_id,
            "current_asset_id": incident.current_asset_id,
            "target_asset_id": incident.target_asset_id,
            "confidence": incident.confidence,
            "current_step": incident.current_step,
            "total_steps": incident.total_steps,
            "steps": [
                {
                    "source_asset_id": s.source_asset_id,
                    "destination_asset_id": s.destination_asset_id,
                    "status": s.status,
                    "confidence": s.confidence,
                }
                for s in steps
            ],
        })
    return result

def get_live_state(db: Session) -> dict:
    """Snapshot léger de l'état courant, envoyé à chaque client connecté."""
    assets = db.query(Asset).all()
    connections = db.query(NetworkConnection).filter(NetworkConnection.status == "active").all()
    paths = find_attack_paths(db, min_score=25.0)
    active_incidents = get_active_incidents(db)
    return {
        "type": "state_update",
        "assets": [
            {
                "id": a.id, "ip": a.ip_address, "hostname": a.hostname,
                "asset_type": a.asset_type, "risk_score": a.risk_score, "status": a.status,
            }
            for a in assets
        ],
        "edges": [
            {"source": c.source_asset_id, "target": c.destination_asset_id,
             "connection_type": c.connection_type, "protocol": c.protocol}
            for c in connections
        ],
        "attack_paths": [
            {"source": p["source"], "target": p["target"], "score": p["score"],
             "risk": p["risk"], "evidence_level": p["evidence_level"]}
            for p in paths
        ],
 	 "active_incidents": active_incidents,
    }


@router.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    await websocket.accept()
    CONNECTED_CLIENTS.add(websocket)
    try:
        while True:
            db = SessionLocal()
            try:
                state = get_live_state(db)
                await websocket.send_text(json.dumps(state, default=str))
            finally:
                db.close()
            await asyncio.sleep(10)  # push l'état toutes les 10s (indépendant du cycle de 5 min de l'orchestrateur)
    except WebSocketDisconnect:
        CONNECTED_CLIENTS.discard(websocket)
