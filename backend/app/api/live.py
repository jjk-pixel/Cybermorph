import asyncio
import json
import logging
import time
from datetime import datetime, timedelta, UTC

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.attack_path_step import AttackPathStep
from app.models.attack_technique import AttackTechnique, AlertTechniqueMapping
from app.models.incident import Incident
from app.models.network_connection import NetworkConnection
from app.models.snapshot import Snapshot
from app.attack_graph.graph_engine import build_graph, find_paths_on_graph, EVIDENCE_RANK, EVIDENCE_LABELS
from app.incidents.incident_engine import ACTIVE_STATUSES
from app.security import websocket_authorized

router = APIRouter(tags=["live"])
logger = logging.getLogger("cybermorph.live")

# Intervalle de diffusion (indépendant du cycle de 5 min de l'orchestrateur)
LIVE_INTERVAL_SECONDS = 5
RECENT_ALERTS_LIMIT = 25
LIVE_PATH_MIN_SCORE = 25.0


def _iso(value: datetime | None) -> str | None:
    """ISO 8601 explicite en UTC : les colonnes sans fuseau (incidents) sont stockées en UTC naïf."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_risk_factors(raw: str | None) -> dict | None:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def get_active_incidents(db: Session) -> list[dict]:
    """Incidents actifs (non dormants), avec leurs étapes, pour le flux temps réel."""
    incidents = (
        db.query(Incident)
        .filter(Incident.status.in_(ACTIVE_STATUSES))
        .order_by(Incident.last_seen.desc())
        .all()
    )
    steps_by_incident: dict[int, list[AttackPathStep]] = {}
    if incidents:
        for s in (
            db.query(AttackPathStep)
            .filter(AttackPathStep.incident_id.in_([i.id for i in incidents]))
            .order_by(AttackPathStep.sequence)
            .all()
        ):
            steps_by_incident.setdefault(s.incident_id, []).append(s)

    return [
        {
            "incident_id": incident.id,
            "status": incident.status,
            "source_asset_id": incident.source_asset_id,
            "current_asset_id": incident.current_asset_id,
            "target_asset_id": incident.target_asset_id,
            "technique_id": incident.technique_id,
            "confidence": incident.confidence,
            "current_step": incident.current_step,
            "total_steps": incident.total_steps,
            "started_at": _iso(incident.started_at),
            "last_seen": _iso(incident.last_seen),
            "trigger": (incident.metadata_json or {}).get("message"),
            "steps": [
                {
                    "sequence": s.sequence,
                    "source_asset_id": s.source_asset_id,
                    "destination_asset_id": s.destination_asset_id,
                    "status": s.status,
                    "confidence": s.confidence,
                    "technique_id": s.technique_id,
                }
                for s in steps_by_incident.get(incident.id, [])
            ],
        }
        for incident in incidents
    ]


def _recent_alerts(db: Session) -> list[dict]:
    alerts = db.query(Alert).order_by(Alert.last_seen.desc().nullslast()).limit(RECENT_ALERTS_LIMIT).all()
    techniques: dict[int, str] = {}
    if alerts:
        rows = (
            db.query(AlertTechniqueMapping.alert_id, AttackTechnique.technique_id)
            .join(AttackTechnique, AttackTechnique.id == AlertTechniqueMapping.technique_id)
            .filter(AlertTechniqueMapping.alert_id.in_([a.id for a in alerts]))
            .all()
        )
        techniques = {alert_id: technique_id for alert_id, technique_id in rows}
    return [
        {
            "id": a.id,
            "source_ip": a.source_ip,
            "destination_ip": a.destination_ip,
            "source_asset_id": a.source_asset_id,
            "destination_asset_id": a.destination_asset_id,
            "protocol": a.protocol,
            "message": a.message,
            "classification": a.classification,
            "priority": a.priority,
            "occurrence_count": a.occurrence_count,
            "first_seen": _iso(a.first_seen),
            "last_seen": _iso(a.last_seen),
            "technique_id": techniques.get(a.id),
        }
        for a in alerts
    ]


def get_live_state(db: Session) -> dict:
    """Snapshot de l'état courant, calculé une fois par tick et diffusé à tous les clients."""
    assets = db.query(Asset).all()
    connections = db.query(NetworkConnection).filter(NetworkConnection.status == "active").all()

    graph = build_graph(db)
    paths = find_paths_on_graph(graph, min_score=LIVE_PATH_MIN_SCORE)
    active_incidents = get_active_incidents(db)

    day_ago = datetime.now(UTC) - timedelta(hours=24)
    alerts_total = db.query(Alert).count()
    alerts_24h = db.query(Alert).filter(Alert.last_seen >= day_ago).count()
    last_snapshot = db.query(Snapshot.captured_at).order_by(Snapshot.captured_at.desc()).first()

    risk_scores = [a.risk_score or 0.0 for a in assets]

    return {
        "type": "state_update",
        "generated_at": _iso(datetime.now(UTC)),
        "last_scan_at": _iso(last_snapshot[0]) if last_snapshot else None,
        "assets": [
            {
                "id": a.id, "ip": a.ip_address, "name": a.name, "hostname": a.hostname,
                "asset_type": a.asset_type, "risk_score": a.risk_score, "status": a.status,
                "mac_address": a.mac_address, "vendor": a.vendor, "os_detected": a.os_detected,
                "open_ports": a.open_ports, "services": a.services, "zone": a.zone,
                "risk_factors": _parse_risk_factors(a.risk_factors),
                "last_seen": _iso(a.last_seen),
            }
            for a in assets
        ],
        # Une entrée par connexion active (format historique)
        "edges": [
            {"source": c.source_asset_id, "target": c.destination_asset_id,
             "connection_type": c.connection_type, "protocol": c.protocol, "port": c.port}
            for c in connections
        ],
        # Une entrée par paire orientée, avec le poids et la preuve calculés par le graphe d'attaque
        "links": [
            {
                "source": u, "target": v,
                "weight": data["weight"],
                "connection_types": data["connection_types"],
                "evidence_level": EVIDENCE_LABELS[max(EVIDENCE_RANK.get(ct, 1) for ct in data["connection_types"])],
                "details": data["details"],
                "alert_summary": data["alert_summary"],
            }
            for u, v, data in graph.edges(data=True)
        ],
        "attack_paths": [
            {"source": p["source"], "target": p["target"], "nodes": p["nodes"], "hops": p["hops"],
             "score": p["score"], "risk": p["risk"], "evidence_level": p["evidence_level"],
             "connection_types": p["connection_types"], "alert_evidence": p["alert_evidence"]}
            for p in paths
        ],
        "active_incidents": active_incidents,
        "recent_alerts": _recent_alerts(db),
        "stats": {
            "assets": len(assets),
            "assets_up": sum(1 for a in assets if a.status == "up"),
            "assets_down": sum(1 for a in assets if a.status == "down"),
            "connections": len(connections),
            "alerts_total": alerts_total,
            "alerts_24h": alerts_24h,
            "active_incidents": len(active_incidents),
            "attack_paths": len(paths),
            "max_path_score": max((p["score"] for p in paths), default=0.0),
            "avg_risk": round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0.0,
            "max_risk": max(risk_scores, default=0.0),
        },
    }


def compute_live_state() -> dict:
    db = SessionLocal()
    try:
        return get_live_state(db)
    finally:
        db.close()


class LiveHub:
    """Diffuse un état unique à tous les clients ; le calcul (synchrone, base + graphe) tourne hors de la boucle async."""

    def __init__(self):
        self.clients: set[WebSocket] = set()
        self.latest: str | None = None
        self.latest_at = 0.0
        self._task: asyncio.Task | None = None
        self._lock = asyncio.Lock()

    def _fresh(self, max_age: float) -> bool:
        return self.latest is not None and time.monotonic() - self.latest_at < max_age

    async def refresh(self, max_age: float = 0.5) -> str:
        async with self._lock:
            # Un autre client vient peut-être de recalculer pendant qu'on attendait le verrou
            if not self._fresh(max_age):
                state = await asyncio.to_thread(compute_live_state)
                self.latest = json.dumps(state, default=str)
                self.latest_at = time.monotonic()
            return self.latest

    async def current(self) -> str:
        if self._fresh(LIVE_INTERVAL_SECONDS):
            return self.latest
        return await self.refresh(max_age=LIVE_INTERVAL_SECONDS)

    async def broadcast(self, message: str):
        for ws in list(self.clients):
            try:
                await ws.send_text(message)
            except Exception:
                self.clients.discard(ws)

    async def _run(self):
        try:
            while self.clients:
                await asyncio.sleep(LIVE_INTERVAL_SECONDS)
                if not self.clients:
                    break
                try:
                    message = await self.refresh()
                except Exception as e:
                    logger.exception("Calcul de l'état live impossible")
                    message = json.dumps({"type": "error", "detail": str(e)})
                await self.broadcast(message)
        finally:
            self._task = None

    def ensure_running(self):
        if self._task is None:
            self._task = asyncio.create_task(self._run())


hub = LiveHub()


@router.get("/api/live/state")
async def live_state_snapshot():
    """Même contenu que le flux /ws/live, pour un chargement initial ou un mode dégradé sans WebSocket."""
    return json.loads(await hub.current())


@router.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    if not websocket_authorized(websocket):
        await websocket.close(code=4401)
        return

    await websocket.accept()
    hub.clients.add(websocket)
    try:
        await websocket.send_text(await hub.current())
        hub.ensure_running()
        while True:
            # Le client peut demander un rafraîchissement immédiat ; sinon on attend la déconnexion.
            message = await websocket.receive_text()
            if message == "refresh":
                await websocket.send_text(await hub.refresh())
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("Erreur WebSocket /ws/live")
    finally:
        hub.clients.discard(websocket)
