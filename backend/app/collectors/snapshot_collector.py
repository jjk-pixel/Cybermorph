from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.asset import Asset
from app.models.network_connection import NetworkConnection
from app.models.alert import Alert
from app.models.snapshot import Snapshot
from app.attack_graph.graph_engine import find_attack_paths
from app.exposure.criticality import effective_criticality


def capture_snapshot():
    db: Session = SessionLocal()
    try:
        assets = db.query(Asset).all()
        assets_summary = [
            {"id": a.id, "ip": a.ip_address, "asset_type": a.asset_type, "risk_score": a.risk_score, "status": a.status}
            for a in assets
        ]

        connections = db.query(NetworkConnection).all()
        connections_count = {}
        for c in connections:
            connections_count[c.connection_type] = connections_count.get(c.connection_type, 0) + 1

        alerts = db.query(Alert).order_by(Alert.occurrence_count.desc()).limit(5).all()
        alerts_summary = [
            {"message": a.message, "occurrence_count": a.occurrence_count, "priority": a.priority}
            for a in alerts
        ]

        paths = find_attack_paths(db)
        highest_score = max((p["score"] for p in paths), default=None)

        # État complet, pour rejouer la topologie et l'inventaire tels qu'ils étaient à ce cycle
        state = {
            "version": 1,
            "relations": [
                {"source": c.source_asset_id, "target": c.destination_asset_id, "connection_type": c.connection_type,
                 "protocol": c.protocol, "port": c.port, "origin": c.source,
                 "last_seen": c.last_seen.isoformat() if c.last_seen else None}
                for c in connections if c.status == "active"
            ],
            "assets": [
                {"id": a.id, "ip": a.ip_address, "open_ports": a.open_ports, "os": a.os_detected, "mac": a.mac_address,
                 "authorization": a.authorization, "criticality": effective_criticality(a)["level"],
                 "is_scanner": bool(a.is_scanner)}
                for a in assets
            ],
            "paths": [{"nodes": p["nodes"], "score": p["score"]} for p in paths[:20]],
        }

        snapshot = Snapshot(
            assets_summary=assets_summary,
            connections_count=connections_count,
            alerts_summary=alerts_summary,
            attack_paths_count=len(paths),
            highest_path_score=int(highest_score) if highest_score is not None else None,
            state=state,
        )
        db.add(snapshot)
        db.commit()
        print(f"[CYBERMORPH][Snapshot] Capturé : {len(assets_summary)} assets, {len(paths)} chemins, score max={highest_score}")
    finally:
        db.close()


if __name__ == "__main__":
    capture_snapshot()
