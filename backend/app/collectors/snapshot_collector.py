from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.asset import Asset
from app.models.network_connection import NetworkConnection
from app.models.alert import Alert
from app.models.snapshot import Snapshot
from app.attack_graph.graph_engine import find_attack_paths


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

        snapshot = Snapshot(
            assets_summary=assets_summary,
            connections_count=connections_count,
            alerts_summary=alerts_summary,
            attack_paths_count=len(paths),
            highest_path_score=int(highest_score) if highest_score is not None else None,
        )
        db.add(snapshot)
        db.commit()
        print(f"[CYBERMORPH][Snapshot] Capturé : {len(assets_summary)} assets, {len(paths)} chemins, score max={highest_score}")
    finally:
        db.close()


if __name__ == "__main__":
    capture_snapshot()
