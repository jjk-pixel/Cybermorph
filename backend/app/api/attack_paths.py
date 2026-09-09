from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.attack_graph.graph_engine import find_attack_paths
from app.models.asset import Asset

router = APIRouter(prefix="/api/attack-paths", tags=["attack-graph"])


@router.get("/")
def get_attack_paths(
    db: Session = Depends(get_db),
    min_score: float = Query(0.0, description="Score minimum du chemin pour être inclus"),
    max_length: int = Query(4, description="Nombre maximum de sauts à considérer"),
):
    paths = find_attack_paths(db, min_score=min_score, max_length=max_length)

    # Enrichir avec les noms/IP lisibles pour éviter d'avoir à re-requêter côté frontend
    asset_map = {a.id: {"ip": a.ip_address, "name": a.name} for a in db.query(Asset).all()}

    enriched = []
    for p in paths:
        enriched.append({
            **p,
            "source_ip": asset_map.get(p["source"], {}).get("ip"),
            "target_ip": asset_map.get(p["target"], {}).get("ip"),
            "path_ips": [asset_map.get(n, {}).get("ip") for n in p["nodes"]],
        })

    return {"count": len(enriched), "paths": enriched}
