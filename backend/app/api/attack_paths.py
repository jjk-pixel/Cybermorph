from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.attack_graph.graph_engine import build_graph, search_paths
from app.models.asset import Asset

router = APIRouter(prefix="/api/attack-paths", tags=["attack-graph"])


@router.get("/")
def get_attack_paths(
    db: Session = Depends(get_db),
    min_score: float = Query(0.0, ge=0, le=100, description="Score minimum du chemin pour être inclus"),
    max_length: int = Query(4, ge=1, le=6, description="Nombre maximum de sauts à considérer"),
):
    paths, limits = search_paths(build_graph(db), min_score=min_score, max_length=max_length)

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

    return {
        "count": len(enriched),
        "paths": enriched,
        # Limites de calcul atteintes et sauts écartés faute de service atteignable : ce que le résultat ne montre pas
        "limits": limits,
        "note": "Chemins potentiels calculés sur le modèle (analyse défensive) : aucun n'est une exploitation démontrée "
                "sauf mention explicite d'une vulnérabilité confirmée à chaque saut.",
    }
