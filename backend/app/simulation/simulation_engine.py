import copy
import networkx as nx
from sqlalchemy.orm import Session
from app.attack_graph.graph_engine import build_graph, find_attack_paths, EVIDENCE_RANK, EVIDENCE_LABELS

# Types d'hypothèses supportées, volontairement limitées et explicites
HYPOTHESIS_TYPES = {
    "asset_compromised": "Un asset est considéré comme déjà compromis par un attaquant.",
    "new_service_exposed": "Un nouveau service/port est ajouté comme exposé sur un asset.",
    "connection_removed": "Une connexion réseau est supprimée (ex: pare-feu ajouté).",
}


def clone_graph(graph: nx.DiGraph) -> nx.DiGraph:
    """Clone profond du graphe, pour ne jamais modifier l'original ni la base réelle."""
    return copy.deepcopy(graph)


def apply_hypothesis(graph: nx.DiGraph, hypothesis: dict) -> nx.DiGraph:
    """
    Applique une hypothèse au graphe cloné (jamais à l'original).
    Retourne le graphe modifié — ne touche jamais la base de données.
    """
    h_type = hypothesis.get("type")

    if h_type not in HYPOTHESIS_TYPES:
        raise ValueError(f"Type d'hypothèse inconnu : {h_type}")

    if h_type == "asset_compromised":
        asset_id = hypothesis["asset_id"]
        if asset_id not in graph.nodes:
            raise ValueError(f"Asset #{asset_id} introuvable dans le graphe")

        # Un asset compromis : toutes ses arêtes sortantes deviennent "déclarées" avec confiance forte,
        # simulant qu'un attaquant ayant ce pied-à-terre peut exploiter les connexions déjà connues à leur poids maximal.
        for _, target, data in graph.out_edges(asset_id, data=True):
            data["weight"] = min(data["weight"] * 1.3, 100.0)
            if "declared" not in data["connection_types"]:
                data["connection_types"] = data["connection_types"] + ["declared"]

        graph.nodes[asset_id]["hypothetically_compromised"] = True

    elif h_type == "new_service_exposed":
        asset_id = hypothesis["asset_id"]
        if asset_id not in graph.nodes:
            raise ValueError(f"Asset #{asset_id} introuvable dans le graphe")
        graph.nodes[asset_id]["risk_score"] = min(graph.nodes[asset_id].get("risk_score", 0) + 20, 100)

    elif h_type == "connection_removed":
        source, target = hypothesis["source_asset_id"], hypothesis["destination_asset_id"]
        if graph.has_edge(source, target):
            graph.remove_edge(source, target)

    return graph


def run_what_if(db: Session, hypothesis: dict) -> dict:
    """
    Exécute une simulation complète : construit le graphe réel, le clone,
    applique l'hypothèse, recalcule les chemins, et compare avant/après.
    AUCUNE écriture n'est faite sur les tables Asset/NetworkConnection/Alert.
    """
    original_graph = build_graph(db)
    paths_before = find_attack_paths(db)  # utilise directement le graphe réel (lecture seule)

    simulated_graph = clone_graph(original_graph)
    simulated_graph = apply_hypothesis(simulated_graph, hypothesis)

    # Recalcul des chemins sur le graphe SIMULÉ (pas sur la base réelle)
    paths_after = _find_paths_on_graph(simulated_graph)

    before_ids = {(p["source"], p["target"], tuple(p["nodes"])) for p in paths_before}
    after_ids = {(p["source"], p["target"], tuple(p["nodes"])) for p in paths_after}
    new_paths = [p for p in paths_after if (p["source"], p["target"], tuple(p["nodes"])) not in before_ids]

    return {
        "hypothesis": hypothesis,
        "paths_before_count": len(paths_before),
        "paths_after_count": len(paths_after),
        "new_paths_count": len(new_paths),
        "new_paths": new_paths,
        "paths_before": paths_before,
        "paths_after": paths_after,
    }


def _find_paths_on_graph(graph: nx.DiGraph) -> list[dict]:
    """Version de find_attack_paths qui opère directement sur un graphe déjà construit (pour le graphe simulé)."""
    results = []
    high_value_targets = [
        n for n, data in graph.nodes(data=True)
        if data.get("risk_score", 0) >= 50 or data.get("asset_type") in ("server", "router")
    ]

    for source in graph.nodes:
        for target in high_value_targets:
            if source == target:
                continue
            try:
                paths = list(nx.all_simple_paths(graph, source, target, cutoff=4))
            except nx.NetworkXNoPath:
                continue

            for path in paths:
                if len(path) < 2:
                    continue
                edges_data = [graph.edges[path[i], path[i + 1]] for i in range(len(path) - 1)]
                edge_weights = [e["weight"] for e in edges_data]
                length_penalty = 0.85 ** (len(path) - 2)
                path_score = round((sum(edge_weights) / len(edge_weights)) * length_penalty, 1)

                if path_score >= 75:
                    risk_label = "critical"
                elif path_score >= 50:
                    risk_label = "high"
                elif path_score >= 25:
                    risk_label = "moderate"
                else:
                    risk_label = "low"

                connection_types = []
                for e in edges_data:
                    connection_types.extend(e["connection_types"])
                weakest_rank = min(EVIDENCE_RANK.get(ct, 1) for ct in connection_types)
                evidence_level = EVIDENCE_LABELS[weakest_rank]

                results.append({
                    "source": source, "target": target, "nodes": path,
                    "score": path_score, "risk": risk_label, "hops": len(path) - 1,
                    "evidence_level": evidence_level, "connection_types": connection_types,
                })

    results.sort(key=lambda r: r["score"], reverse=True)
    return results
