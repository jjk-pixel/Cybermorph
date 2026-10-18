import copy
import networkx as nx
from sqlalchemy.orm import Session
from app.attack_graph.graph_engine import build_graph, find_paths_on_graph

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

        # Un attaquant qui tient cet actif exploite plus facilement ses relations connues. Les arêtes sont marquées
        # « simulées » : leur preuve n'est PAS modifiée (une hypothèse n'est jamais une déclaration ni une observation).
        for _, target, data in graph.out_edges(asset_id, data=True):
            data["weight"] = round(min(data["weight"] * 1.3, 100.0), 1)
            data["simulated"] = True
            data["simulation_note"] = f"Source supposée compromise (hypothèse sur #{asset_id})"

        graph.nodes[asset_id]["hypothetically_compromised"] = True

    elif h_type == "new_service_exposed":
        asset_id = hypothesis["asset_id"]
        if asset_id not in graph.nodes:
            raise ValueError(f"Asset #{asset_id} introuvable dans le graphe")
        port = hypothesis.get("port")
        label = f"port {port}" if port else "service non précisé"
        graph.nodes[asset_id]["risk_score"] = min(graph.nodes[asset_id].get("risk_score", 0) + 20, 100)
        graph.nodes[asset_id]["simulated_service"] = port or True
        # Un service supplémentaire rend l'actif atteignable par ses relations entrantes : saut plausible, simulé
        for _, _, data in graph.in_edges(asset_id, data=True):
            data["weight"] = round(min(data["weight"] + 10, 100.0), 1)
            data["simulated"] = True
            data["simulation_note"] = f"Service hypothétique exposé sur #{asset_id} ({label})"
            transition = data.get("transition")
            if transition is not None:
                transition = {**transition, "plausible": True,
                              "services": sorted(set(transition["services"]) | ({port} if port else set()))}
                transition["preconditions"] = transition["preconditions"] + [{
                    "condition": "Service hypothétique (simulation)", "status": "simulated",
                    "evidence": f"Ajouté par l'hypothèse : {label}"}]
                transition["uncertainties"] = transition["uncertainties"] + ["Service supposé par la simulation, non observé"]
                data["transition"] = transition

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
    paths_before = find_paths_on_graph(original_graph)  # graphe réel, en lecture seule

    simulated_graph = clone_graph(original_graph)
    simulated_graph = apply_hypothesis(simulated_graph, hypothesis)

    # Recalcul des chemins sur le graphe SIMULÉ (pas sur la base réelle)
    paths_after = find_paths_on_graph(simulated_graph)

    before_ids = {(p["source"], p["target"], tuple(p["nodes"])) for p in paths_before}
    new_paths = [p for p in paths_after if (p["source"], p["target"], tuple(p["nodes"])) not in before_ids]

    # Chemins déjà existants dont le score augmente sous l'hypothèse (ex: asset compromis)
    score_before = {(p["source"], p["target"], tuple(p["nodes"])): p["score"] for p in paths_before}
    escalated_paths = [
        {**p, "score_before": score_before[key]}
        for p in paths_after
        if (key := (p["source"], p["target"], tuple(p["nodes"]))) in score_before and p["score"] > score_before[key]
    ]

    return {
        "simulated": True,
        "note": "Résultat calculé sur une copie du modèle à partir d'une hypothèse : ni observé, ni déclaré.",
        "hypothesis": hypothesis,
        "paths_before_count": len(paths_before),
        "paths_after_count": len(paths_after),
        "new_paths_count": len(new_paths),
        "new_paths": new_paths,
        "escalated_paths_count": len(escalated_paths),
        "escalated_paths": escalated_paths,
        "paths_before": paths_before,
        "paths_after": paths_after,
    }

