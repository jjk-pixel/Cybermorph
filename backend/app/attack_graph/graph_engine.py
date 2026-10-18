from itertools import islice
import networkx as nx
from sqlalchemy.orm import Session
from app.models.asset import Asset
from app.models.alert import Alert
from app.models.network_connection import NetworkConnection
from app.correlation.alert_correlation import compute_alert_score
from app.exposure.criticality import effective_criticality, is_target_level

# Poids de transition, par type de service exposé sur la connexion cible
SERVICE_EXPOSURE_WEIGHTS = {
    "ssh": 15,
    "rdp": 25,
    "smb": 25,
    "mysql": 20,
    "postgresql": 20,
    "domain": 10,   # DNS
    "http": 10,
    "https": 5,
}

# Poids selon le type de preuve de la relation (connection_type)
EVIDENCE_WEIGHTS = {
    "detected": 15,          # observé directement (scan de service réel)
    "neighbor_detected": 5,  # simple voisinage ARP, preuve plus faible
    "inferred": 8,
    "declared": 15,          # déclaré manuellement = considéré fiable
}

# Hiérarchie de fiabilité des preuves, du plus faible au plus fort
EVIDENCE_RANK = {
    "neighbor_detected": 1,  # voisinage ARP seul
    "inferred": 2,
    "detected": 3,           # observation réelle de service/trafic
    "declared": 3,           # déclaré manuellement, considéré fiable
    "alert": 4,  # le plus fort : corroboré par une détection de sécurité active
}

EVIDENCE_LABELS = {
    1: "voisinage_detecte",     # le plus faible : ARP seulement
    2: "inferee",
    3: "observee",              # le plus solide : connexion réellement constatée
    4: "alerte_ids",
}

# Garde-fous contre l'explosion combinatoire de all_simple_paths sur un graphe dense
MAX_PATHS_PER_PAIR = 25
MAX_TOTAL_PATHS = 500


def build_graph(db: Session) -> nx.DiGraph:
    """Construit le graphe orienté Asset -> Asset, en corroborant chaque relation avec les alertes IDS disponibles."""
    graph = nx.DiGraph()

    assets = db.query(Asset).all()
    assets_by_id = {a.id: a for a in assets}

    for asset in assets:
        graph.add_node(
            asset.id,
            ip=asset.ip_address,
            name=asset.name,
            asset_type=asset.asset_type,
            risk_score=asset.risk_score or 0.0,
            status=asset.status,
            criticality=effective_criticality(asset)["level"],
        )

    connections = db.query(NetworkConnection).filter(NetworkConnection.status == "active").all()

    pair_data: dict[tuple[int, int], list[NetworkConnection]] = {}
    for conn in connections:
        key = (conn.source_asset_id, conn.destination_asset_id)
        pair_data.setdefault(key, []).append(conn)

    # Chargement unique des alertes, regroupées par paire (source_ip, destination_ip)
    alerts_by_pair: dict[tuple[str, str], list[Alert]] = {}
    for alert in db.query(Alert).all():
        alerts_by_pair.setdefault((alert.source_ip, alert.destination_ip), []).append(alert)

    for (src, dst), conns in pair_data.items():
        dest = assets_by_id.get(dst)
        weights = [_transition_weight(dest, c) for c in conns]
        base_weight = max(weights)
        connection_types = [c.connection_type for c in conns]

        # Corrélation : cette relation est-elle corroborée par une alerte IDS réelle ?
        src_asset = assets_by_id.get(src)
        alert_score, alert_summary = 0.0, None
        if src_asset and dest:
            alerts = alerts_by_pair.get((src_asset.ip_address, dest.ip_address), [])
            alert_score, alert_summary = compute_alert_score(alerts)

        if alert_score > 0:
            # La preuve d'alerte renforce le score de transition (pondération 60% preuve réseau / 40% preuve IDS)
            final_weight = round(min(base_weight * 0.6 + (alert_score / 60 * 100) * 0.4, 100.0), 1)
            connection_types.append("alert")
        else:
            final_weight = base_weight

        graph.add_edge(
            src, dst,
            weight=final_weight,
            connection_types=connection_types,
            alert_summary=alert_summary,
            details=[
                {"protocol": c.protocol, "port": c.port, "connection_type": c.connection_type,
                 "source": c.source, "last_seen": c.last_seen.isoformat() if c.last_seen else None}
                for c in conns
            ],
        )

    return graph


def compute_transition_weight(db: Session, conn: NetworkConnection) -> float:
    """Variante historique : charge l'asset cible puis délègue au calcul pur."""
    dest = db.query(Asset).filter(Asset.id == conn.destination_asset_id).first()
    return _transition_weight(dest, conn)


def _transition_weight(dest: Asset | None, conn: NetworkConnection) -> float:
    """
    Calcule un score de transition (0-100) représentant la facilité/plausibilité
    de progression d'un attaquant de source_asset vers destination_asset.

    Critères (niveau 1, déterministe) :
    - reachability      (20) : la connexion existe et est active
    - service_exposure  (25) : le service exposé sur la cible est-il sensible
    - asset_risk        (20) : le risk_score déjà calculé de l'asset cible
    - privilege         (20) : type d'asset cible (server/router = plus intéressant)
    - evidence          (15) : fiabilité de la preuve de connexion
    """
    if not dest:
        return 0.0

    reachability = 20.0

    service_exposure = 0.0
    if dest.services:
        dest_services = [s.strip().lower() for s in dest.services.split(",")]
        matched_weights = [SERVICE_EXPOSURE_WEIGHTS.get(s, 0) for s in dest_services]
        service_exposure = min(max(matched_weights, default=0), 25)

    asset_risk = min((dest.risk_score or 0.0) / 100 * 20, 20)

    privilege_map = {"router": 20, "firewall": 20, "server": 15, "pc": 8, "iot": 5, "unknown": 3}
    privilege = privilege_map.get(dest.asset_type, 3)

    evidence = EVIDENCE_WEIGHTS.get(conn.connection_type, 5)

    total = reachability + service_exposure + asset_risk + privilege + evidence
    return round(min(total, 100.0), 1)


def risk_label_for(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "moderate"
    return "low"


def is_target_node(data: dict) -> bool:
    """
    Cible d'un chemin d'attaque : actif critique (criticité élevée ou critique, déclarée ou inférée)
    ou actif déjà très risqué. Repli sur le rôle pour un graphe construit sans criticité.
    """
    if data.get("risk_score", 0) >= 50:
        return True
    if "criticality" in data:
        return is_target_level(data["criticality"])
    return data.get("asset_type") in ("server", "router")


def find_paths_on_graph(
    graph: nx.DiGraph,
    min_score: float = 0.0,
    max_length: int = 4,
    sources: list[int] | None = None,
    targets: list[int] | None = None,
) -> list[dict]:
    """
    Trouve les chemins simples vers les cibles à forte valeur d'un graphe déjà construit
    (graphe réel ou graphe simulé), évalue leur score cumulé et leur niveau de preuve.
    `sources` / `targets` restreignent la recherche (rayon d'impact : une source, toutes les cibles).
    """
    results = []

    if targets is None:
        targets = [n for n, data in graph.nodes(data=True) if is_target_node(data)]
    source_nodes = list(graph.nodes) if sources is None else [n for n in sources if n in graph]

    for source in source_nodes:
        for target in targets:
            if source == target or len(results) >= MAX_TOTAL_PATHS:
                continue

            paths = islice(nx.all_simple_paths(graph, source, target, cutoff=max_length), MAX_PATHS_PER_PAIR)

            for path in paths:
                if len(path) < 2:
                    continue

                edges_data = [
                    graph.edges[path[i], path[i + 1]]
                    for i in range(len(path) - 1)
                ]
                edge_weights = [e["weight"] for e in edges_data]

                length_penalty = 0.85 ** (len(path) - 2)
                path_score = round((sum(edge_weights) / len(edge_weights)) * length_penalty, 1)

                if path_score < min_score:
                    continue

                # Niveau de preuve du chemin = maillon le plus faible sur le trajet,
                # chaque maillon valant sa preuve la plus forte (ARP + alerte IDS sur la même paire = alerte IDS)
                connection_types = []
                alert_summaries = []
                for e in edges_data:
                    connection_types.extend(e["connection_types"])
                    if e.get("alert_summary"):
                        alert_summaries.append(e["alert_summary"])

                weakest_rank = min(
                    max(EVIDENCE_RANK.get(ct, 1) for ct in e["connection_types"])
                    for e in edges_data
                )
                evidence_level = EVIDENCE_LABELS[weakest_rank]

                results.append({
                    "source": source,
                    "target": target,
                    "nodes": path,
                    "score": path_score,
                    "risk": risk_label_for(path_score),
                    "hops": len(path) - 1,
                    "evidence_level": evidence_level,
                    "connection_types": connection_types,
                    "alert_evidence": alert_summaries,
                })

    results.sort(key=lambda r: r["score"], reverse=True)
    return results


def find_attack_paths(db: Session, min_score: float = 0.0, max_length: int = 4) -> list[dict]:
    """
    Trouve tous les chemins simples entre assets, évalue leur score cumulé,
    et retourne ceux vers des cibles à risque (score cible élevé).
    """
    return find_paths_on_graph(build_graph(db), min_score=min_score, max_length=max_length)
