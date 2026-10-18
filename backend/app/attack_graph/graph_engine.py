from itertools import islice
import networkx as nx
from sqlalchemy.orm import Session
from app.models.asset import Asset
from app.models.alert import Alert
from app.models.network_connection import NetworkConnection
from app.correlation.alert_correlation import compute_alert_score
from app.exposure.criticality import effective_criticality, is_target_level
from app.topology.relations import assess
from app.inventory.classification import parse_ports
from app.incidents.incident_engine import is_attack_relevant

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


def build_graph(db: Session, now=None) -> nx.DiGraph:
    """
    Construit le graphe orienté Asset -> Asset à partir des relations persistées, en corroborant chaque relation avec
    les alertes IDS disponibles. Une relation dont la période de validité est dépassée n'y figure pas.
    """
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
            open_ports=parse_ports(asset.open_ports),
        )

    connections = db.query(NetworkConnection).filter(NetworkConnection.status == "active").order_by(NetworkConnection.id).all()

    pair_data: dict[tuple[int, int], list[NetworkConnection]] = {}
    quality: dict[int, dict] = {}
    for conn in connections:
        quality[conn.id] = assess(conn, now)
        if quality[conn.id]["stale"]:
            continue
        key = (conn.source_asset_id, conn.destination_asset_id)
        pair_data.setdefault(key, []).append(conn)

    confirmed_vulns = _confirmed_vulnerabilities(db)

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
        alert_score, alert_summary, hostile = 0.0, None, []
        if src_asset and dest:
            alerts = alerts_by_pair.get((src_asset.ip_address, dest.ip_address), [])
            alert_score, alert_summary = compute_alert_score(alerts)
            # Activité hostile : alerte sévère (P1-P2) à caractère offensif ; une anomalie de protocole n'en est pas une
            hostile = sorted((a for a in alerts if a.priority is not None and a.priority <= 2 and is_attack_relevant(a)),
                             key=lambda a: (a.priority, -(a.occurrence_count or 0), a.id or 0))

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
            confidence=max(quality[c.id]["confidence"] for c in conns),
            relation_classes=sorted({quality[c.id]["relation_class"] for c in conns}),
            transition=assess_transition(dest, conns, quality, confirmed_vulns.get(dst, []), alert_summary, hostile),
            details=[
                {"id": c.id, "protocol": c.protocol, "port": c.port, "connection_type": c.connection_type,
                 "source": c.source, "last_seen": c.last_seen.isoformat() if c.last_seen else None,
                 "relation_class": quality[c.id]["relation_class"], "origin": quality[c.id]["origin"],
                 "confidence": quality[c.id]["confidence"], "reason": quality[c.id]["reason"],
                 "valid_until": quality[c.id]["valid_until"].isoformat() if quality[c.id]["valid_until"] else None}
                for c in conns
            ],
        )

    return graph


def _confirmed_vulnerabilities(db: Session) -> dict[int, list[dict]]:
    try:
        from app.models.vulnerability import VulnerabilityFinding
        rows = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.status == "confirmed").all()
    except Exception:  # noqa: BLE001 — table absente : aucune vulnérabilité confirmée
        db.rollback()
        return {}
    result: dict[int, list[dict]] = {}
    for f in rows:
        result.setdefault(f.asset_id, []).append({"id": f.id, "cve_id": f.cve_id, "port": f.port, "cvss_score": f.cvss_score})
    return result


def assess_transition(
    dest: Asset | None, conns: list[NetworkConnection], quality: dict, vulns: list[dict], alert_summary: dict | None,
    hostile: list[Alert] | None = None,
) -> dict:
    """
    Pourquoi un attaquant pourrait passer de la source à la cible, et ce qui manque pour l'affirmer.
    Un saut n'est plausible que si un service de la cible est atteignable par cette relation : une simple
    connexion réseau (ou un voisinage) vers un actif sans service connu ne suffit pas.
    """
    open_ports = set(parse_ports(dest.open_ports)) if dest else set()
    relation_ports = {c.port for c in conns if c.port is not None and (c.protocol or "").lower() in ("tcp", "udp")}
    if relation_ports:
        services = sorted(relation_ports)
        how = "port utilisé par la relation observée ou déclarée"
    else:
        services = sorted(open_ports)
        how = "port ouvert sur la cible (Nmap), atteignable depuis le même segment mais non vu en usage"
    best = max(conns, key=lambda c: quality[c.id]["confidence"])
    relation_text = f"{quality[best.id]['reason']} (confiance {quality[best.id]['confidence']:.0%})"
    exploit = [v for v in vulns if v.get("port") is None or v.get("port") in services]

    preconditions = [
        {"condition": "Relation réseau entre les deux actifs", "status": "satisfied", "evidence": relation_text},
        {"condition": "Service atteignable sur la cible",
         "status": "satisfied" if services else "unmet",
         "evidence": f"{', '.join(map(str, services))} : {how}" if services else "Aucun port ouvert ni port de relation connu sur la cible"},
        {"condition": "Moyen d'exploitation (vulnérabilité confirmée, identifiants ou mauvaise configuration)",
         "status": "satisfied" if exploit else "unknown",
         "evidence": ", ".join(f"{v['cve_id']} confirmée" for v in exploit) if exploit
         else "Aucune vulnérabilité confirmée : l'exploitation n'est pas démontrée"},
        {"condition": "Activité hostile observée sur cette paire",
         "status": "satisfied" if hostile else "not_observed",
         "evidence": (f"{hostile[0].message} (P{hostile[0].priority}, ×{hostile[0].occurrence_count})" if hostile
                      else f"Alertes présentes mais non offensives ({alert_summary['message']})" if alert_summary
                      else "Aucune alerte IDS de la source vers la cible"),
         "alert_ids": [a.id for a in (hostile or [])[:10]]},
    ]
    uncertainties = []
    if all(quality[c.id]["relation_class"] == "inferred" for c in conns):
        uncertainties.append("Relation seulement inférée (voisinage ARP) : aucune communication observée")
    if any(quality[c.id]["origin"] == "legacy" for c in conns) and len(conns) == 1:
        uncertainties.append("Relation de provenance inconnue (antérieure au suivi)")
    if not relation_ports and services:
        uncertainties.append("Service non vu en usage depuis la source : accessibilité supposée sur le segment")
    if not exploit:
        uncertainties.append("Exploitation non démontrée")
    return {
        "plausible": bool(services),
        "services": services,
        "preconditions": preconditions,
        "uncertainties": uncertainties,
        "exploit_evidence": [v["cve_id"] for v in exploit],
        "observed_activity": bool(hostile),
    }


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


def _plausible(graph: nx.DiGraph, u, v) -> bool:
    # Graphe sans évaluation de transition (construit à la main, ancien format) : arête acceptée telle quelle
    transition = graph.edges[u, v].get("transition")
    return True if transition is None else transition["plausible"]


def search_paths(
    graph: nx.DiGraph,
    min_score: float = 0.0,
    max_length: int = 4,
    sources: list[int] | None = None,
    targets: list[int] | None = None,
) -> tuple[list[dict], dict]:
    """
    Chemins simples (sans cycle) vers les cibles à forte valeur, sur les seuls sauts plausibles, avec le détail des
    préconditions et les limites de calcul atteintes. Ordre déterministe (score décroissant, puis nœuds).
    """
    if targets is None:
        targets = [n for n, data in graph.nodes(data=True) if is_target_node(data)]
    targets = sorted(targets)
    source_nodes = sorted(graph.nodes) if sources is None else sorted(n for n in sources if n in graph)
    view = nx.subgraph_view(graph, filter_edge=lambda u, v: _plausible(graph, u, v))
    excluded = sorted(
        ({"source": u, "target": v, "reason": "Aucun service atteignable connu sur la cible"}
         for u, v in graph.edges if not _plausible(graph, u, v)),
        key=lambda e: (e["source"], e["target"]),
    )
    meta = {"max_length": max_length, "max_paths_per_pair": MAX_PATHS_PER_PAIR, "max_total_paths": MAX_TOTAL_PATHS,
            "truncated_pairs": [], "total_limit_reached": False, "excluded_transitions": excluded}
    results = []

    for source in source_nodes:
        for target in targets:
            if source == target:
                continue
            if len(results) >= MAX_TOTAL_PATHS:
                meta["total_limit_reached"] = True
                break
            generator = nx.all_simple_paths(view, source, target, cutoff=max_length)
            paths = list(islice(generator, MAX_PATHS_PER_PAIR + 1))
            if len(paths) > MAX_PATHS_PER_PAIR:
                meta["truncated_pairs"].append([source, target])
                paths = paths[:MAX_PATHS_PER_PAIR]

            for path in paths:
                if len(path) < 2:
                    continue
                edges_data = [graph.edges[path[i], path[i + 1]] for i in range(len(path) - 1)]
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
                transitions = [e.get("transition") for e in edges_data]
                observed = all(t and t["observed_activity"] for t in transitions)
                steps = [
                    {"source": path[i], "target": path[i + 1], "weight": edges_data[i]["weight"],
                     "confidence": edges_data[i].get("confidence"), "relation_classes": edges_data[i].get("relation_classes", []),
                     **({k: transitions[i][k] for k in ("services", "preconditions", "uncertainties", "exploit_evidence", "observed_activity")}
                        if transitions[i] else {})}
                    for i in range(len(path) - 1)
                ]
                uncertainties = sorted({u for t in transitions if t for u in t["uncertainties"]})

                results.append({
                    "source": source,
                    "target": target,
                    "nodes": path,
                    "score": path_score,
                    "risk": risk_label_for(path_score),
                    "hops": len(path) - 1,
                    "evidence_level": EVIDENCE_LABELS[weakest_rank],
                    "connection_types": connection_types,
                    "alert_evidence": alert_summaries,
                    # Observé : chaque saut est corroboré par une détection IDS ; sinon chemin hypothétique
                    "nature": "observed" if observed else "hypothetical",
                    "confidence": min((e.get("confidence") or 0.3) for e in edges_data),
                    "exploitation_demonstrated": all(t and t["exploit_evidence"] for t in transitions),
                    "uncertainties": uncertainties,
                    "steps": steps,
                    "simulated": any(e.get("simulated") for e in edges_data),
                })
        if meta["total_limit_reached"]:
            break

    results.sort(key=lambda r: (-r["score"], r["nodes"]))
    return results, meta


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
    return search_paths(graph, min_score, max_length, sources, targets)[0]


def find_attack_paths(db: Session, min_score: float = 0.0, max_length: int = 4) -> list[dict]:
    """
    Trouve tous les chemins simples entre assets, évalue leur score cumulé,
    et retourne ceux vers des cibles à risque (score cible élevé).
    """
    return find_paths_on_graph(build_graph(db), min_score=min_score, max_length=max_length)
