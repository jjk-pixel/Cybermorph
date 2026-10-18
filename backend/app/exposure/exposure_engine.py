"""
Analyse d'exposition : chemins vers les actifs critiques, points d'entrée qualifiés, points de blocage,
rayon d'impact et recommandations chiffrées.

Principes (inspirés de la gestion d'exposition, sans reprendre d'algorithme propriétaire) :
- une cible est un actif critique (criticité élevée ou critique) ou déjà très risqué ;
- un point d'entrée n'est « qualifié » que par un fait (incident, alerte IDS émise, service dangereux exposé) ;
  sinon le chemin repose sur l'hypothèse d'un actif interne quelconque compromis, et c'est dit ;
- un point de blocage est un actif intermédiaire par lequel passent plusieurs chemins ;
- une recommandation est évaluée de façon contrefactuelle : on retire l'élément d'une COPIE du graphe et on
  mesure ce qui disparaît. C'est une estimation sur le modèle, jamais une action sur le réseau.
"""
from datetime import datetime, timedelta, UTC

import networkx as nx
from sqlalchemy.orm import Session

from app.attack_graph.graph_engine import build_graph, find_paths_on_graph, is_target_node, search_paths
from app.exposure.criticality import LEVEL_LABEL, effective_criticality
from app.incidents.incident_engine import ACTIVE_STATUSES
from app.inventory.classification import parse_ports
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.incident import Incident
from app.risk.risk_engine import DANGEROUS_PORTS

DEFAULT_MIN_SCORE = 25.0
DEFAULT_MAX_LENGTH = 4
ALERT_ENTRY_WINDOW = timedelta(hours=24)
MAX_RECOMMENDATION_CANDIDATES = 60
MAX_RECOMMENDATIONS = 10

ENTRY_LABELS = {
    "incident": "Source ou position actuelle d'un incident actif",
    "ids_alert_source": "Émetteur d'une alerte IDS sévère (24 h)",
    "dangerous_service": "Expose un service à risque",
    "assumed": "Hypothèse : actif interne compromis (aucun fait ne le qualifie)",
}

ASSUMPTIONS = [
    "Les chemins suivent les relations connues (observées, voisinage ARP, déclarées) : une relation non observée n'existe pas pour le modèle.",
    "Un saut n'est retenu que si un service de la cible est atteignable par la relation ; une simple connexion ne suffit pas.",
    "Le score d'un chemin mesure sa plausibilité relative sur ce modèle, pas une probabilité d'attaque.",
    "Les recommandations sont des estimations contrefactuelles : retirer une liaison ou un actif d'une copie du graphe et mesurer les chemins qui disparaissent.",
    "Seules les vulnérabilités confirmées par l'opérateur valent moyen d'exploitation ; sinon l'exploitation reste non démontrée.",
]


def _total(paths: list[dict]) -> float:
    return round(sum(p["score"] for p in paths), 1)


def qualify_entry_points(db: Session, assets: dict[int, Asset]) -> dict[int, list[dict]]:
    """Faits qui font d'un actif un point d'entrée plausible, avec leur justification."""
    entries: dict[int, list[dict]] = {}

    def add(asset_id: int | None, kind: str, detail: str):
        if asset_id is None or asset_id not in assets:
            return
        if any(e["kind"] == kind for e in entries.get(asset_id, [])):
            return
        entries.setdefault(asset_id, []).append({"kind": kind, "label": ENTRY_LABELS[kind], "detail": detail})

    for incident in db.query(Incident).filter(Incident.status.in_(ACTIVE_STATUSES)).all():
        detail = f"Incident #{incident.id} ({incident.technique_id or 'technique non identifiée'})"
        add(incident.source_asset_id, "incident", detail)
        add(incident.current_asset_id, "incident", detail)

    by_ip = {a.ip_address: a.id for a in assets.values()}
    since = datetime.now(UTC) - ALERT_ENTRY_WINDOW
    for alert in db.query(Alert).filter(Alert.priority <= 2, Alert.last_seen >= since).all():
        add(by_ip.get(alert.source_ip), "ids_alert_source", f"{alert.message} (P{alert.priority}, ×{alert.occurrence_count})")

    for asset in assets.values():
        dangerous = [DANGEROUS_PORTS[p]["label"] for p in parse_ports(asset.open_ports) if p in DANGEROUS_PORTS]
        if dangerous:
            add(asset.id, "dangerous_service", ", ".join(dangerous))
    return entries


def compute_choke_points(paths: list[dict]) -> list[dict]:
    """Actifs intermédiaires traversés par au moins deux chemins vers une cible."""
    through: dict[int, dict] = {}
    for p in paths:
        # Une cible traversée en route vers une autre cible reste un point de passage : elle est comptée
        for node in p["nodes"][1:-1]:
            entry =through.setdefault(node, {"paths": 0, "score_sum": 0.0, "max_score": 0.0, "targets": set(), "sources": set()})
            entry["paths"] += 1
            entry["score_sum"] += p["score"]
            entry["max_score"] = max(entry["max_score"], p["score"])
            entry["targets"].add(p["target"])
            entry["sources"].add(p["source"])

    total = len(paths) or 1
    result = [
        {
            "asset_id": node,
            "paths": data["paths"],
            "share": round(data["paths"] / total, 3),
            "score_sum": round(data["score_sum"], 1),
            "max_score": data["max_score"],
            "targets": sorted(data["targets"]),
            "sources": sorted(data["sources"]),
        }
        for node, data in through.items()
        if data["paths"] >= 2
    ]
    result.sort(key=lambda c: (c["score_sum"], c["paths"]), reverse=True)
    return result


def _edge_measure(graph: nx.DiGraph, u: int, v: int, label) -> tuple[str, str]:
    data = graph.edges[u, v]
    details = data.get("details", [])
    observed = sorted({
        (d["protocol"] if (d.get("protocol") or "").lower() == "icmp" else f"{d['protocol']}/{d['port']}")
        for d in details
        if d.get("port") is not None and d.get("connection_type") in ("detected", "declared")
    })
    if observed:
        action = f"Filtrer {', '.join(observed)} de {label(u)} vers {label(v)}"
        why = "Relation observée sur ces ports : une règle de filtrage la coupe sans isoler les actifs."
    elif all(ct == "neighbor_detected" for ct in data.get("connection_types", []) if ct != "alert"):
        action = f"Segmenter {label(u)} et {label(v)} (VLAN ou ACL de niveau 2)"
        why = "Leur seule relation connue est le voisinage ARP : ils partagent le même segment."
    else:
        action = f"Restreindre les flux de {label(u)} vers {label(v)}"
        why = "Relation présente dans le modèle sans port identifié."
    if data.get("alert_summary"):
        why += f" Liaison corroborée par une alerte IDS ({data['alert_summary']['message']}) : à traiter en priorité."
    return action, why


def compute_recommendations(
    graph: nx.DiGraph, paths: list[dict], label, min_score: float, max_length: int, choke_ids: list[int],
) -> list[dict]:
    """Classe liaisons et actifs de passage selon la réduction du score total des chemins s'ils étaient retirés."""
    if not paths:
        return []
    total_before = _total(paths)
    targets_before = {p["target"] for p in paths}

    edge_use: dict[tuple[int, int], int] = {}
    for p in paths:
        for i in range(len(p["nodes"]) - 1):
            key = (p["nodes"][i], p["nodes"][i + 1])
            edge_use[key] = edge_use.get(key, 0) + 1
    candidates: list[tuple[str, object]] = [("edge", e) for e, _ in sorted(edge_use.items(), key=lambda kv: -kv[1])]
    candidates += [("node", n) for n in choke_ids]
    candidates = candidates[:MAX_RECOMMENDATION_CANDIDATES]

    results = []
    for kind, element in candidates:
        trial = graph.copy()
        if kind == "edge":
            trial.remove_edge(*element)
        else:
            trial.remove_node(element)
        after = find_paths_on_graph(trial, min_score=min_score, max_length=max_length)
        reduction = round(total_before - _total(after), 1)
        if reduction <= 0:
            continue
        unreachable = sorted(targets_before - {p["target"] for p in after} - ({element} if kind == "node" else set()))

        if kind == "edge":
            u, v = element
            action, why = _edge_measure(graph, u, v, label)
            subject = {"source_asset_id": u, "destination_asset_id": v}
        else:
            action = f"Renforcer ou isoler {label(element)}"
            why = "Point de passage de plusieurs chemins vers des actifs critiques."
            subject = {"asset_id": element}

        results.append({
            "kind": kind,
            **subject,
            "action": action,
            "rationale": why,
            "paths_removed": len(paths) - len(after),
            "paths_remaining": len(after),
            "score_reduction": reduction,
            "score_reduction_pct": round(100 * reduction / total_before, 1) if total_before else 0.0,
            "max_score_after": max((p["score"] for p in after), default=0.0),
            "targets_protected": unreachable,
        })

    results.sort(key=lambda r: (r["score_reduction"], r["kind"] == "edge"), reverse=True)
    return results[:MAX_RECOMMENDATIONS]


def analyze_exposure(db: Session, min_score: float = DEFAULT_MIN_SCORE, max_length: int = DEFAULT_MAX_LENGTH) -> dict:
    assets = {a.id: a for a in db.query(Asset).all()}
    label = lambda asset_id: assets[asset_id].ip_address if asset_id in assets else f"#{asset_id}"  # noqa: E731

    graph = build_graph(db)
    paths, limits = search_paths(graph, min_score=min_score, max_length=max_length)
    target_ids = {n for n, data in graph.nodes(data=True) if is_target_node(data)}
    entries = qualify_entry_points(db, assets)

    for p in paths:
        p["entry"] = entries.get(p["source"]) or [{"kind": "assumed", "label": ENTRY_LABELS["assumed"], "detail": None}]

    targets = []
    for asset_id in sorted(target_ids):
        asset = assets.get(asset_id)
        if not asset:
            continue
        crit = effective_criticality(asset)
        to_target = [p for p in paths if p["target"] == asset_id]
        targets.append({
            "asset_id": asset_id,
            "criticality": crit,
            "why_target": (
                f"Criticité {LEVEL_LABEL[crit['level']]}" if crit["level"] in ("high", "critical")
                else f"Risque élevé ({asset.risk_score:.0f}/100)"
            ),
            "paths": len(to_target),
            "max_score": max((p["score"] for p in to_target), default=0.0),
            "qualified_entries": sorted({p["source"] for p in to_target if p["entry"][0]["kind"] != "assumed"}),
        })
    targets.sort(key=lambda t: (t["max_score"], t["paths"]), reverse=True)

    entry_points = []
    for asset_id, facts in entries.items():
        from_entry = [p for p in paths if p["source"] == asset_id]
        entry_points.append({
            "asset_id": asset_id,
            "facts": facts,
            "paths": len(from_entry),
            "max_score": max((p["score"] for p in from_entry), default=0.0),
        })
    entry_points.sort(key=lambda e: (e["max_score"], e["paths"]), reverse=True)

    choke_points = compute_choke_points(paths)
    recommendations = compute_recommendations(
        graph, paths, label, min_score, max_length, [c["asset_id"] for c in choke_points],
    )

    return {
        "generated_at": datetime.now(UTC),
        "parameters": {"min_score": min_score, "max_length": max_length},
        "summary": {
            "paths": len(paths),
            "total_score": _total(paths),
            "max_score": max((p["score"] for p in paths), default=0.0),
            "targets": len(targets),
            "targets_reached": sum(1 for t in targets if t["paths"] > 0),
            "qualified_entry_points": len(entry_points),
            "paths_from_qualified_entries": sum(1 for p in paths if p["entry"][0]["kind"] != "assumed"),
        },
        "targets": targets,
        "entry_points": entry_points,
        "choke_points": choke_points,
        "recommendations": recommendations,
        "paths": paths[:100],
        "limits": limits,
        "assumptions": ASSUMPTIONS,
    }


def blast_radius(db: Session, asset_id: int, min_score: float = 0.0, max_length: int = DEFAULT_MAX_LENGTH) -> dict | None:
    """Actifs atteignables si `asset_id` était compromis : meilleur chemin vers chacun d'eux."""
    graph = build_graph(db)
    if asset_id not in graph:
        return None
    others = [n for n in graph.nodes if n != asset_id]
    paths = find_paths_on_graph(graph, min_score=min_score, max_length=max_length, sources=[asset_id], targets=others)
    best: dict[int, dict] = {}
    for p in paths:
        if p["target"] not in best or p["score"] > best[p["target"]]["score"]:
            best[p["target"]] = p
    reachable = [
        {
            "asset_id": target,
            "criticality": graph.nodes[target].get("criticality"),
            "critical": is_target_node(graph.nodes[target]),
            "score": p["score"],
            "hops": p["hops"],
            "nodes": p["nodes"],
            "evidence_level": p["evidence_level"],
        }
        for target, p in best.items()
    ]
    reachable.sort(key=lambda r: r["score"], reverse=True)
    return {
        "asset_id": asset_id,
        "hypothesis": "L'actif est supposé compromis ; calcul sur une copie du modèle, aucune action sur le réseau.",
        "reachable": reachable,
        "reachable_count": len(reachable),
        "critical_reachable": sum(1 for r in reachable if r["critical"]),
        "unreachable": sorted(set(others) - set(best)),
    }
