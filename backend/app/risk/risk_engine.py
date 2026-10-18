import json
from datetime import datetime, UTC
from app.exposure.criticality import LEVEL_LABEL, LEVEL_POINTS, effective_criticality

# --- Référentiel des ports à risque, avec leur poids et justification ---
DANGEROUS_PORTS = {
    23:   {"label": "Telnet exposé",      "weight": 25},
    3389: {"label": "RDP exposé",         "weight": 20},
    445:  {"label": "SMB exposé",         "weight": 20},
    21:   {"label": "FTP exposé",         "weight": 15},
    139:  {"label": "NetBIOS exposé",     "weight": 10},
    3306: {"label": "MySQL exposé",       "weight": 10},
    5432: {"label": "PostgreSQL exposé",  "weight": 10},
}

CRITICAL_ASSET_TYPES = {
    "router": 20,
    "server": 15,
    "pc": 5,
    "unknown": 0,
}


def score_network_exposure(open_ports: list[int]) -> tuple[float, list[str]]:
    """Critère 1 (poids 30%) : exposition réseau / ports dangereux."""
    factors = []
    raw_score = 0
    for port in open_ports:
        if port in DANGEROUS_PORTS:
            info = DANGEROUS_PORTS[port]
            raw_score += info["weight"]
            factors.append(f"{info['label']} : +{info['weight']}")

    capped = min(raw_score, 100)
    return capped * 0.30, factors


def score_os_vulnerability(os_detected: str | None) -> tuple[float, list[str]]:
    """Critère 2 (poids 25%) : OS non identifié ou potentiellement obsolète."""
    factors = []
    if not os_detected:
        factors.append("OS non identifié : +40")
        return 40 * 0.25, factors

    outdated_markers = ["windows 7", "windows xp", "windows server 2008",
                         "windows server 2012", "2.6.32"]
    os_lower = os_detected.lower()
    if any(marker in os_lower for marker in outdated_markers):
        factors.append(f"OS potentiellement obsolète ({os_detected}) : +60")
        return 60 * 0.25, factors

    factors.append(f"OS identifié ({os_detected}) : +10")
    return 10 * 0.25, factors


def score_asset_criticality(criticality: dict) -> tuple[float, list[str]]:
    """Critère 3 (poids 20%) : criticité de l'actif, déclarée par l'opérateur ou inférée de son rôle."""
    level = criticality["level"]
    points = LEVEL_POINTS.get(level, 0)
    origin = "déclarée" if criticality["source"] == "declared" else f"inférée, confiance {criticality['confidence']:.0%}"
    factors = [f"Criticité {LEVEL_LABEL.get(level, level)} ({origin}) : +{points}"]
    return float(points), factors


def score_behavioral_signals(status: str, signals: list[tuple[int, str]] | None = None) -> tuple[float, list[str]]:
    """
    Critère 4 (poids 15%) : signaux comportementaux observés (indisponibilité, écarts à la référence,
    alertes IDS, actif non autorisé). Le signal le plus fort compte en entier, chaque signal supplémentaire +10.
    Sans contexte (`signals=None`), seul le statut est évalué, comme avant.
    """
    if signals is None:
        signals = [(50, "Asset actuellement down : +50")] if status == "down" else []
    if not signals:
        return 0, ["Aucun signal comportemental anormal : +0"]
    ordered = sorted(signals, key=lambda s: s[0], reverse=True)
    raw = min(ordered[0][0] + 10 * (len(ordered) - 1), 100)
    factors = [label for _, label in ordered]
    if len(ordered) > 1:
        factors.append(f"Signaux cumulés : {raw}/100")
    return raw * 0.15, factors


def score_data_freshness(last_seen: datetime | None) -> tuple[float, list[str]]:
    """Critère 5 (poids 10%) : fraîcheur des données. Données vieilles = score de risque incertain, donc pénalisé légèrement."""
    if not last_seen:
        return 100 * 0.10, ["Aucune donnée de dernière observation : +100"]

    now = datetime.now(UTC)
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=UTC)

    age_minutes = (now - last_seen).total_seconds() / 60

    if age_minutes < 15:
        return 0, ["Données récentes (<15 min) : +0"]
    elif age_minutes < 60:
        return 30 * 0.10, ["Données modérément récentes (<1h) : +30"]
    else:
        return 70 * 0.10, [f"Données anciennes ({int(age_minutes)} min) : +70"]


def score_confidence(asset, context: dict | None) -> dict:
    """Fiabilité du score : un score calculé sur peu de données mérite d'être lu avec prudence."""
    confidence, reasons = 1.0, []
    if not asset.os_detected:
        confidence -= 0.2
        reasons.append("OS non identifié : critère « vulnérabilité OS » estimé par défaut (−0,20)")
    if not asset.mac_address and not getattr(asset, "is_scanner", False):
        confidence -= 0.1
        reasons.append("MAC inconnue : identité moins sûre (−0,10)")
    if context is None:
        confidence -= 0.1
        reasons.append("Signaux comportementaux non évalués (−0,10)")
    elif not context.get("flow_visibility"):
        confidence -= 0.2
        reasons.append("Aucun flux observé par Suricata pour cet actif : comportement invisible (−0,20)")
    last_seen = asset.last_seen
    if last_seen is not None:
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=UTC)
        if (datetime.now(UTC) - last_seen).total_seconds() > 3600:
            confidence -= 0.2
            reasons.append("Dernière observation de plus d'une heure (−0,20)")
    if not reasons:
        reasons.append("Données complètes et récentes")
    return {"value": round(max(confidence, 0.1), 2), "reasons": reasons}


def calculate_risk(asset, context: dict | None = None) -> dict:
    """
    Calcule le risk_score complet (0-100) et retourne le détail explicatif.
    `context` (app.risk.signals.collect_signals) apporte les faits comportementaux observés en base.
    """
    open_ports = []
    if asset.open_ports:
        open_ports = [int(p) for p in asset.open_ports.split(",") if p.strip().isdigit()]

    s1, f1 = score_network_exposure(open_ports)
    s2, f2 = score_os_vulnerability(asset.os_detected)
    criticality = effective_criticality(asset)
    s3, f3 = score_asset_criticality(criticality)
    s4, f4 = score_behavioral_signals(asset.status, context["signals"] if context else None)
    s5, f5 = score_data_freshness(asset.last_seen)

    total = round(s1 + s2 + s3 + s4 + s5, 1)
    total = min(total, 100.0)

    if total < 25:
        level = "FAIBLE"
    elif total < 50:
        level = "MODÉRÉ"
    elif total < 75:
        level = "ÉLEVÉ"
    else:
        level = "CRITIQUE"

    all_factors = f1 + f2 + f3 + f4 + f5

    return {
        "risk_score": total,
        "risk_level": level,
        "factors": all_factors,
        "criticality": criticality,
        "confidence": score_confidence(asset, context),
        "breakdown": {
            "exposition_reseau": round(s1, 1),
            "vulnerabilite_os": round(s2, 1),
            "criticite_asset": round(s3, 1),
            "signaux_comportementaux": round(s4, 1),
            "fraicheur_donnees": round(s5, 1),
        },
    }


def format_risk_summary(asset_name: str, risk_result: dict) -> str:
    """Formatte un résumé lisible, façon rapport."""
    lines = [f"Risque : {risk_result['risk_score']}/100 — {risk_result['risk_level']}"]
    lines.extend(risk_result["factors"])
    return f"[{asset_name}] " + " | ".join(lines)
