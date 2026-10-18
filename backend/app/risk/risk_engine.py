"""
Moteur de risque explicable (modèle 2).

Le score (0-100) est une **mesure relative de priorisation**, pas une probabilité de compromission : aucun modèle
statistique validé ne permettrait de l'interpréter ainsi. Il additionne quatre critères plafonnés :

| Critère                  | Max | Ce qui compte                                                              |
|--------------------------|-----|----------------------------------------------------------------------------|
| exposition_reseau        | 30  | services à risque réellement exposés (liste DANGEROUS_PORTS), un par port  |
| vulnerabilites           | 25  | vulnérabilités CONFIRMÉES (CVSS) ; à défaut, OS estimé hors support        |
| criticite_asset          | 20  | criticité déclarée ou inférée (échelle historique)                         |
| signaux_comportementaux  | 25  | écarts, alertes IDS, actif non autorisé ; chaque événement compté une fois |

Principes :
- une donnée manquante n'augmente jamais le score : elle est listée (`missing_data`) et baisse la confiance ;
- un port ouvert ordinaire n'ajoute rien ; seuls les services à risque documentés comptent ;
- l'indisponibilité et la fraîcheur des données agissent sur la confiance, pas sur le score ;
- à données et date égales, le résultat est identique (`now` est un paramètre) ;
- le risque reste « potentiel » ; les indices de compromission (étape d'incident confirmée par IDS) sont listés à
  part et ne sont pas présentés comme une compromission constatée.

Seuils de gravité (RISK_LEVELS) : FAIBLE < 25 ≤ MODÉRÉ < 50 ≤ ÉLEVÉ < 75 ≤ CRITIQUE ; les mêmes bornes servent aux
chemins d'attaque (graph_engine.risk_label_for).
"""
from datetime import datetime, UTC

from app.exposure.criticality import LEVEL_LABEL, LEVEL_POINTS, effective_criticality

MODEL_VERSION = 2

# --- Référentiel des ports à risque, avec leur poids et justification ---
DANGEROUS_PORTS = {
    23:   {"label": "Telnet exposé",      "weight": 25, "why": "administration en clair, identifiants interceptables"},
    3389: {"label": "RDP exposé",         "weight": 20, "why": "accès graphique à distance, cible fréquente de force brute"},
    445:  {"label": "SMB exposé",         "weight": 20, "why": "partage de fichiers Windows, vecteur de propagation latérale"},
    21:   {"label": "FTP exposé",         "weight": 15, "why": "transfert de fichiers en clair"},
    139:  {"label": "NetBIOS exposé",     "weight": 10, "why": "service hérité, énumération d'informations"},
    3306: {"label": "MySQL exposé",       "weight": 10, "why": "base de données accessible par le réseau"},
    5432: {"label": "PostgreSQL exposé",  "weight": 10, "why": "base de données accessible par le réseau"},
}

CRITERIA = {
    "exposition_reseau": {"label": "Exposition réseau", "max": 30.0},
    "vulnerabilites": {"label": "Vulnérabilités", "max": 25.0},
    "criticite_asset": {"label": "Criticité", "max": 20.0},
    "signaux_comportementaux": {"label": "Signaux comportementaux", "max": 25.0},
}

RISK_LEVELS = [(75.0, "CRITIQUE"), (50.0, "ÉLEVÉ"), (25.0, "MODÉRÉ"), (0.0, "FAIBLE")]

# Fin de support éditeur : fait documenté, mais appliqué à une ESTIMATION d'OS par Nmap
OUTDATED_OS_MARKERS = ["windows 7", "windows xp", "windows vista", "windows server 2003", "windows server 2008",
                       "windows server 2012", "2.6.32"]
OUTDATED_OS_RAW = 40

DISCLAIMER = "Score relatif de priorisation (0-100), pas une probabilité de compromission."


def level_for(score: float) -> str:
    return next(label for threshold, label in RISK_LEVELS if score >= threshold)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _criterion(key: str, raw: float, items: list[dict], note: str | None = None) -> dict:
    max_points = CRITERIA[key]["max"]
    raw = max(0.0, min(raw, 100.0))
    return {
        "criterion": key, "label": CRITERIA[key]["label"], "max": max_points, "raw": round(raw, 1),
        "points": round(raw * max_points / 100, 1), "items": items, "note": note,
    }


def score_network_exposure(open_ports: list[int]) -> dict:
    items = [
        {"label": DANGEROUS_PORTS[p]["label"], "raw": DANGEROUS_PORTS[p]["weight"],
         "justification": f"Port {p} ouvert (Nmap / ss) : {DANGEROUS_PORTS[p]['why']}", "evidence": [f"port:{p}"]}
        for p in sorted(set(open_ports)) if p in DANGEROUS_PORTS
    ]
    others = len(set(open_ports)) - len(items)
    note = f"{others} autre(s) port(s) ouvert(s) sans risque documenté : non comptés" if others else None
    return _criterion("exposition_reseau", sum(i["raw"] for i in items), items, note)


def score_vulnerabilities(os_detected: str | None, findings: list[dict]) -> dict:
    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    pending = [f for f in findings if f.get("status") in ("probable", "uncertain")]
    items = []
    if confirmed:
        ranked = sorted(confirmed, key=lambda f: -(f.get("cvss_score") or 0))
        top = ranked[0].get("cvss_score")
        raw = (top * 10 if top is not None else 50) + 5 * (len(confirmed) - 1)
        for f in ranked:
            items.append({"label": f"{f['cve_id']} confirmée", "raw": round((f.get('cvss_score') or 5) * 10, 1),
                          "justification": f"{f.get('product') or ''} {f.get('version') or ''} : correspondance validée"
                                           + (f", CVSS {f['cvss_score']}" if f.get("cvss_score") is not None else ", CVSS inconnu"),
                          "evidence": [f"vulnerability:{f['id']}"]})
    else:
        raw = 0
        os_l = (os_detected or "").lower()
        if os_l and any(m in os_l for m in OUTDATED_OS_MARKERS):
            raw = OUTDATED_OS_RAW
            items.append({"label": "OS estimé hors support éditeur", "raw": OUTDATED_OS_RAW,
                          "justification": f"Empreinte Nmap « {os_detected} » : système sans correctifs de sécurité, "
                                           "à confirmer (l'empreinte est une estimation)", "evidence": ["os"]})
    note = None
    if pending:
        note = f"{len(pending)} correspondance(s) non confirmée(s) (version annoncée ou ambiguë) : non comptées dans le score"
    return _criterion("vulnerabilites", raw, items, note)


def score_asset_criticality(criticality: dict) -> dict:
    level = criticality["level"]
    points = LEVEL_POINTS.get(level, 0)
    origin = "déclarée" if criticality["source"] == "declared" else f"inférée, confiance {criticality['confidence']:.0%}"
    item = {"label": f"Criticité {LEVEL_LABEL.get(level, level)} ({origin})", "raw": points * 5,
            "justification": " ; ".join(criticality["reasons"]), "evidence": [f"criticality:{criticality['source']}"]}
    return _criterion("criticite_asset", points * 5, [item])


def score_behavioral_signals(signals: list[dict]) -> dict:
    """Le signal le plus fort compte en entier, chaque signal distinct supplémentaire +10 (plafond 100)."""
    if not signals:
        return _criterion("signaux_comportementaux", 0, [], "Aucun signal comportemental anormal observé")
    ordered = sorted(signals, key=lambda s: (-s["points"], s["label"]))
    raw = ordered[0]["points"] + 10 * (len(ordered) - 1)
    items = [{"label": s["label"], "raw": s["points"], "justification": s["label"], "evidence": s["evidence"]} for s in ordered]
    note = f"Signal principal compté en entier, {len(ordered) - 1} autre(s) à +10" if len(ordered) > 1 else None
    return _criterion("signaux_comportementaux", raw, items, note)


def missing_data(asset, context: dict | None) -> list[str]:
    missing = []
    if not asset.os_detected:
        missing.append("Système d'exploitation non identifié : vulnérabilités système non évaluables")
    classification = asset.classification if isinstance(asset.classification, dict) else {}
    services = classification.get("services") or []
    if asset.open_ports and not any(s.get("version") for s in services if isinstance(s, dict)):
        missing.append("Versions des services inconnues : aucune correspondance de vulnérabilité possible")
    if context is not None and not context.get("vulnerability_source", False):
        missing.append("Aucune source de vulnérabilités configurée (CVE non évaluées)")
    if not asset.mac_address and not getattr(asset, "is_scanner", False):
        missing.append("Adresse MAC inconnue : identité moins sûre")
    if context is None:
        missing.append("Signaux comportementaux non évalués")
    elif not context.get("flow_visibility"):
        missing.append("Aucun flux observé par Suricata pour cet actif : comportement non visible")
    return missing


def score_confidence(asset, context: dict | None, now: datetime | None = None) -> dict:
    """Fiabilité du score : un score calculé sur peu de données, ou sur des données anciennes, se lit avec prudence."""
    now = now or datetime.now(UTC)
    confidence, reasons = 1.0, []

    def lower(amount: float, reason: str):
        nonlocal confidence
        confidence -= amount
        reasons.append(f"{reason} (−{amount:.2f})".replace(".", ","))

    if not asset.os_detected:
        lower(0.15, "OS non identifié")
    if not asset.mac_address and not getattr(asset, "is_scanner", False):
        lower(0.1, "MAC inconnue")
    if context is None:
        lower(0.1, "Signaux comportementaux non évalués")
    elif not context.get("flow_visibility"):
        lower(0.2, "Aucun flux observé par Suricata : comportement invisible")
    if asset.status == "down":
        lower(0.2, "Actif hors ligne : état figé à la dernière observation")
    elif asset.status == "unknown":
        lower(0.1, "Actif non observé au dernier balayage")
    last_seen = _as_utc(asset.last_seen)
    if last_seen is None:
        lower(0.3, "Aucune date d'observation")
    else:
        age = (now - last_seen).total_seconds()
        if age > 3600:
            lower(0.3, "Dernière observation de plus d'une heure")
        elif age > 900:
            lower(0.1, "Dernière observation de plus de 15 minutes")
    if not reasons:
        reasons.append("Données complètes et récentes")
    return {"value": round(max(confidence, 0.1), 2), "reasons": reasons}


def calculate_risk(asset, context: dict | None = None, now: datetime | None = None) -> dict:
    """
    Score explicable d'un actif. `context` (app.risk.signals.collect_signals) apporte les faits observés en base ;
    `now` fixe la date de calcul (déterminisme).
    """
    now = now or datetime.now(UTC)
    open_ports = [int(p) for p in (asset.open_ports or "").split(",") if p.strip().isdigit()]
    criticality = effective_criticality(asset)
    context_signals = (context or {}).get("signals", [])
    contributors = [
        score_network_exposure(open_ports),
        score_vulnerabilities(asset.os_detected, (context or {}).get("vulnerabilities", [])),
        score_asset_criticality(criticality),
        score_behavioral_signals(context_signals),
    ]
    total = round(min(max(sum(c["points"] for c in contributors), 0.0), 100.0), 1)
    factors = []
    for c in contributors:
        factors += [f"{i['label']} : +{i['raw']:g}" for i in c["items"]]
    if not context_signals:
        factors.append("Aucun signal comportemental anormal : +0")

    return {
        "model_version": MODEL_VERSION,
        "computed_at": now.isoformat(),
        "risk_score": total,
        "risk_level": level_for(total),
        "assessment": "potential",
        "disclaimer": DISCLAIMER,
        "factors": factors,
        "contributors": contributors,
        "breakdown": {c["criterion"]: c["points"] for c in contributors},
        "missing_data": missing_data(asset, context),
        "criticality": criticality,
        "confidence": score_confidence(asset, context, now),
        "compromise_indicators": (context or {}).get("compromise_indicators", []),
    }


def format_risk_summary(asset_name: str, risk_result: dict) -> str:
    """Formatte un résumé lisible, façon rapport."""
    lines = [f"Risque : {risk_result['risk_score']}/100 — {risk_result['risk_level']}"]
    lines.extend(risk_result["factors"])
    return f"[{asset_name}] " + " | ".join(lines)
