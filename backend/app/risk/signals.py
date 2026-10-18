"""
Faits par actif lus en base une fois par calcul de risque : signaux comportementaux, visibilité, vulnérabilités,
indices de compromission.

Chaque signal porte les clés des événements qui le fondent (`alert:12`, `deviation:3`…). Une alerte déjà comptée
dans un écart (preuve de corrélation de l'écart) n'est pas recomptée comme signal séparé : un même événement ne
pèse qu'une fois. L'indisponibilité n'est pas un signal de risque : elle diminue la confiance du score.
"""
from datetime import datetime, timedelta, UTC

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.asset import Asset
from app.models.attack_path_step import AttackPathStep
from app.models.behavior import Communication, Deviation

ALERT_WINDOW = timedelta(hours=24)


def _signal(points: int, label: str, evidence: set[str], kind: str) -> dict:
    return {"points": points, "label": label, "evidence": sorted(evidence), "kind": kind}


def _vulnerability_context(db: Session) -> dict[int, list[dict]]:
    """Correspondances de vulnérabilités par actif (lot E) ; vide si le module ou la table n'est pas disponible."""
    try:
        from app.vulnerabilities.service import findings_by_asset
    except ImportError:
        return {}
    return findings_by_asset(db)


def collect_signals(db: Session, now: datetime | None = None) -> dict[int, dict]:
    now = now or datetime.now(UTC)
    assets = db.query(Asset).all()
    by_ip = {a.ip_address: a.id for a in assets}
    result = {a.id: {"signals": [], "flow_visibility": False, "vulnerabilities": [], "compromise_indicators": []} for a in assets}

    for a in assets:
        if a.authorization == "unauthorized":
            result[a.id]["signals"].append(_signal(60, "Actif non autorisé dans l'inventaire", {f"asset:{a.id}:unauthorized"}, "authorization"))

    # Écarts ouverts : le plus sévère par actif, avec les alertes qui les corroborent
    covered_alerts: dict[int, set[int]] = {}
    per_asset: dict[int, dict[str, list[Deviation]]] = {}
    for d in db.query(Deviation).filter(Deviation.status == "open").order_by(Deviation.id).all():
        for asset_id in {d.src_asset_id, d.dst_asset_id} - {None}:
            per_asset.setdefault(asset_id, {}).setdefault(d.severity, []).append(d)
    for asset_id, groups in per_asset.items():
        if asset_id not in result:
            continue
        severity = "warning" if groups.get("warning") else ("notice" if groups.get("notice") else None)
        if not severity:
            continue
        devs = groups[severity]
        alert_ids = {i for d in devs for i in ((d.evidence or {}).get("alert_ids") or [])}
        covered_alerts.setdefault(asset_id, set()).update(alert_ids)
        points = 80 if severity == "warning" else 40
        label = f"{len(devs)} écart(s) comportemental(aux) {'à vérifier' if severity == 'warning' else 'à noter'}"
        if alert_ids:
            label += f", corroboré(s) par {len(alert_ids)} alerte(s) IDS"
        result[asset_id]["signals"].append(_signal(points, label, {f"deviation:{d.id}" for d in devs} | {f"alert:{i}" for i in alert_ids}, "deviation"))

    since = now - ALERT_WINDOW
    as_source: dict[int, set[int]] = {}
    as_target: dict[int, set[int]] = {}
    for alert in db.query(Alert).filter(Alert.priority <= 2, Alert.last_seen >= since).all():
        if alert.source_ip in by_ip:
            as_source.setdefault(by_ip[alert.source_ip], set()).add(alert.id)
        if alert.destination_ip in by_ip:
            as_target.setdefault(by_ip[alert.destination_ip], set()).add(alert.id)
    for asset_id, ids in as_source.items():
        ids = ids - covered_alerts.get(asset_id, set())
        if ids:
            result[asset_id]["signals"].append(_signal(60, f"Émet {len(ids)} alerte(s) IDS sévère(s) en 24 h", {f"alert:{i}" for i in ids}, "ids_source"))
    for asset_id, ids in as_target.items():
        ids = ids - covered_alerts.get(asset_id, set()) - as_source.get(asset_id, set())
        if ids:
            result[asset_id]["signals"].append(_signal(30, f"Cible de {len(ids)} alerte(s) IDS sévère(s) en 24 h", {f"alert:{i}" for i in ids}, "ids_target"))

    for src_id, dst_id in db.query(Communication.src_asset_id, Communication.dst_asset_id).filter(
        or_(Communication.src_asset_id.isnot(None), Communication.dst_asset_id.isnot(None))
    ).all():
        for asset_id in (src_id, dst_id):
            if asset_id in result:
                result[asset_id]["flow_visibility"] = True

    # Étapes d'incident confirmées par une alerte IDS : indice de compromission, jamais une preuve
    for step in db.query(AttackPathStep).filter(AttackPathStep.status == "confirmed").all():
        if step.destination_asset_id in result:
            result[step.destination_asset_id]["compromise_indicators"].append({
                "incident_id": step.incident_id, "step": step.sequence, "evidence_type": step.evidence_type,
                "technique_id": step.technique_id,
                "label": f"Étape {step.sequence} de l'incident #{step.incident_id} confirmée par {step.evidence_type or 'une détection'} (non vérifiée par un analyste)",
            })

    for asset_id, findings in _vulnerability_context(db).items():
        if asset_id in result:
            result[asset_id]["vulnerabilities"] = findings
    configured = _vulnerability_source_configured()
    for entry in result.values():
        entry["vulnerability_source"] = configured
    return result


def _vulnerability_source_configured() -> bool:
    try:
        from app.vulnerabilities.sources import configured_sources
    except ImportError:
        return False
    return any(s.available() for s in configured_sources())
