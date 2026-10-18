"""
Signaux comportementaux et visibilité par actif, lus en base une fois par calcul de risque.

Ils alimentent le critère « signaux comportementaux » (15 % du score) avec des faits : écarts à la référence,
alertes IDS récentes, statut d'autorisation, disponibilité. La visibilité (l'actif apparaît-il dans les flux
observés ?) sert à la confiance du score, pas au score lui-même.
"""
from datetime import datetime, timedelta, UTC

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.asset import Asset
from app.models.behavior import Communication, Deviation

ALERT_WINDOW = timedelta(hours=24)


def collect_signals(db: Session, now: datetime | None = None) -> dict[int, dict]:
    now = now or datetime.now(UTC)
    assets = db.query(Asset).all()
    by_ip = {a.ip_address: a.id for a in assets}
    result = {a.id: {"signals": [], "flow_visibility": False} for a in assets}

    for a in assets:
        if a.status == "down":
            result[a.id]["signals"].append((50, "Asset actuellement down : +50"))
        if a.authorization == "unauthorized":
            result[a.id]["signals"].append((60, "Actif non autorisé dans l'inventaire : +60"))

    open_deviations = db.query(Deviation).filter(Deviation.status == "open").all()
    per_asset: dict[int, dict[str, int]] = {}
    for d in open_deviations:
        for asset_id in {d.src_asset_id, d.dst_asset_id} - {None}:
            per_asset.setdefault(asset_id, {}).setdefault(d.severity, 0)
            per_asset[asset_id][d.severity] += 1
    for asset_id, counts in per_asset.items():
        if asset_id not in result:
            continue
        if counts.get("warning"):
            result[asset_id]["signals"].append((80, f"{counts['warning']} écart(s) comportemental(aux) à vérifier : +80"))
        elif counts.get("notice"):
            result[asset_id]["signals"].append((40, f"{counts['notice']} écart(s) comportemental(aux) à noter : +40"))

    since = now - ALERT_WINDOW
    as_source: dict[int, int] = {}
    as_target: dict[int, int] = {}
    for alert in db.query(Alert).filter(Alert.priority <= 2, Alert.last_seen >= since).all():
        if alert.source_ip in by_ip:
            as_source[by_ip[alert.source_ip]] = as_source.get(by_ip[alert.source_ip], 0) + 1
        if alert.destination_ip in by_ip:
            as_target[by_ip[alert.destination_ip]] = as_target.get(by_ip[alert.destination_ip], 0) + 1
    for asset_id, n in as_source.items():
        result[asset_id]["signals"].append((60, f"Émet {n} alerte(s) IDS sévère(s) en 24 h : +60"))
    for asset_id, n in as_target.items():
        result[asset_id]["signals"].append((30, f"Cible de {n} alerte(s) IDS sévère(s) en 24 h : +30"))

    for src_id, dst_id in db.query(Communication.src_asset_id, Communication.dst_asset_id).filter(
        or_(Communication.src_asset_id.isnot(None), Communication.dst_asset_id.isnot(None))
    ).all():
        for asset_id in (src_id, dst_id):
            if asset_id in result:
                result[asset_id]["flow_visibility"] = True
    return result
