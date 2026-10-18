"""
Journal d'observations, rapprochement des identités et détection des changements d'inventaire.

- Les collecteurs enregistrent ce qu'ils voient (`record_observation`), attribut par attribut, avec leur source.
- En fin de cycle, `reconcile_cycle` compare l'état observé pendant le cycle à l'état connu avant, et produit des
  changements explicables. Comparer une fois par cycle (et non par collecteur) évite les faux changements : sur
  l'hôte local, Nmap puis `ss` réécrivent les ports à quelques secondes d'intervalle.
- Un port n'est déclaré fermé qu'après un délai de grâce (≈ 2 cycles) pendant lequel la même source a observé
  l'actif sans le voir : un scan incomplet ne suffit pas à « fermer » un service.
- Rapprochement conservateur : l'IP reste la clé d'un actif. Une MAC différente sur la même IP, ou une même MAC sur
  plusieurs IP, est signalée comme conflit d'identité ; rien n'est fusionné automatiquement.
"""
import os
from datetime import datetime, timedelta, UTC

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.observation import AssetChange, AssetObservation, Setting
from app.risk.risk_engine import DANGEROUS_PORTS

PORT_CLOSE_GRACE = timedelta(minutes=12)
MAC_SHARED_WINDOW = timedelta(hours=24)
LEARNING_HOURS = float(os.getenv("CYBERMORPH_LEARNING_HOURS", "48"))

SINGLE_VALUED = ("mac", "vendor", "os", "hostname")

SOURCE_LABEL = {
    "nmap": "Nmap",
    "mdns": "mDNS (avahi)",
    "dns": "DNS inverse (Nmap)",
    "heuristic": "heuristique CYBERMORPH",
    "local": "hôte local (ss, hostname)",
    "arp": "table ARP",
    "dhcp": "DHCP (Suricata)",
    "suricata": "Suricata",
    "manual": "opérateur",
}
# Fiabilité d'une source pour le nom d'un actif : un nom annoncé par l'équipement vaut mieux qu'un nom déduit
NAME_SOURCE_RANK = {"manual": 6, "dhcp": 5, "mdns": 4, "local": 4, "dns": 3, "heuristic": 1}

ATTRIBUTE_LABEL = {"mac": "adresse MAC", "vendor": "constructeur", "os": "OS estimé", "hostname": "nom d'hôte"}


def utcnow() -> datetime:
    return datetime.now(UTC)


def as_utc(value: datetime | None) -> datetime | None:
    """SQLite rend des dates naïves : elles sont stockées en UTC."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def normalize(attribute: str, value) -> str:
    text = str(value).strip()
    return text.upper() if attribute == "mac" else text


# --------------------------------------------------------------------------- réglages durables

def get_setting(db: Session, key: str, default=None):
    row = db.get(Setting, key)
    return row.value if row else default


def set_setting(db: Session, key: str, value):
    row = db.get(Setting, key)
    if row:
        row.value = value
    else:
        db.add(Setting(key=key, value=value))


def learning_window(db: Session, now: datetime | None = None) -> dict:
    """
    Période d'apprentissage (inventaire et comportement), démarrée la première fois qu'elle est demandée.
    Pendant cette période, ce qui apparaît est considéré comme normal ; ensuite, comme un écart à valider.
    """
    now = now or utcnow()
    state = get_setting(db, "learning")
    if not state:
        state = {"started_at": now.isoformat(), "hours": LEARNING_HOURS}
        set_setting(db, "learning", state)
        db.flush()
    started = datetime.fromisoformat(state["started_at"])
    ends = started + timedelta(hours=float(state["hours"]))
    return {
        "started_at": started,
        "ends_at": ends,
        "hours": float(state["hours"]),
        "in_learning": now < ends,
    }


# --------------------------------------------------------------------------- observations

def record_observation(
    db: Session, ip: str, source: str, attribute: str, value, asset_id: int | None = None, seen_at: datetime | None = None,
) -> AssetObservation | None:
    if value is None or str(value).strip() == "":
        return None
    value = normalize(attribute, value)
    now = seen_at or utcnow()
    obs = (
        db.query(AssetObservation)
        .filter(
            AssetObservation.ip == ip,
            AssetObservation.source == source,
            AssetObservation.attribute == attribute,
            AssetObservation.value == value,
        )
        .first()
    )
    if obs:
        if as_utc(obs.last_seen) < now:
            obs.last_seen = now
        obs.seen_count = (obs.seen_count or 0) + 1
        if asset_id is not None:
            obs.asset_id = asset_id
    else:
        obs = AssetObservation(
            asset_id=asset_id, ip=ip, source=source, attribute=attribute, value=value,
            first_seen=now, last_seen=now, seen_count=1,
        )
        db.add(obs)
    db.flush()
    return obs


# --------------------------------------------------------------------------- changements

def _change(db, changes, asset, change_type, severity, explanation, now, attribute=None, old=None, new=None, source=None, evidence=None):
    change = AssetChange(
        asset_id=asset.id if asset else None, ip=asset.ip_address if asset else None,
        change_type=change_type, attribute=attribute, old_value=old, new_value=new, source=source,
        severity=severity, explanation=explanation, evidence=evidence, detected_at=now,
    )
    db.add(change)
    changes.append(change)
    return change


def _port_severity(port: str) -> str:
    return "warning" if port.isdigit() and int(port) in DANGEROUS_PORTS else "notice"


def reconcile_cycle(
    db: Session, cycle_started_at: datetime, status_before: dict[int, str] | None = None, now: datetime | None = None,
) -> list[AssetChange]:
    """Compare ce qui a été observé pendant le cycle à l'état antérieur ; enregistre et retourne les changements."""
    now = now or utcnow()
    cycle_start = as_utc(cycle_started_at)
    status_before = status_before or {}
    learning = learning_window(db, now)
    changes: list[AssetChange] = []

    observations: dict[int, list[AssetObservation]] = {}
    for o in db.query(AssetObservation).filter(AssetObservation.asset_id.isnot(None)).all():
        observations.setdefault(o.asset_id, []).append(o)

    for asset in db.query(Asset).all():
        obs = observations.get(asset.id, [])
        created = as_utc(asset.created_at)
        known_before = any(as_utc(o.first_seen) < cycle_start for o in obs)

        if created is not None and created >= cycle_start:
            if asset.authorization is None:
                asset.authorization = "authorized" if learning["in_learning"] else "unauthorized"
                asset.authorization_source = "learning"
            after_learning = not learning["in_learning"]
            _change(
                db, changes, asset, "new_asset", "warning" if after_learning else "notice",
                (
                    f"Nouvel actif {asset.ip_address} découvert après la période d'apprentissage : "
                    "non autorisé tant qu'un opérateur ne l'a pas validé."
                    if after_learning else
                    f"Nouvel actif {asset.ip_address} découvert pendant la période d'apprentissage."
                ),
                now, new=asset.ip_address, source="nmap",
            )
            continue

        if not known_before:
            # Premier passage de l'inventaire sur un actif déjà connu : on enregistre, sans signaler de « changement »
            if asset.authorization is None:
                asset.authorization = "authorized"
                asset.authorization_source = "learning"
            continue

        seen_sources = {o.source for o in obs if as_utc(o.last_seen) >= cycle_start}

        # Ports : ouverture immédiate, fermeture après délai de grâce
        for o in (o for o in obs if o.attribute == "open_port"):
            first, last = as_utc(o.first_seen), as_utc(o.last_seen)
            label = SOURCE_LABEL.get(o.source, o.source)
            if first >= cycle_start:
                _change(db, changes, asset, "port_opened", _port_severity(o.value),
                        f"Port {o.value} ouvert sur {asset.ip_address}, jamais observé auparavant ({label}).",
                        now, attribute="open_port", new=o.value, source=o.source, evidence={"observation_id": o.id})
            elif o.retired_at is not None and last >= cycle_start:
                o.retired_at = None
                _change(db, changes, asset, "port_opened", _port_severity(o.value),
                        f"Port {o.value} de nouveau ouvert sur {asset.ip_address} ({label}).",
                        now, attribute="open_port", new=o.value, source=o.source, evidence={"observation_id": o.id})
            elif o.retired_at is None and o.source in seen_sources and last < now - PORT_CLOSE_GRACE:
                o.retired_at = now
                minutes = int((now - last).total_seconds() // 60)
                _change(db, changes, asset, "port_closed", "info",
                        f"Port {o.value} plus observé sur {asset.ip_address} depuis {minutes} min, alors que {label} a bien sondé l'actif.",
                        now, attribute="open_port", old=o.value, source=o.source, evidence={"observation_id": o.id})

        # Attributs à valeur unique : comparaison par source (une source qui change d'avis)
        for attribute in SINGLE_VALUED:
            by_source: dict[str, list[AssetObservation]] = {}
            for o in obs:
                if o.attribute == attribute:
                    by_source.setdefault(o.source, []).append(o)
            for source, group in by_source.items():
                fresh = [o for o in group if as_utc(o.first_seen) >= cycle_start]
                previous = sorted(
                    (o for o in group if as_utc(o.first_seen) < cycle_start and o.retired_at is None),
                    key=lambda o: as_utc(o.last_seen), reverse=True,
                )
                for new in fresh:
                    if not previous:
                        continue
                    old = previous[0]
                    old.retired_at = now
                    severity = {"mac": "warning", "vendor": "notice", "hostname": "notice"}.get(attribute, "info")
                    if attribute == "hostname" and source == "heuristic":
                        severity = "info"
                    explanation = (
                        f"{ATTRIBUTE_LABEL[attribute].capitalize()} de {asset.ip_address} : « {old.value} » → « {new.value} » "
                        f"({SOURCE_LABEL.get(source, source)})."
                    )
                    if attribute == "mac":
                        explanation += (" Même IP, autre carte réseau : remplacement d'équipement, réattribution DHCP "
                                        "ou usurpation ARP. À vérifier.")
                        change_type = "identity_conflict"
                    else:
                        change_type = f"{attribute}_changed"
                    _change(db, changes, asset, change_type, severity, explanation, now, attribute=attribute,
                            old=old.value, new=new.value, source=source,
                            evidence={"observation_ids": [old.id, new.id]})

        before = status_before.get(asset.id)
        if before and before != asset.status and asset.status in ("up", "down"):
            if asset.status == "down":
                _change(db, changes, asset, "went_offline", "notice",
                        f"{asset.ip_address} ne répond plus au scan Nmap.", now, attribute="status", old=before, new="down", source="nmap")
            else:
                _change(db, changes, asset, "back_online", "info",
                        f"{asset.ip_address} répond de nouveau au scan Nmap.", now, attribute="status", old=before, new="up", source="nmap")

    changes.extend(_detect_shared_macs(db, now))
    db.flush()
    return changes


def _detect_shared_macs(db: Session, now: datetime) -> list[AssetChange]:
    """Même MAC vue sur plusieurs IP récemment : signalé une fois par période, jamais fusionné."""
    since = now - MAC_SHARED_WINDOW
    by_mac: dict[str, set[int]] = {}
    for o in db.query(AssetObservation).filter(AssetObservation.attribute == "mac", AssetObservation.retired_at.is_(None)).all():
        if o.asset_id is not None and as_utc(o.last_seen) >= since:
            by_mac.setdefault(o.value, set()).add(o.asset_id)

    changes: list[AssetChange] = []
    for mac, asset_ids in by_mac.items():
        if len(asset_ids) < 2:
            continue
        already = (
            db.query(AssetChange)
            .filter(AssetChange.change_type == "mac_shared", AssetChange.new_value == mac, AssetChange.detected_at >= since)
            .first()
        )
        if already:
            continue
        assets = db.query(Asset).filter(Asset.id.in_(asset_ids)).all()
        ips = ", ".join(sorted(a.ip_address for a in assets))
        _change(db, changes, assets[0], "mac_shared", "notice",
                f"La MAC {mac} est observée sur plusieurs IP ({ips}) : équipement multi-adressé, réattribution DHCP "
                "ou usurpation. Les actifs ne sont pas fusionnés.",
                now, attribute="mac", new=mac, evidence={"asset_ids": sorted(asset_ids)})
    return changes


# --------------------------------------------------------------------------- identité

def identity_summary(asset: Asset, obs: list[AssetObservation], open_conflicts: int = 0) -> dict:
    """Identifiants connus d'un actif, sources qui les corroborent, nom retenu et confiance d'identité."""
    identifiers: dict[tuple[str, str], dict] = {}
    for o in obs:
        if o.attribute not in SINGLE_VALUED:
            continue
        entry = identifiers.setdefault((o.attribute, o.value), {
            "attribute": o.attribute, "value": o.value, "sources": [], "first_seen": as_utc(o.first_seen),
            "last_seen": as_utc(o.last_seen), "current": False,
        })
        entry["sources"].append(o.source)
        entry["first_seen"] = min(entry["first_seen"], as_utc(o.first_seen))
        entry["last_seen"] = max(entry["last_seen"], as_utc(o.last_seen))
        entry["current"] = entry["current"] or o.retired_at is None

    reasons = ["IP observée : clé d'identité de l'actif (+0,30)"]
    confidence = 0.3
    macs = [i for i in identifiers.values() if i["attribute"] == "mac" and i["current"]]
    if macs:
        confidence += 0.3
        reasons.append(f"MAC observée ({', '.join(SOURCE_LABEL.get(s, s) for s in macs[0]['sources'])}) (+0,30)")
        if len(set(macs[0]["sources"])) >= 2:
            confidence += 0.15
            reasons.append("MAC corroborée par deux sources indépendantes (+0,15)")
    elif any(o.source == "local" for o in obs):
        confidence += 0.3
        reasons.append("Hôte local : identité lue sur la machine elle-même (+0,30)")

    names = [i for i in identifiers.values() if i["attribute"] == "hostname" and i["current"]]
    best_name = max(
        names, key=lambda i: max(NAME_SOURCE_RANK.get(s, 2) for s in i["sources"]), default=None,
    )
    name_observed = bool(best_name) and max(NAME_SOURCE_RANK.get(s, 2) for s in best_name["sources"]) > 1
    if name_observed:
        confidence += 0.15
        reasons.append("Nom annoncé ou résolu, pas seulement déduit (+0,15)")
    if open_conflicts:
        confidence -= 0.3
        reasons.append(f"{open_conflicts} conflit(s) d'identité non acquitté(s) (−0,30)")

    return {
        "confidence": round(min(max(confidence, 0.1), 0.95), 2),
        "reasons": reasons,
        "name": (
            {"value": best_name["value"], "sources": best_name["sources"], "observed": name_observed}
            if best_name else None
        ),
        "identifiers": sorted(identifiers.values(), key=lambda i: (i["attribute"], not i["current"], i["value"])),
        "open_conflicts": open_conflicts,
    }
