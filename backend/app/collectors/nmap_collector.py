"""
Découverte active Nmap, dans la portée autorisée (app.collectors.scope), en deux temps : balayage de présence
(-sn), puis identification des hôtes répondants (-sV -O, sans script ni option intrusive).

Présence : un actif qui répond est « up ». Un actif de la portée qui ne répond pas à un balayage complet n'est d'abord
que « non observé » (status unknown) ; il ne passe « down » (hors ligne) qu'après OFFLINE_AFTER_MISSES balayages
complets consécutifs sans réponse. Un balayage en échec ou interrompu ne modifie aucune présence.

Identité : si une MAC déjà connue répond sur une nouvelle IP alors que son ancienne IP ne répond plus, l'actif est
conservé et suit sa nouvelle adresse (changement « ip_changed ») au lieu de créer un doublon.
"""
import nmap
import logging
from datetime import datetime, UTC
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.asset import Asset
from app.models.observation import AssetObservation
from app.collectors.network_utils import get_default_gateway, get_local_subnet
from app.collectors.runs import Interrupted, check_stop
from app.collectors.scope import in_scope, scan_configuration
import subprocess
from app.inventory.classification import MODEL_VERSION, classify_asset, parse_list, parse_ports
from app.inventory.observations import record_change, record_observation

OFFLINE_AFTER_MISSES = 2
IDENTITY_SOURCES = ("nmap", "arp", "dhcp")
logger = logging.getLogger("cybermorph.nmap")


def resolve_hostname_mdns(ip: str) -> str:
    """Tente de résoudre le hostname via mDNS (avahi), indépendamment de Nmap."""
    try:
        result = subprocess.run(
            ["avahi-resolve-address", ip],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                hostname = parts[1]
                if hostname.endswith(".local"):
                    hostname = hostname[:-6]
                return hostname
    except Exception:
        pass
    return ""

def guess_asset_type(open_ports: list, vendor: str, services: list = None) -> str:
    """Compatibilité : type seul. La classification complète (raisons, confiance) est dans classify_asset."""
    return classify_asset(open_ports, services or [], vendor, None)["type"]


def service_details_from_host(host_data: dict) -> list[dict]:
    """Services TCP ouverts tels que rapportés par Nmap -sV : nom, produit, version, CPE (vides si non identifiés)."""
    details = []
    for port, info in sorted(host_data.get("tcp", {}).items()):
        if info.get("state") != "open":
            continue
        details.append({
            "port": int(port), "proto": "tcp", "name": info.get("name") or None,
            "product": info.get("product") or None, "version": info.get("version") or None,
            "extrainfo": info.get("extrainfo") or None, "cpe": info.get("cpe") or None,
            # Fiabilité de l'identification annoncée par Nmap (0-10) : 3 = déduit du seul numéro de port
            "conf": int(info["conf"]) if str(info.get("conf", "")).isdigit() else None,
        })
    return details


def os_classes_from_host(host_data: dict) -> list[dict]:
    if not host_data.get("osmatch"):
        return []
    best = host_data["osmatch"][0]
    return [
        {"type": c.get("type"), "vendor": c.get("vendor"), "osfamily": c.get("osfamily"),
         "osgen": c.get("osgen"), "accuracy": c.get("accuracy") or best.get("accuracy")}
        for c in best.get("osclass", [])
    ]


def reclassify_stored(asset: Asset, gateway_ip: str | None) -> None:
    """Reclasse un actif non vu à ce cycle à partir des faits déjà enregistrés (passage au modèle courant)."""
    if (asset.classification or {}).get("model") == MODEL_VERSION or asset.is_scanner:
        return
    classification = classify_asset(
        parse_ports(asset.open_ports), parse_list(asset.services), asset.vendor, asset.os_detected,
        is_gateway=asset.ip_address == gateway_ip,
    )
    asset.classification = classification
    if asset.asset_type_source != "declared":
        asset.asset_type = classification["type"]


def _hostname(ip: str, host_data: dict, vendor: str | None, open_ports: list[int], asset_type: str) -> tuple[str, str | None]:
    """Nom et provenance : mDNS (annoncé), puis DNS inverse (résolu), puis heuristique VMware (déduit)."""
    resolved = resolve_hostname_mdns(ip)
    if resolved:
        return resolved, "mdns"
    nmap_hostname = (host_data.get("hostnames") or [{}])[0].get("name") or ""
    if nmap_hostname and nmap_hostname != ip:
        return nmap_hostname, "dns"
    if vendor and "vmware" in vendor.lower():
        if 53 in open_ports:
            return "vmware-nat", "heuristic"
        if not open_ports:
            return "vmware-reserved", "heuristic"
        return f"vmware-{asset_type}", "heuristic"
    return ip, None


def _moved_asset(db: Session, ip: str, mac: str | None, responded: set[str]) -> Asset | None:
    """Actif connu par cette MAC sur une autre IP qui, elle, ne répond plus : même équipement, nouvelle adresse."""
    if not mac:
        return None
    rows = (
        db.query(AssetObservation)
        .filter(AssetObservation.attribute == "mac", AssetObservation.value == mac.upper(),
                AssetObservation.retired_at.is_(None), AssetObservation.source.in_(IDENTITY_SOURCES),
                AssetObservation.asset_id.isnot(None))
        .all()
    )
    candidates = {o.asset_id for o in rows}
    assets = [a for a in db.query(Asset).filter(Asset.id.in_(candidates)).all()
              if a.ip_address != ip and a.ip_address not in responded and not a.is_scanner] if candidates else []
    # Plusieurs candidats : ambigu, on ne fusionne rien (le conflit de MAC sera signalé par le rapprochement)
    return assets[0] if len(assets) == 1 else None


def _follow_ip_change(db: Session, asset: Asset, new_ip: str, mac: str, now: datetime) -> dict:
    old_ip = asset.ip_address
    # Les ports et services observés sur l'ancienne IP ne décrivent plus l'actif : retirés sans être « fermés »
    for o in db.query(AssetObservation).filter(AssetObservation.asset_id == asset.id, AssetObservation.ip == old_ip,
                                               AssetObservation.attribute.in_(("open_port", "service", "port_service", "cpe")),
                                               AssetObservation.retired_at.is_(None)).all():
        o.retired_at = now
    asset.ip_address = new_ip
    record_change(
        db, asset, "ip_changed", "notice",
        f"L'équipement {mac} répond désormais sur {new_ip} (auparavant {old_ip}, qui ne répond plus) : même actif, "
        "nouvelle adresse (réattribution DHCP probable). À vérifier si l'équipement n'est pas censé changer d'adresse.",
        now, attribute="ip", old=old_ip, new=new_ip, source="nmap", evidence={"mac": mac},
    )
    return {"asset_id": asset.id, "old_ip": old_ip, "new_ip": new_ip, "mac": mac}


def _upsert_host(db: Session, ip: str, host_data: dict, gateway_ip: str | None, responded: set[str], now: datetime) -> tuple[Asset, dict | None]:
    mac = host_data["addresses"].get("mac")
    vendor = host_data.get("vendor", {}).get(mac) if mac else None
    details = service_details_from_host(host_data)
    open_ports = [d["port"] for d in details]
    services = [d["name"] or "unknown" for d in details]
    os_detected = host_data["osmatch"][0]["name"] if host_data.get("osmatch") else None

    classification = classify_asset(
        open_ports, services, vendor, os_detected,
        os_classes=os_classes_from_host(host_data), is_gateway=ip == gateway_ip, service_details=details,
    )
    hostname, hostname_source = _hostname(ip, host_data, vendor, open_ports, classification["type"])

    moved = None
    asset = db.query(Asset).filter(Asset.ip_address == ip).first()
    if asset is None:
        asset = _moved_asset(db, ip, mac, responded)
        if asset is not None:
            moved = _follow_ip_change(db, asset, ip, mac, now)
    if asset is None:
        asset = Asset(ip_address=ip, name=hostname, asset_type=classification["type"], status="up", created_at=now)
        db.add(asset)

    asset.mac_address = mac
    asset.vendor = vendor
    asset.os_detected = os_detected
    asset.open_ports = ",".join(map(str, open_ports))
    asset.services = ",".join(services)
    asset.status = "up"
    asset.missed_scans = 0
    # Un type déclaré par l'opérateur n'est jamais écrasé ; la classification reste publiée comme avis
    if asset.asset_type_source != "declared":
        asset.asset_type = classification["type"]
    asset.classification = classification
    asset.last_seen = now
    asset.hostname = hostname
    asset.name = hostname
    db.flush()

    # Journal d'observations : chaque fait vu par Nmap, attribut par attribut
    record_observation(db, ip, "nmap", "mac", mac, asset.id, now)
    record_observation(db, ip, "nmap", "vendor", vendor, asset.id, now)
    record_observation(db, ip, "nmap", "os", os_detected, asset.id, now)
    if hostname_source:
        record_observation(db, ip, hostname_source, "hostname", hostname, asset.id, now)
    for d in details:
        record_observation(db, ip, "nmap", "open_port", d["port"], asset.id, now)
        if d["name"]:
            record_observation(db, ip, "nmap", "service", d["name"], asset.id, now)
        record_observation(db, ip, "nmap", "port_service", port_service_value(d), asset.id, now)
        if d.get("cpe"):
            record_observation(db, ip, "nmap", "cpe", f"{d['port']}/{d['proto']} {d['cpe']}", asset.id, now)
    return asset, moved


def port_service_value(d: dict) -> str:
    """« 22/tcp ssh OpenSSH 9.6p1 » : port, service et, si Nmap l'a identifié, produit et version."""
    parts = [f"{d['port']}/{d.get('proto', 'tcp')}", d.get("name") or "unknown"]
    if d.get("product"):
        parts.append(d["product"])
    if d.get("version"):
        parts.append(d["version"])
    return " ".join(parts)


def update_presence(db: Session, responded: set[str], targets: list, gateway_ip: str | None) -> dict:
    """Après un balayage COMPLET : non observé d'abord, hors ligne après OFFLINE_AFTER_MISSES balayages manqués."""
    unobserved, offline = [], []
    for a in db.query(Asset).all():
        if a.ip_address in responded:
            continue
        reclassify_stored(a, gateway_ip)
        if a.is_scanner or not in_scope(a.ip_address, targets):
            continue  # l'hôte capteur est suivi localement ; une IP hors portée n'a pas été sondée
        a.missed_scans = (a.missed_scans or 0) + 1
        if a.missed_scans >= OFFLINE_AFTER_MISSES:
            if a.status != "down":
                offline.append(a.ip_address)
            a.status = "down"
        elif a.status != "down":
            a.status = "unknown"
            unobserved.append(a.ip_address)
    return {"unobserved": unobserved, "marked_offline": offline}


def scan_network(subnet: str = None, scanner_factory=nmap.PortScanner, session_factory=SessionLocal,
                 gateway_ip: str | None = None, now: datetime | None = None) -> dict:
    """Un passage de découverte. Retourne les statistiques de l'exécution (journal collector_runs)."""
    config = scan_configuration(subnet or get_local_subnet())
    targets = config["targets"]
    gateway_ip = gateway_ip if gateway_ip is not None else get_default_gateway()
    now = now or datetime.now(UTC)

    responded: set[str] = set()
    for net in targets:
        check_stop()
        scanner = scanner_factory()
        logger.info("nmap_discovery", extra={"target": str(net), "nmap_args": config["discovery_args"]})
        # Une erreur ou un dépassement de délai ici fait échouer l'étape : aucune présence n'est modifiée
        scanner.scan(hosts=str(net), arguments=config["discovery_args"], timeout=config["discovery_timeout"])
        responded |= {ip for ip in scanner.all_hosts() if in_scope(ip, targets)}

    stats = {"targets": [str(n) for n in targets], "discovery_args": config["discovery_args"],
             "detail_args": config["detail_args"], "hosts_up": len(responded), "identified": 0,
             "failures": [], "ip_changes": []}
    db: Session = session_factory()
    try:
        for ip in sorted(responded, key=lambda v: tuple(int(x) for x in v.split(".")) if v.count(".") == 3 else (999,)):
            try:
                check_stop()
            except Interrupted:
                db.commit()
                stats["status"] = "interrupted"
                stats["interrupted_before"] = ip
                return stats
            detailed = scanner_factory()
            try:
                detailed.scan(hosts=ip, arguments=config["detail_args"], timeout=config["detail_timeout"])
            except Exception as e:  # noqa: BLE001 — un hôte en échec n'arrête pas les autres
                stats["failures"].append({"ip": ip, "error": str(e)[:200]})
                continue
            if ip not in detailed.all_hosts():
                # A répondu au balayage mais pas à l'identification : présent, non identifié à ce cycle
                stats["failures"].append({"ip": ip, "error": "aucun résultat d'identification"})
                asset = db.query(Asset).filter(Asset.ip_address == ip).first()
                if asset:
                    asset.status, asset.missed_scans, asset.last_seen = "up", 0, now
                continue
            asset, moved = _upsert_host(db, ip, detailed[ip], gateway_ip, responded, now)
            if moved:
                stats["ip_changes"].append(moved)
            stats["identified"] += 1
            db.commit()
            print(f"[CYBERMORPH][Nmap] {ip} → {asset.asset_type} ({asset.vendor or 'vendor inconnu'})")

        stats.update(update_presence(db, responded, targets, gateway_ip))
        db.commit()
    finally:
        db.close()

    stats["status"] = "partial" if stats["failures"] else "success"
    print(f"[CYBERMORPH][Nmap] Scan terminé : {stats['hosts_up']} hôte(s) répondant(s), {stats['identified']} identifié(s).")
    return stats


if __name__ == "__main__":
    scan_network()
