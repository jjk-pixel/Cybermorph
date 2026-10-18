import nmap
from datetime import datetime, UTC
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.asset import Asset
from app.collectors.network_utils import get_default_gateway, get_local_subnet
import subprocess
from app.inventory.classification import MODEL_VERSION, classify_asset, parse_list, parse_ports
from app.inventory.observations import record_observation

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


def scan_network(subnet: str = None):
    subnet = subnet or get_local_subnet()
    scanner = nmap.PortScanner()
    print(f"[CYBERMORPH][Nmap] Scan en cours sur {subnet} ...")
    scanner.scan(hosts=subnet, arguments="-sn")

    hosts_found = scanner.all_hosts()
    print(f"[CYBERMORPH][Nmap] {len(hosts_found)} hôte(s) découvert(s). Scan détaillé en cours...")

    gateway_ip = get_default_gateway()
    db: Session = SessionLocal()
    try:
        seen_ips = set()

        for ip in hosts_found:
            seen_ips.add(ip)
            detailed = nmap.PortScanner()
            try:
                detailed.scan(hosts=ip, arguments="-sV -O --host-timeout 30s")
            except Exception as e:
                print(f"[CYBERMORPH][Nmap] Erreur scan détaillé {ip}: {e}")
                continue

            if ip not in detailed.all_hosts():
                continue

            host_data = detailed[ip]
            mac = host_data["addresses"].get("mac")
            vendor = None
            if mac and host_data.get("vendor"):
                vendor = host_data["vendor"].get(mac)

            open_ports, services = [], []
            if "tcp" in host_data:
                for port, port_info in host_data["tcp"].items():
                    if port_info["state"] == "open":
                        open_ports.append(port)
                        services.append(port_info.get("name", "unknown"))

            os_detected = None
            if host_data.get("osmatch"):
                os_detected = host_data["osmatch"][0]["name"]

            classification = classify_asset(
                open_ports, services, vendor, os_detected,
                os_classes=os_classes_from_host(host_data), is_gateway=ip == gateway_ip,
                service_details=service_details_from_host(host_data),
            )
            asset_type = classification["type"]

            # Résolution hostname : mDNS d'abord, puis fallback VMware. La source est mémorisée :
            # un nom annoncé (mDNS) ou résolu (DNS) n'a pas la même valeur qu'un nom déduit.
            resolved_hostname = resolve_hostname_mdns(ip)
            hostname_source = "mdns" if resolved_hostname else None

            if not resolved_hostname:
                nmap_hostname = host_data.get("hostnames", [{}])[0].get("name") or ""
                if nmap_hostname and nmap_hostname != ip:
                    resolved_hostname = nmap_hostname
                    hostname_source = "dns"

            if not resolved_hostname:
                hostname_source = "heuristic"
                if vendor and "vmware" in vendor.lower():
                    if 53 in open_ports:
                        resolved_hostname = "vmware-nat"
                    elif not open_ports:
                        resolved_hostname = "vmware-reserved"
                    else:
                        resolved_hostname = f"vmware-{asset_type}"

            if not resolved_hostname:
                resolved_hostname = ip

            existing = db.query(Asset).filter(Asset.ip_address == ip).first()
            if existing:
                existing.mac_address = mac
                existing.vendor = vendor
                existing.os_detected = os_detected
                existing.open_ports = ",".join(map(str, open_ports))
                existing.services = ",".join(services)
                existing.status = "up"
                # Un type déclaré par l'opérateur n'est jamais écrasé ; la classification reste publiée comme avis
                if existing.asset_type_source != "declared":
                    existing.asset_type = asset_type
                existing.classification = classification
                existing.last_seen = datetime.now(UTC)
                existing.hostname = resolved_hostname
                existing.name = resolved_hostname
            else:
                new_asset = Asset(
                    name=resolved_hostname,
                    hostname=resolved_hostname,
                    ip_address=ip,
                    mac_address=mac,
                    vendor=vendor,
                    asset_type=asset_type,
                    classification=classification,
                    os_detected=os_detected,
                    open_ports=",".join(map(str, open_ports)),
                    services=",".join(services),
                    status="up",
                )
                db.add(new_asset)
                db.flush()
                existing = new_asset

            # Journal d'observations : chaque fait vu par Nmap, attribut par attribut
            record_observation(db, ip, "nmap", "mac", mac, existing.id)
            record_observation(db, ip, "nmap", "vendor", vendor, existing.id)
            record_observation(db, ip, "nmap", "os", os_detected, existing.id)
            if resolved_hostname != ip:
                record_observation(db, ip, hostname_source, "hostname", resolved_hostname, existing.id)
            for port in open_ports:
                record_observation(db, ip, "nmap", "open_port", port, existing.id)
            for service in services:
                record_observation(db, ip, "nmap", "service", service, existing.id)

            db.commit()
            print(f"[CYBERMORPH][Nmap] {ip} → {asset_type} ({vendor or 'vendor inconnu'})")

        all_assets = db.query(Asset).all()
        for a in all_assets:
            if a.ip_address not in seen_ips:
                reclassify_stored(a, gateway_ip)
                if a.status != "down":
                    a.status = "down"
                    print(f"[CYBERMORPH][Nmap] {a.ip_address} non vu → marqué down")
        db.commit()

    finally:
        db.close()

    print("[CYBERMORPH][Nmap] Scan terminé.")


if __name__ == "__main__":
    scan_network()
