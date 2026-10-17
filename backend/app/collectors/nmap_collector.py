import nmap
from datetime import datetime, UTC
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.asset import Asset
from app.collectors.network_utils import get_local_subnet
import subprocess

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
    services = services or []
    vendor_lower = (vendor or "").lower()

    if any(v in vendor_lower for v in ["cisco", "mikrotik", "ubiquiti", "tp-link", "netgear"]):
        return "router"
    if "domain" in services or 53 in open_ports:
        return "router"
    if 22 in open_ports:
        return "server"
    if any(p in open_ports for p in [80, 443, 3306, 5432, 8080]):
        return "server"
    if 3389 in open_ports or 445 in open_ports:
        return "pc"
    return "unknown"


def scan_network(subnet: str = None):
    subnet = subnet or get_local_subnet()
    scanner = nmap.PortScanner()
    print(f"[CYBERMORPH][Nmap] Scan en cours sur {subnet} ...")
    scanner.scan(hosts=subnet, arguments="-sn")

    hosts_found = scanner.all_hosts()
    print(f"[CYBERMORPH][Nmap] {len(hosts_found)} hôte(s) découvert(s). Scan détaillé en cours...")

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

            asset_type = guess_asset_type(open_ports, vendor or "", services)

            # Résolution hostname : mDNS d'abord, puis fallback VMware
            resolved_hostname = resolve_hostname_mdns(ip)

            if not resolved_hostname:
                nmap_hostname = host_data.get("hostnames", [{}])[0].get("name") or ""
                if nmap_hostname and nmap_hostname != ip:
                    resolved_hostname = nmap_hostname

            if not resolved_hostname:
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
                existing.asset_type = asset_type
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
                    os_detected=os_detected,
                    open_ports=",".join(map(str, open_ports)),
                    services=",".join(services),
                    status="up",
                )
                db.add(new_asset)

            db.commit()
            print(f"[CYBERMORPH][Nmap] {ip} → {asset_type} ({vendor or 'vendor inconnu'})")

        all_assets = db.query(Asset).all()
        for a in all_assets:
            if a.ip_address not in seen_ips and a.status != "down":
                a.status = "down"
                print(f"[CYBERMORPH][Nmap] {a.ip_address} non vu → marqué down")
        db.commit()

    finally:
        db.close()

    print("[CYBERMORPH][Nmap] Scan terminé.")


if __name__ == "__main__":
    scan_network()
