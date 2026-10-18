import socket
import subprocess
import re
from datetime import datetime, UTC
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.asset import Asset
from app.collectors.network_utils import get_local_ip_and_interface
from app.inventory.classification import classify_sensor_host
from app.inventory.observations import record_observation


def get_local_listening_ports() -> list[dict]:
    """Utilise `ss` pour lister fiablement les ports en écoute sur cette machine (TCP + UDP)."""
    result = subprocess.run(
        ["ss", "-tulnp"], capture_output=True, text=True
    )
    ports = []
    for line in result.stdout.split("\n")[1:]:
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 5:
            continue

        proto = parts[0]  # tcp, udp, tcp6, udp6...
        local_addr = parts[4]

        match = re.search(r":(\d+)$", local_addr)
        if not match:
            continue
        port = int(match.group(1))

        # Nom du processus si visible (nécessite sudo pour ss -p)
        process_match = re.search(r'users:\(\("(\w+)"', line)
        process = process_match.group(1) if process_match else None

        ports.append({"port": port, "proto": proto.replace("6", ""), "process": process})

    return ports


def sync_local_asset():
    local_ip, _ = get_local_ip_and_interface()
    ports_info = get_local_listening_ports()

    unique_ports = sorted(set(p["port"] for p in ports_info))
    services = sorted(set(p["process"] for p in ports_info if p["process"]))

    print(f"[CYBERMORPH][LocalPorts] {len(unique_ports)} port(s) en écoute détecté(s) sur {local_ip}.")

    db: Session = SessionLocal()
    try:
        asset = db.query(Asset).filter(Asset.ip_address == local_ip).first()
        if not asset:
            print(f"[CYBERMORPH][LocalPorts] Asset local {local_ip} introuvable — le scan Nmap doit tourner au moins une fois avant.")
            return

        asset.open_ports = ",".join(map(str, unique_ports))
        asset.services = ",".join(services)
        # L'hôte local héberge toujours plusieurs services : "server", sauf type déclaré par l'opérateur
        asset.classification = classify_sensor_host()
        if asset.asset_type_source != "declared":
            asset.asset_type = "server"
        asset.status = "up"
        asset.last_seen = datetime.now(UTC)
        asset.hostname = socket.gethostname()
        asset.name = socket.gethostname()
        # L'hôte CYBERMORPH lance les scans Nmap : ses sondes ne doivent pas être apprises comme du trafic normal
        if asset.is_scanner is None:
            asset.is_scanner = True
            asset.scanner_reason = "Hôte du capteur CYBERMORPH : exécute les scans Nmap toutes les 5 minutes"

        record_observation(db, local_ip, "local", "hostname", socket.gethostname(), asset.id)
        for port in unique_ports:
            record_observation(db, local_ip, "local", "open_port", port, asset.id)
        for service in services:
            record_observation(db, local_ip, "local", "service", service, asset.id)
        db.commit()

        print(f"[CYBERMORPH][LocalPorts] {local_ip} mis à jour → {asset.asset_type} (ports: {unique_ports})")

    finally:
        db.close()


if __name__ == "__main__":
    sync_local_asset()
