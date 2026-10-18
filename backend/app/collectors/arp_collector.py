import subprocess
import re
from datetime import datetime, UTC
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.asset import Asset
from app.models.network_connection import NetworkConnection
from app.collectors.network_utils import get_local_ip_and_interface
from app.inventory.observations import record_observation
from app.topology.relations import refresh_quality


def get_arp_neighbors(interface: str):
    result = subprocess.run(["ip", "neigh"], capture_output=True, text=True)
    neighbors = []
    for line in result.stdout.strip().split("\n"):
        if not line or interface not in line:
            continue
        match = re.match(
            r"(?P<ip>[\d.]+)\s+dev\s+(?P<dev>\S+)\s+lladdr\s+(?P<mac>[\da-fA-F:]+)\s+(?P<state>\w+)",
            line,
        )
        if match:
            neighbors.append(match.groupdict())
    return neighbors


def sync_arp_connections():
    local_ip, interface = get_local_ip_and_interface()
    neighbors = get_arp_neighbors(interface)
    print(f"[CYBERMORPH][ARP] {len(neighbors)} voisin(s) détecté(s) sur {interface} ({local_ip}).")

    db: Session = SessionLocal()
    try:
        source = db.query(Asset).filter(Asset.ip_address == local_ip).first()
        if not source:
            print(f"[CYBERMORPH][ARP] L'asset local {local_ip} n'existe pas encore. Lance d'abord le scan Nmap.")
            return

        seen_dest_ids = set()

        for n in neighbors:
            dest = db.query(Asset).filter(Asset.ip_address == n["ip"]).first()
            if not dest:
                print(f"[CYBERMORPH][ARP] {n['ip']} vu en ARP mais absent des assets — ignoré.")
                continue

            seen_dest_ids.add(dest.id)
            # La table ARP corrobore (ou contredit) la MAC vue par Nmap
            record_observation(db, n["ip"], "arp", "mac", n["mac"], dest.id)

            existing = (
                db.query(NetworkConnection)
                .filter(
                    NetworkConnection.source_asset_id == source.id,
                    NetworkConnection.destination_asset_id == dest.id,
                    NetworkConnection.connection_type == "neighbor_detected",
                )
                .first()
            )

            if not existing:
                existing = NetworkConnection(
                    source_asset_id=source.id,
                    destination_asset_id=dest.id,
                    protocol="arp",
                    connection_type="neighbor_detected",
                    status="active",
                    created_at=datetime.now(UTC),
                )
                db.add(existing)
            existing.status = "active"
            existing.last_seen = datetime.now(UTC)
            existing.source = "arp"
            existing.evidence = {"mac": n["mac"].upper(), "arp_state": n["state"]}
            refresh_quality(existing)

            db.commit()
            print(f"[CYBERMORPH][ARP] Voisinage : {local_ip} → {n['ip']} ({n['mac']}, état={n['state']})")

        stale = (
            db.query(NetworkConnection)
            .filter(
                NetworkConnection.source_asset_id == source.id,
                NetworkConnection.connection_type == "neighbor_detected",
                NetworkConnection.status == "active",
            )
            .all()
        )
        for conn in stale:
            if conn.destination_asset_id not in seen_dest_ids:
                conn.status = "inactive"
                print(f"[CYBERMORPH][ARP] Connexion vers asset #{conn.destination_asset_id} marquée inactive")
        db.commit()

    finally:
        db.close()

    print("[CYBERMORPH][ARP] Synchronisation terminée.")


if __name__ == "__main__":
    sync_arp_connections()
