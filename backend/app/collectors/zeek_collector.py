import subprocess
from datetime import datetime, UTC
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.asset import Asset
from app.models.network_connection import NetworkConnection

ZEEK_BIN = "/opt/zeek/bin/zeek"
CAPTURE_DURATION_SECONDS = 20  # durée de capture à chaque cycle


def capture_traffic(interface: str = "ens33", duration: int = CAPTURE_DURATION_SECONDS) -> str:
    """Lance Zeek en capture live pendant `duration` secondes, retourne le contenu de conn.log."""
    proc = subprocess.Popen(
        [ZEEK_BIN, "-C", "-i", interface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        proc.wait(timeout=duration)
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait(timeout=5)

    try:
        with open("conn.log", "r") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def parse_conn_log(content: str) -> list[dict]:
    """Parse le format TSV Zeek conn.log en liste de dictionnaires."""
    lines = content.strip().split("\n")
    fields = []
    records = []

    for line in lines:
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
        elif line.startswith("#"):
            continue
        else:
            values = line.split("\t")
            if len(values) != len(fields):
                continue
            record = dict(zip(fields, values))
            records.append(record)

    return records


def sync_zeek_connections(interface: str = "ens33"):
    print(f"[CYBERMORPH][Zeek] Capture en cours sur {interface} ({CAPTURE_DURATION_SECONDS}s)...")
    raw_log = capture_traffic(interface)

    if not raw_log:
        print("[CYBERMORPH][Zeek] Aucun log capturé.")
        return

    records = parse_conn_log(raw_log)
    print(f"[CYBERMORPH][Zeek] {len(records)} connexion(s) observée(s) dans conn.log.")

    db: Session = SessionLocal()
    try:
        for r in records:
            src_ip = r.get("id.orig_h")
            dst_ip = r.get("id.resp_h")
            dst_port_raw = r.get("id.resp_p")
            proto = r.get("proto")
            service = r.get("service")

            if not src_ip or not dst_ip:
                continue

            source = db.query(Asset).filter(Asset.ip_address == src_ip).first()
            dest = db.query(Asset).filter(Asset.ip_address == dst_ip).first()

            # On n'enregistre que les connexions entre deux assets déjà connus de CYBERMORPH
            # (une IP externe comme 172.217.16.238/Google n'est pas un asset de ton lab)
            if not source or not dest:
                continue

            try:
                dst_port = int(dst_port_raw) if dst_port_raw and dst_port_raw != "-" else None
            except ValueError:
                dst_port = None

            protocol_label = service if service and service != "-" else proto

            existing = (
                db.query(NetworkConnection)
                .filter(
                    NetworkConnection.source_asset_id == source.id,
                    NetworkConnection.destination_asset_id == dest.id,
                    NetworkConnection.connection_type == "detected",
                    NetworkConnection.port == dst_port,
                )
                .first()
            )

            if existing:
                existing.status = "active"
                existing.last_seen = datetime.now(UTC)
            else:
                db.add(NetworkConnection(
                    source_asset_id=source.id,
                    destination_asset_id=dest.id,
                    protocol=protocol_label,
                    port=dst_port,
                    connection_type="detected",
                    status="active",
                ))

            db.commit()
            print(f"[CYBERMORPH][Zeek] Observé : {src_ip} → {dst_ip}:{dst_port} ({protocol_label})")

    finally:
        db.close()

    print("[CYBERMORPH][Zeek] Synchronisation terminée.")


if __name__ == "__main__":
    sync_zeek_connections()
