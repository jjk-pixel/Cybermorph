import re
from datetime import datetime, UTC
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.asset import Asset
from app.models.alert import Alert

FAST_LOG_PATH = "/var/log/suricata/fast.log"

LINE_PATTERN = re.compile(
    r"(?P<date>\d{2}/\d{2}/\d{4})-(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+\[(?P<sig_id>[\d:]+)\]\s+(?P<message>.+?)\s+\[\*\*\]\s+"
    r"\[Classification:\s+(?P<classification>[^\]]+)\]\s+"
    r"\[Priority:\s+(?P<priority>\d+)\]\s+"
    r"\{(?P<proto>\w+)\}\s+"
    r"(?P<src_ip>[\d.]+):(?P<src_port>\d+)\s+->\s+(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)"
)


def parse_fast_log(path: str = FAST_LOG_PATH) -> list[dict]:
    alerts = []
    try:
        with open(path, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[CYBERMORPH][Suricata] Fichier introuvable : {path}")
        return alerts

    for line in lines:
        match = LINE_PATTERN.match(line.strip())
        if not match:
            continue
        alerts.append(match.groupdict())

    return alerts


def sync_suricata_alerts():
    records = parse_fast_log()
    print(f"[CYBERMORPH][Suricata] {len(records)} ligne(s) d'alerte trouvée(s) dans fast.log.")

    db: Session = SessionLocal()
    try:
        new_count = 0
        updated_count = 0

        for r in records:
            detected_at = None
            try:
                dt_str = f"{r['date']}-{r['time'][:8]}"
                detected_at = datetime.strptime(dt_str, "%m/%d/%Y-%H:%M:%S").replace(tzinfo=UTC)
            except ValueError:
                pass

            existing = (
                db.query(Alert)
                .filter(
                    Alert.signature_id == r["sig_id"],
                    Alert.source_ip == r["src_ip"],
                    Alert.destination_ip == r["dst_ip"],
                )
                .first()
            )

            if existing:
                existing.occurrence_count += 1
                if detected_at and (not existing.last_seen or detected_at > existing.last_seen):
                    existing.last_seen = detected_at
                updated_count += 1
                continue

            source = db.query(Asset).filter(Asset.ip_address == r["src_ip"]).first()
            dest = db.query(Asset).filter(Asset.ip_address == r["dst_ip"]).first()

            alert = Alert(
                source_asset_id=source.id if source else None,
                destination_asset_id=dest.id if dest else None,
                source_ip=r["src_ip"],
                destination_ip=r["dst_ip"],
                protocol=r["proto"],
                signature_id=r["sig_id"],
                message=r["message"],
                classification=r["classification"],
                priority=int(r["priority"]),
                occurrence_count=1,
                first_seen=detected_at,
                last_seen=detected_at,
            )
            db.add(alert)
            new_count += 1

        db.commit()
        print(f"[CYBERMORPH][Suricata] {new_count} nouvelle(s) alerte(s), {updated_count} occurrence(s) mise(s) à jour.")
   	# Vider le fichier après lecture pour ne traiter que les nouvelles lignes au prochain cycle
        open(FAST_LOG_PATH, "w").close()

    finally:
        db.close()

if __name__ == "__main__":
    sync_suricata_alerts()

