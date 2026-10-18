import json
import os
import re
from datetime import datetime, UTC
from pathlib import Path
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.asset import Asset
from app.models.alert import Alert

FAST_LOG_PATH = "/var/log/suricata/fast.log"

# Position de lecture mémorisée entre deux cycles : fast.log n'est plus vidé (aucune perte de lignes)
OFFSET_STATE_PATH = Path(__file__).resolve().parents[2] / "suricata_fast.offset"

LINE_PATTERN = re.compile(
    r"(?P<date>\d{2}/\d{2}/\d{4})-(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+\[(?P<sig_id>[\d:]+)\]\s+(?P<message>.+?)\s+\[\*\*\]\s+"
    r"\[Classification:\s+(?P<classification>[^\]]+)\]\s+"
    r"\[Priority:\s+(?P<priority>\d+)\]\s+"
    r"\{(?P<proto>\w+)\}\s+"
    r"(?P<src_ip>[\d.]+):(?P<src_port>\d+)\s+->\s+(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)"
)


def _load_offset() -> dict:
    try:
        return json.loads(OFFSET_STATE_PATH.read_text())
    except (FileNotFoundError, ValueError):
        return {}


def _save_offset(inode: int, offset: int):
    OFFSET_STATE_PATH.write_text(json.dumps({"inode": inode, "offset": offset}))


def read_new_lines(path: str = FAST_LOG_PATH) -> tuple[list[str], int, int] | None:
    """
    Lit uniquement les lignes complètes ajoutées depuis le dernier cycle.
    Repart du début si le fichier a été remplacé (inode) ou tronqué (logrotate copytruncate).
    Retourne (lignes, inode, nouvel_offset) ou None si le fichier est absent.
    """
    try:
        stat = os.stat(path)
    except FileNotFoundError:
        print(f"[CYBERMORPH][Suricata] Fichier introuvable : {path}")
        return None

    state = _load_offset()
    offset = state.get("offset", 0)
    if state.get("inode") != stat.st_ino or stat.st_size < offset:
        offset = 0

    with open(path, "rb") as f:
        f.seek(offset)
        chunk = f.read()

    # On ne consomme pas une éventuelle dernière ligne incomplète (en cours d'écriture par Suricata)
    last_newline = chunk.rfind(b"\n")
    if last_newline == -1:
        return [], stat.st_ino, offset
    complete = chunk[: last_newline + 1]
    lines = complete.decode("utf-8", errors="replace").splitlines()
    return lines, stat.st_ino, offset + len(complete)


def parse_fast_log_lines(lines: list[str], start_offset: int | None = None) -> list[dict]:
    """
    Analyse les lignes ; si `start_offset` est connu, chaque alerte garde sa ligne brute et sa position
    dans fast.log (preuve source consultable).
    """
    alerts = []
    offset = start_offset
    for line in lines:
        match = LINE_PATTERN.match(line.strip())
        if match:
            record = match.groupdict()
            if offset is not None:
                record["_raw"] = {"path": FAST_LOG_PATH, "offset": offset, "line": line.strip()[:1000]}
            alerts.append(record)
        if offset is not None:
            offset += len(line.encode("utf-8")) + 1
    return alerts


def _merge_evidence(evidence: dict | None, raw: dict | None) -> dict | None:
    """Première et dernière ligne fast.log d'une alerte agrégée."""
    if not raw:
        return evidence
    evidence = dict(evidence or {})
    evidence.setdefault("fast_log_first", raw)
    evidence["fast_log_last"] = raw
    return evidence


def parse_fast_log(path: str = FAST_LOG_PATH) -> list[dict]:
    """Parse l'intégralité du fichier (utilitaire de diagnostic, sans effet sur la position mémorisée)."""
    try:
        with open(path, "r") as f:
            return parse_fast_log_lines(f.readlines())
    except FileNotFoundError:
        print(f"[CYBERMORPH][Suricata] Fichier introuvable : {path}")
        return []


def sync_suricata_alerts():
    read = read_new_lines()
    if read is None:
        return
    lines, inode, new_offset = read
    start_offset = new_offset - sum(len(line.encode("utf-8")) + 1 for line in lines)
    records = parse_fast_log_lines(lines, start_offset if start_offset >= 0 else None)
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
                existing.evidence = _merge_evidence(existing.evidence, r.get("_raw"))
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
                evidence=_merge_evidence(None, r.get("_raw")),
            )
            db.add(alert)
            db.flush()  # rend l'alerte visible aux requêtes suivantes du même lot (autoflush désactivé)
            new_count += 1

        db.commit()
        # La position n'avance qu'une fois les alertes enregistrées : en cas d'erreur, les lignes seront relues
        _save_offset(inode, new_offset)
        print(f"[CYBERMORPH][Suricata] {new_count} nouvelle(s) alerte(s), {updated_count} occurrence(s) mise(s) à jour.")

    finally:
        db.close()

if __name__ == "__main__":
    sync_suricata_alerts()

