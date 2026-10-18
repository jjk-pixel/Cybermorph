"""
État de santé réel de la collecte : cycles, étapes, capteurs, fraîcheur des données par actif.

Principes :
- l'absence de données n'est jamais présentée comme une absence de menace : un capteur muet ou une étape en échec
  est signalé comme une perte de visibilité ;
- la fréquence annoncée est celle du timer (CYBERMORPH_CYCLE_MINUTES, 5 par défaut) : le flux /ws/live rediffuse
  l'état toutes les 5 s mais n'est jamais plus récent que le dernier cycle.
"""
import os
import subprocess
from datetime import datetime, timedelta, UTC
from pathlib import Path

from sqlalchemy.orm import Session

from app.inventory.observations import get_setting
from app.models.asset import Asset
from app.models.collector import CollectorRun

CYCLE_MINUTES = float(os.getenv("CYBERMORPH_CYCLE_MINUTES", "5"))
FRESH_AFTER = timedelta(minutes=15)
STALE_AFTER = timedelta(hours=1)
STEPS = ("nmap", "local_ports", "arp", "inventory", "suricata", "eve", "mitre", "vulnerabilities", "correlation",
         "risk", "snapshot", "incidents")
STEP_LABEL = {
    "nmap": "Découverte Nmap", "local_ports": "Ports locaux (ss)", "arp": "Voisinage ARP", "inventory": "Rapprochement d'inventaire",
    "suricata": "Alertes Suricata (fast.log)", "eve": "Flux Suricata (eve.json)", "mitre": "ATT&CK",
    "vulnerabilities": "Vulnérabilités", "correlation": "Corrélation", "risk": "Risque", "snapshot": "Snapshot",
    "incidents": "Incidents",
}
# Étapes dont l'échec fait perdre de la visibilité sur le réseau (et pas seulement un calcul)
VISIBILITY_STEPS = {"nmap": "inventaire actif", "arp": "voisinage", "suricata": "alertes IDS", "eve": "flux réseau"}


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def timer_state(runner=subprocess.run) -> dict:
    """État du timer systemd, lu sans privilège ; indisponible hors systemd (tests, conteneur)."""
    try:
        out = runner(["systemctl", "show", "cybermorph-scan.timer", "--property=ActiveState,LastTriggerUSec,NextElapseUSecRealtime"],
                     capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return {"available": False}
    props = dict(line.split("=", 1) for line in out.stdout.splitlines() if "=" in line)
    if not props:
        return {"available": False}
    return {"available": True, "active_state": props.get("ActiveState"), "last_trigger": props.get("LastTriggerUSec") or None,
            "next_elapse": props.get("NextElapseUSecRealtime") or None}


def _step_status(db: Session, collector: str, now: datetime) -> dict:
    runs = db.query(CollectorRun).filter(CollectorRun.collector == collector).order_by(CollectorRun.started_at.desc(), CollectorRun.id.desc()).limit(20).all()
    last = runs[0] if runs else None
    success = next((r for r in runs if r.status == "success"), None)
    if success is None:
        success = db.query(CollectorRun).filter(CollectorRun.collector == collector, CollectorRun.status == "success").order_by(
            CollectorRun.started_at.desc()).first()
    failures = 0
    for r in runs:
        if r.status in ("failed", "interrupted"):
            failures += 1
        else:
            break
    return {
        "collector": collector, "label": STEP_LABEL.get(collector, collector),
        "last_run_at": _utc(last.started_at) if last else None, "last_status": last.status if last else None,
        "last_error": last.error if last and last.status != "success" else None,
        "last_duration_s": last.duration_s if last else None,
        "last_success_at": _utc(success.started_at) if success else None,
        "consecutive_failures": failures,
        "stats": last.stats if last else None,
    }


def asset_freshness(asset: Asset, now: datetime) -> dict:
    last = _utc(asset.last_seen)
    if last is None:
        state, age = "unknown", None
    else:
        age = (now - last).total_seconds()
        state = "fresh" if age <= FRESH_AFTER.total_seconds() else ("stale" if age <= STALE_AFTER.total_seconds() else "obsolete")
    return {"asset_id": asset.id, "ip": asset.ip_address, "status": asset.status, "last_seen": last,
            "age_s": round(age) if age is not None else None, "freshness": state}


def system_health(db: Session, now: datetime | None = None, runner=subprocess.run) -> dict:
    now = now or datetime.now(UTC)
    interval = timedelta(minutes=CYCLE_MINUTES)
    cycles = db.query(CollectorRun).filter(CollectorRun.collector == "cycle").order_by(CollectorRun.started_at.desc()).limit(12).all()
    last_cycle = cycles[0] if cycles else None
    last_cycle_at = _utc(last_cycle.started_at) if last_cycle else None
    late = last_cycle_at is None or now - last_cycle_at > 2 * interval
    steps = [_step_status(db, s, now) for s in STEPS]
    nmap = next(s for s in steps if s["collector"] == "nmap")
    assets = [asset_freshness(a, now) for a in db.query(Asset).order_by(Asset.id).all()]

    issues = []
    if last_cycle_at is None:
        issues.append({"severity": "critical", "message": "Aucun cycle de collecte enregistré : les données affichées ne sont pas mises à jour."})
    elif late:
        minutes = int((now - last_cycle_at).total_seconds() // 60)
        issues.append({"severity": "critical", "message": f"Collecte en retard : dernier cycle il y a {minutes} min (attendu toutes les {CYCLE_MINUTES:g} min)."})
    for s in steps:
        if s["last_status"] in ("failed", "interrupted"):
            impact = VISIBILITY_STEPS.get(s["collector"])
            message = f"{s['label']} : {s['last_status']} ({s['last_error'] or 'sans détail'})"
            if impact:
                message += f". Visibilité perdue ({impact}) : l'absence d'événement n'est pas une absence de menace."
            issues.append({"severity": "warning" if s["consecutive_failures"] < 3 else "critical", "message": message,
                           "collector": s["collector"]})
    eve_run = get_setting(db, "eve_last_run") or {}
    if eve_run.get("error"):
        issues.append({"severity": "warning", "message": f"Flux Suricata indisponible : {eve_run['error']}. Comportement non observé."})
    fast_log = Path(os.getenv("CYBERMORPH_FAST_LOG", "/var/log/suricata/fast.log"))
    vuln = next(s for s in steps if s["collector"] == "vulnerabilities")
    if vuln["last_status"] == "skipped":
        issues.append({"severity": "info", "message": "Aucune source de vulnérabilités configurée : les CVE ne sont pas évaluées."})
    obsolete = [a for a in assets if a["freshness"] == "obsolete"]
    if obsolete:
        issues.append({"severity": "info", "message": f"{len(obsolete)} actif(s) sans observation depuis plus d'une heure : données potentiellement obsolètes ({', '.join(a['ip'] for a in obsolete)})."})

    severities = {i["severity"] for i in issues}
    overall = "failing" if "critical" in severities else ("degraded" if "warning" in severities else "ok")
    return {
        "generated_at": now,
        "status": overall,
        "cycle": {
            "interval_minutes": CYCLE_MINUTES,
            "last_cycle_at": last_cycle_at,
            "last_cycle_status": last_cycle.status if last_cycle else None,
            "last_cycle_duration_s": last_cycle.duration_s if last_cycle else None,
            "late": late,
            "recent": [{"at": _utc(c.started_at), "status": c.status, "duration_s": c.duration_s} for c in cycles],
        },
        "timer": timer_state(runner),
        "last_scan": {"executed_at": nmap["last_run_at"], "status": nmap["last_status"], "succeeded_at": nmap["last_success_at"]},
        "steps": steps,
        "sensors": {
            "fast_log": {"path": str(fast_log), "present": fast_log.exists()},
            "eve": {"last_run": eve_run or None},
        },
        "assets": assets,
        "issues": issues,
        "refresh_note": (f"Collecte périodique toutes les {CYCLE_MINUTES:g} min. Le flux temps réel rediffuse l'état "
                         "toutes les 5 s, sans être plus récent que le dernier cycle."),
    }


def collection_summary(db: Session, now: datetime | None = None) -> dict:
    """Résumé léger pour le flux /ws/live (barre d'état)."""
    now = now or datetime.now(UTC)
    last = db.query(CollectorRun).filter(CollectorRun.collector == "cycle").order_by(CollectorRun.started_at.desc()).first()
    failing = []
    if last and last.stats:
        failing = [k for k, v in (last.stats.get("steps") or {}).items() if v in ("failed", "interrupted")]
    last_at = _utc(last.started_at) if last else None
    return {
        "interval_minutes": CYCLE_MINUTES,
        "last_cycle_at": last_at.isoformat().replace("+00:00", "Z") if last_at else None,
        "last_cycle_status": last.status if last else None,
        "late": last_at is None or now - last_at > timedelta(minutes=2 * CYCLE_MINUTES),
        "failing_steps": failing,
    }
