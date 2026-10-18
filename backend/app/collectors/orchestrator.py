"""
Cycle de collecte CYBERMORPH (timer systemd toutes les 5 min).

Ordre : nmap → local → arp → inventaire → suricata → mitre → eve → risque → snapshot → incidents.
- Un seul cycle à la fois (verrou) ; un lancement concurrent est tracé « skipped » et ne fait rien.
- Chaque étape est tracée dans `collector_runs` ; une étape en échec n'empêche pas les suivantes.
- Arrêt propre sur SIGTERM/SIGINT : l'étape en cours se termine « interrupted », les suivantes ne sont pas lancées.
"""
import uuid
from datetime import datetime, UTC

from app.collectors import runs
from app.collectors.arp_collector import sync_arp_connections
from app.collectors.local_ports_collector import sync_local_asset
from app.collectors.nmap_collector import scan_network
from app.collectors.snapshot_collector import capture_snapshot
from app.collectors.suricata_collector import sync_suricata_alerts
from app.behavior.baseline import ingest_eve
from app.database import SessionLocal
from app.incidents.attack_progression import advance_incident, create_potential_steps
from app.incidents.incident_engine import CORRELATION_WINDOW, create_incident_from_alert, mark_dormant_incidents
from app.inventory.observations import reconcile_cycle
from app.logging_config import configure_logging
from app.mitre.mapping_engine import apply_mitre_mapping
from app.models.alert import Alert
from app.models.asset import Asset
from app.risk.apply_risk import apply_risk_scoring

logger = configure_logging()


def _with_session(fn):
    def step():
        db = SessionLocal()
        try:
            result = fn(db)
            db.commit()
            return result
        finally:
            db.close()
    return step


def _status_before() -> dict:
    db = SessionLocal()
    try:
        return {a.id: a.status for a in db.query(Asset).all()}
    finally:
        db.close()


def _incidents(db) -> dict:
    # Seules les alertes réellement récentes alimentent les incidents : une alerte ancienne
    # ne doit pas maintenir artificiellement un incident actif indéfiniment.
    window_start = datetime.now(UTC) - CORRELATION_WINDOW
    recent_alerts = db.query(Alert).filter(Alert.priority <= 2, Alert.last_seen >= window_start).all()
    updated, confirmed = 0, 0
    for a in recent_alerts:
        incident = create_incident_from_alert(db, a)
        if incident:
            create_potential_steps(db, incident)
            if advance_incident(db, incident):
                confirmed += 1
                create_potential_steps(db, incident)
            updated += 1
    dormant = mark_dormant_incidents(db)
    print(f"[CYBERMORPH][Incidents] {updated} traité(s), {confirmed} étape(s) confirmée(s), {dormant} dormant(s).")
    return {"incidents_updated": updated, "steps_confirmed": confirmed, "dormant": dormant}


def _eve(db) -> dict:
    stats = ingest_eve(db)
    print(f"[CYBERMORPH][Comportement] {stats}")
    return stats


def run_full_scan() -> dict:
    cycle_id = uuid.uuid4().hex[:12]
    start = datetime.now(UTC)
    print(f"[CYBERMORPH][Orchestrateur] Cycle {cycle_id} démarré à {start.isoformat()}")
    runs.install_signal_handlers()
    try:
        with runs.cycle_lock():
            return _run_cycle(cycle_id, start)
    except runs.CycleBusy as e:
        logger.warning("cycle_skipped", extra={"cycle_id": cycle_id, "reason": str(e)})
        print(f"[CYBERMORPH][Orchestrateur] {e} : cycle ignoré.")
        try:
            runs.record_run("cycle", "skipped", start, cycle_id, error=str(e))
        except Exception as record_error:  # noqa: BLE001
            logger.error("cycle_skip_not_recorded", extra={"error": runs.sanitize_error(record_error)})
        return {"cycle_id": cycle_id, "status": "skipped"}


def _run_cycle(cycle_id: str, start: datetime) -> dict:
    logger.info("cycle_start", extra={"cycle_id": cycle_id})
    # État avant le cycle, pour détecter les changements une seule fois, après tous les collecteurs d'inventaire
    try:
        status_before = _status_before()
    except Exception as e:  # noqa: BLE001
        status_before = {}
        logger.error("status_before_unavailable", extra={"cycle_id": cycle_id, "error": runs.sanitize_error(e)})

    steps = [
        ("nmap", scan_network),
        ("local_ports", sync_local_asset),
        ("arp", sync_arp_connections),
        ("inventory", _with_session(lambda db: {"changes": len(reconcile_cycle(db, start, status_before))})),
        ("suricata", sync_suricata_alerts),
        ("mitre", _with_session(apply_mitre_mapping)),
        ("eve", _with_session(_eve)),
        # Le risque est calculé après les alertes et les flux : il tient compte des derniers faits observés
        ("risk", apply_risk_scoring),
        ("snapshot", capture_snapshot),
        ("incidents", _with_session(_incidents)),
    ]
    results = {}
    for name, fn in steps:
        if runs.stop_requested.is_set():
            results[name] = "not_started"
            continue
        status, _ = runs.run_step(name, fn, cycle_id, logger)
        results[name] = status
        if status != "success":
            print(f"[CYBERMORPH][Orchestrateur] Étape {name} : {status}")

    duration = (datetime.now(UTC) - start).total_seconds()
    overall = "interrupted" if runs.stop_requested.is_set() else (
        "success" if all(s == "success" for s in results.values()) else "partial")
    runs.record_run("cycle", overall, start, cycle_id, stats={"steps": results})
    logger.info("cycle_end", extra={"cycle_id": cycle_id, "status": overall, "duration_s": round(duration, 1), "steps": results})
    print(f"[CYBERMORPH][Orchestrateur] Cycle terminé en {duration:.1f}s ({overall})")
    return {"cycle_id": cycle_id, "status": overall, "steps": results}


if __name__ == "__main__":
    run_full_scan()
