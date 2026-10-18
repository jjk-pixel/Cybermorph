import logging
from app.models.alert import Alert
from app.incidents.incident_engine import create_incident_from_alert, mark_dormant_incidents, CORRELATION_WINDOW
from app.incidents.attack_progression import create_potential_steps, advance_incident
from app.risk.apply_risk import apply_risk_scoring
from datetime import datetime, UTC
from app.collectors.nmap_collector import scan_network
from app.collectors.arp_collector import sync_arp_connections
from app.collectors.local_ports_collector import sync_local_asset
from app.collectors.suricata_collector import sync_suricata_alerts
from app.mitre.mapping_engine import apply_mitre_mapping
from app.database import SessionLocal
from app.collectors.snapshot_collector import capture_snapshot
from app.inventory.observations import reconcile_cycle
from app.models.asset import Asset

logging.basicConfig(
    filename="/opt/cybermorph/backend/cybermorph.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


def run_full_scan():
    start = datetime.now(UTC)
    logging.info("=== Début du cycle de scan CYBERMORPH ===")
    print(f"[CYBERMORPH][Orchestrateur] Cycle démarré à {start.isoformat()}")

    # État avant le cycle, pour détecter les changements une seule fois, après tous les collecteurs d'inventaire
    status_before = {}
    try:
        db = SessionLocal()
        try:
            status_before = {a.id: a.status for a in db.query(Asset).all()}
        finally:
            db.close()
    except Exception as e:
        logging.error(f"Lecture de l'état initial impossible : {e}")

    try:
        scan_network()
        logging.info("Scan Nmap terminé avec succès.")
    except Exception as e:
        logging.error(f"Erreur pendant le scan Nmap : {e}")
        print(f"[CYBERMORPH][Orchestrateur] Erreur Nmap : {e}")
    try:
        sync_local_asset()
        logging.info("Synchronisation des ports locaux terminée avec succès.")
    except Exception as e:
        logging.error(f"Erreur pendant la synchronisation des ports locaux : {e}")
        print(f"[CYBERMORPH][Orchestrateur] Erreur LocalPorts : {e}")

    try:
        sync_arp_connections()
        logging.info("Synchronisation ARP terminée avec succès.")
    except Exception as e:
        logging.error(f"Erreur pendant la synchronisation ARP : {e}")
        print(f"[CYBERMORPH][Orchestrateur] Erreur ARP : {e}")
    try:
        db = SessionLocal()
        try:
            changes = reconcile_cycle(db, start, status_before)
            db.commit()
        finally:
            db.close()
        logging.info(f"Rapprochement d'inventaire : {len(changes)} changement(s) détecté(s).")
        print(f"[CYBERMORPH][Inventaire] {len(changes)} changement(s) détecté(s).")
    except Exception as e:
        logging.error(f"Erreur pendant le rapprochement d'inventaire : {e}")
        print(f"[CYBERMORPH][Orchestrateur] Erreur Inventaire : {e}")
    try:
        apply_risk_scoring()
        logging.info("Calcul du risque terminé avec succès.")
    except Exception as e:
        logging.error(f"Erreur pendant le calcul du risque : {e}")
        print(f"[CYBERMORPH][Orchestrateur] Erreur Risk : {e}")
    try:
        sync_suricata_alerts()
        logging.info("Synchronisation Suricata terminée avec succès.")
    except Exception as e:
        logging.error(f"Erreur pendant la synchronisation Suricata : {e}")
        print(f"[CYBERMORPH][Orchestrateur] Erreur Suricata : {e}")
    try:
        db = SessionLocal()
        try:
            apply_mitre_mapping(db)
        finally:
            db.close()
        logging.info("Mapping MITRE ATT&CK terminé avec succès.")
    except Exception as e:
        logging.error(f"Erreur pendant le mapping MITRE : {e}")
        print(f"[CYBERMORPH][Orchestrateur] Erreur MITRE : {e}")
    try:
        capture_snapshot()
        logging.info("Snapshot capturé avec succès.")
    except Exception as e:
        logging.error(f"Erreur pendant la capture du snapshot : {e}")
        print(f"[CYBERMORPH][Orchestrateur] Erreur Snapshot : {e}")
    try:
        db = SessionLocal()
        try:
            # Seules les alertes réellement récentes alimentent les incidents : une alerte ancienne
            # ne doit pas maintenir artificiellement un incident actif indéfiniment.
            window_start = datetime.now(UTC) - CORRELATION_WINDOW
            recent_alerts = (
                db.query(Alert)
                .filter(Alert.priority <= 2, Alert.last_seen >= window_start)
                .all()
            )
            incidents_updated = 0
            steps_confirmed = 0
            for a in recent_alerts:
                incident = create_incident_from_alert(db, a)
                if incident:
                    create_potential_steps(db, incident)
                    if advance_incident(db, incident):
                        steps_confirmed += 1
                        create_potential_steps(db, incident)
                    incidents_updated += 1
            dormant = mark_dormant_incidents(db)
        finally:
            db.close()
        logging.info(
            f"Incident Engine : {incidents_updated} incident(s) traité(s), "
            f"{steps_confirmed} étape(s) confirmée(s), {dormant} passé(s) en dormant."
        )
        print(f"[CYBERMORPH][Incidents] {incidents_updated} traité(s), {steps_confirmed} étape(s) confirmée(s), {dormant} dormant(s).")
    except Exception as e:
        logging.error(f"Erreur pendant l'Incident Engine : {e}")
        print(f"[CYBERMORPH][Orchestrateur] Erreur Incidents : {e}")


    end = datetime.now(UTC)
    duration = (end - start).total_seconds()
    logging.info(f"=== Cycle terminé en {duration:.1f}s ===")
    print(f"[CYBERMORPH][Orchestrateur] Cycle terminé en {duration:.1f}s")


if __name__ == "__main__":
    run_full_scan()
