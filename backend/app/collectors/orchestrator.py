import logging
from app.models.alert import Alert
from app.incidents.incident_engine import create_incident_from_alert
from app.incidents.attack_progression import create_potential_steps
from app.risk.apply_risk import apply_risk_scoring
from datetime import datetime, UTC
from app.collectors.nmap_collector import scan_network
from app.collectors.arp_collector import sync_arp_connections
from app.collectors.local_ports_collector import sync_local_asset
from app.collectors.suricata_collector import sync_suricata_alerts
from app.mitre.mapping_engine import apply_mitre_mapping
from app.database import SessionLocal
from app.collectors.snapshot_collector import capture_snapshot

logging.basicConfig(
    filename="/opt/cybermorph/backend/cybermorph.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


def run_full_scan():
    start = datetime.now(UTC)
    logging.info("=== Début du cycle de scan CYBERMORPH ===")
    print(f"[CYBERMORPH][Orchestrateur] Cycle démarré à {start.isoformat()}")

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
        apply_mitre_mapping(db)
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
        recent_alerts = db.query(Alert).filter(Alert.priority <= 2).all()
        incidents_updated = 0
        for a in recent_alerts:
            incident = create_incident_from_alert(db, a)
            if incident:
                create_potential_steps(db, incident)
                incidents_updated += 1
        db.close()
        logging.info(f"Incident Engine : {incidents_updated} incident(s) traité(s).")
        print(f"[CYBERMORPH][Incidents] {incidents_updated} incident(s) traité(s).")
    except Exception as e:
        logging.error(f"Erreur pendant l'Incident Engine : {e}")
        print(f"[CYBERMORPH][Orchestrateur] Erreur Incidents : {e}")


    end = datetime.now(UTC)
    duration = (end - start).total_seconds()
    logging.info(f"=== Cycle terminé en {duration:.1f}s ===")
    print(f"[CYBERMORPH][Orchestrateur] Cycle terminé en {duration:.1f}s")


if __name__ == "__main__":
    run_full_scan()
