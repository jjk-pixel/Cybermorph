from sqlalchemy import Column, Integer, String, DateTime, Float, JSON, Index
from app.database import Base


class CollectorRun(Base):
    """
    Une exécution d'une étape de collecte (scan Nmap, ARP, Suricata…) : résultat ponctuel, distinct de l'état estimé
    du réseau porté par les actifs. Sert à la supervision (dernier scan, dernier succès, erreurs, retards).
    """
    __tablename__ = "collector_runs"
    __table_args__ = (Index("ix_collector_runs_collector", "collector", "started_at"),)

    id = Column(Integer, primary_key=True)
    cycle_id = Column(String, nullable=True, index=True)      # identifiant du cycle d'orchestration
    collector = Column(String, nullable=False)                # nmap, local_ports, arp, inventory, suricata, mitre, eve…
    status = Column(String, nullable=False)                   # running, success, partial, failed, interrupted, skipped
    started_at = Column(DateTime(timezone=True), nullable=False)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    duration_s = Column(Float, nullable=True)
    error = Column(String, nullable=True)                     # message d'erreur tronqué, sans secret
    stats = Column(JSON, nullable=True)                       # résultats chiffrés (hôtes répondants, lignes lues…)
