from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, BigInteger, UniqueConstraint, Index
from app.database import Base


class Communication(Base):
    """
    Activité : agrégat des flux observés (Suricata) entre une source et une destination, pour un protocole,
    un port de service et un protocole applicatif. C'est l'unité de la référence comportementale.
    Les destinations hors réseau local sont regroupées par portée (external, multicast, broadcast…).
    """
    __tablename__ = "communications"
    __table_args__ = (
        UniqueConstraint("src_ip", "dst_key", "proto", "dst_port", "app_proto", name="uq_communication"),
        Index("ix_communications_assets", "src_asset_id", "dst_asset_id"),
    )

    id = Column(Integer, primary_key=True)
    src_ip = Column(String, nullable=False)
    dst_key = Column(String, nullable=False)          # IP locale, ou portée (external, multicast…) pour le reste
    dst_scope = Column(String, nullable=False)        # local, routed, external, multicast, broadcast, link-local
    src_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    dst_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    proto = Column(String, nullable=False)
    dst_port = Column(Integer, nullable=False, default=-1)   # -1 : sans port (ICMP…)
    app_proto = Column(String, nullable=False, default="")
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    flow_count = Column(Integer, nullable=False, default=0)
    established_count = Column(Integer, nullable=False, default=0)
    bytes_toserver = Column(BigInteger, nullable=False, default=0)
    bytes_toclient = Column(BigInteger, nullable=False, default=0)
    # learning → baseline (appris pendant l'apprentissage), new (écart), accepted (validé par l'opérateur)
    baseline_state = Column(String, nullable=False)
    learned_via = Column(String, nullable=True)       # global_learning, asset_learning, operator
    details = Column(JSON, nullable=True)             # échantillons : IP externes, SNI, flow_id Suricata


class Deviation(Base):
    """Écart à la référence comportementale, expliqué et rattaché à ses preuves (activité, flux, alertes)."""
    __tablename__ = "deviations"
    __table_args__ = (Index("ix_deviations_status", "status", "last_seen"), Index("ix_deviations_kind", "kind", "src_ip", "status"))

    id = Column(Integer, primary_key=True)
    kind = Column(String, nullable=False)             # new_communication, port_scan, host_sweep
    severity = Column(String, nullable=False)         # info, notice, warning
    status = Column(String, nullable=False, default="open")   # open, acknowledged, learned
    src_ip = Column(String, nullable=True)
    dst_ip = Column(String, nullable=True)
    src_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    dst_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    communication_id = Column(Integer, ForeignKey("communications.id"), nullable=True)
    explanation = Column(String, nullable=False)
    reasons = Column(JSON, nullable=True)             # facteurs qui fixent la sévérité
    evidence = Column(JSON, nullable=True)
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    occurrences = Column(Integer, nullable=False, default=1)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
