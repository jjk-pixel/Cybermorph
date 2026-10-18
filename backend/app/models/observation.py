from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, UniqueConstraint, Index
from sqlalchemy.sql import func
from app.database import Base


class AssetObservation(Base):
    """
    Un fait observé sur un actif, par une source donnée : « nmap a vu le port 22 ouvert sur 10.0.0.5 ».
    Une ligne par (IP, source, attribut, valeur) : les observations répétées incrémentent seen_count.
    `retired_at` marque une valeur qui n'est plus observée (port fermé, ancienne MAC), sans rien supprimer.
    """
    __tablename__ = "asset_observations"
    __table_args__ = (
        UniqueConstraint("ip", "source", "attribute", "value", name="uq_observation"),
        Index("ix_asset_observations_asset", "asset_id", "attribute"),
    )

    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    ip = Column(String, nullable=False)
    source = Column(String, nullable=False)       # nmap, mdns, dns, heuristic, local, arp, dhcp, suricata
    attribute = Column(String, nullable=False)    # mac, vendor, os, hostname, open_port, service
    value = Column(String, nullable=False)
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    seen_count = Column(Integer, nullable=False, default=1)
    retired_at = Column(DateTime(timezone=True), nullable=True)


class AssetChange(Base):
    """Changement détecté sur l'inventaire, avec l'ancienne et la nouvelle valeur et la source qui l'a constaté."""
    __tablename__ = "asset_changes"
    __table_args__ = (Index("ix_asset_changes_detected", "detected_at"),)

    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    ip = Column(String, nullable=True)
    change_type = Column(String, nullable=False)
    attribute = Column(String, nullable=True)
    old_value = Column(String, nullable=True)
    new_value = Column(String, nullable=True)
    source = Column(String, nullable=True)
    severity = Column(String, nullable=False, default="info")   # info, notice, warning
    explanation = Column(String, nullable=False)
    evidence = Column(JSON, nullable=True)                     # identifiants d'observations, etc.
    detected_at = Column(DateTime(timezone=True), nullable=False)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)


class Setting(Base):
    """État durable du jumeau : début de l'apprentissage, positions de lecture des capteurs…"""
    __tablename__ = "cybermorph_settings"

    key = Column(String, primary_key=True)
    value = Column(JSON, nullable=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
