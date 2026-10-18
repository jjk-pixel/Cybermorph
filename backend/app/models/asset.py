from sqlalchemy import Column, Integer, String, DateTime, Float, JSON
from sqlalchemy.sql import func
from app.database import Base

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    hostname = Column(String, nullable=True)
    ip_address = Column(String, unique=True, index=True, nullable=False)
    mac_address = Column(String, nullable=True)
    vendor = Column(String, nullable=True)          # constructeur (via MAC OUI)
    asset_type = Column(String, nullable=False)      # pc, server, router, iot...
    os_detected = Column(String, nullable=True)
    open_ports = Column(String, nullable=True)        # ex: "22,80,443" (simple pour l'instant)
    services = Column(String, nullable=True)          # ex: "ssh,http,https"
    status = Column(String, default="unknown")        # up, down, unknown
    risk_score = Column(Float, default=0.0)
    risk_factors = Column(String, nullable=True)  # JSON stringifié : détail des facteurs de risque
    zone = Column(String, nullable=True)               # ex: "lan", "dmz", "iot"
    # Provenance du type : "declared" (saisi par l'opérateur, jamais écrasé par un scan) ou NULL/"inferred"
    asset_type_source = Column(String, nullable=True)
    # Explication de la classification automatique : {type, confidence, reasons[], alternatives[]}
    classification = Column(JSON, nullable=True)
    # Criticité DÉCLARÉE par l'opérateur (low, medium, high, critical) ; NULL = criticité inférée à la volée
    criticality = Column(String, nullable=True)
    criticality_reason = Column(String, nullable=True)
    criticality_updated_at = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
