from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.database import Base

class NetworkConnection(Base):
    __tablename__ = "network_connections"

    id = Column(Integer, primary_key=True, index=True)
    source_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    destination_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    protocol = Column(String, nullable=True)      # tcp, udp, icmp...
    port = Column(Integer, nullable=True)
    connection_type = Column(String, nullable=True)  # ex: "detected", "inferred", "declared"
    status = Column(String, default="active")         # active, inactive
    # Capteur à l'origine de la relation : suricata_flow, arp, zeek, operator ; NULL = antérieur à ce suivi
    source = Column(String, nullable=True)
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    source_asset = relationship("Asset", foreign_keys=[source_asset_id])
    destination_asset = relationship("Asset", foreign_keys=[destination_asset_id])
