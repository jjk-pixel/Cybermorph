from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.sql import func
from app.database import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    source_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    destination_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    source_ip = Column(String, nullable=False)
    destination_ip = Column(String, nullable=False)
    protocol = Column(String, nullable=True)
    signature_id = Column(String, nullable=True)
    message = Column(String, nullable=False)
    classification = Column(String, nullable=True)
    priority = Column(Integer, nullable=True)
    occurrence_count = Column(Integer, default=1, nullable=False)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    # Colonne héritée d'une version antérieure, conservée pour ne perdre aucune donnée (plus alimentée)
    detected_at = Column(DateTime(timezone=True), nullable=True)
