from datetime import datetime, UTC
from sqlalchemy import Column, Integer, String, Float, DateTime
from app.database import Base


def _utcnow() -> datetime:
    """UTC naïf : ces colonnes DateTime sont sans fuseau."""
    return datetime.now(UTC).replace(tzinfo=None)


class AttackPathStep(Base):
    __tablename__ = "attack_path_steps"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, nullable=False, index=True)
    sequence = Column(Integer, nullable=False)
    source_asset_id = Column(Integer, nullable=False)
    destination_asset_id = Column(Integer, nullable=False)
    status = Column(String, nullable=False, default="potential")
    technique_id = Column(String, nullable=True)
    evidence_type = Column(String, nullable=True)
    confidence = Column(Float, default=0.0)
    detected_at = Column(DateTime, default=_utcnow)
