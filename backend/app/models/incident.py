from datetime import datetime, UTC
from sqlalchemy import Column, Integer, String, Float, DateTime, JSON
from app.database import Base


def _utcnow() -> datetime:
    """UTC naïf : ces colonnes DateTime sont sans fuseau."""
    return datetime.now(UTC).replace(tzinfo=None)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    status = Column(String, nullable=False, default="detected")
    source_asset_id = Column(Integer, nullable=True)
    current_asset_id = Column(Integer, nullable=True)
    target_asset_id = Column(Integer, nullable=True)
    technique_id = Column(String, nullable=True)
    confidence = Column(Float, default=0.0)
    current_step = Column(Integer, default=1)
    total_steps = Column(Integer, default=1)
    started_at = Column(DateTime, default=_utcnow)
    last_seen = Column(DateTime, default=_utcnow)
    metadata_json = Column(JSON, nullable=True)

