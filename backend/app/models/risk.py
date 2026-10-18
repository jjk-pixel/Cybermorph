from sqlalchemy import Column, Integer, String, DateTime, Float, JSON, ForeignKey, Index
from app.database import Base


class RiskHistory(Base):
    """Historique des scores : une ligne quand le score, le niveau ou la confiance changent (au moins une par heure)."""
    __tablename__ = "risk_history"
    __table_args__ = (Index("ix_risk_history_asset", "asset_id", "computed_at"),)

    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    computed_at = Column(DateTime(timezone=True), nullable=False)
    score = Column(Float, nullable=False)
    level = Column(String, nullable=False)
    confidence = Column(Float, nullable=True)
    model_version = Column(Integer, nullable=False)
    breakdown = Column(JSON, nullable=True)
