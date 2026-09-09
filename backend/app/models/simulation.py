from sqlalchemy import Column, Integer, String, DateTime, JSON
from sqlalchemy.sql import func
from app.database import Base


class Simulation(Base):
    __tablename__ = "simulations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    status = Column(String, default="created")  # created, hypothesis_applied, completed, failed
    hypothesis = Column(JSON, nullable=True)  # ex: {"type": "asset_compromised", "asset_id": 2}
    result = Column(JSON, nullable=True)       # résultat complet, stocké une fois calculé
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
