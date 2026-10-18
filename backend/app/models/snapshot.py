from sqlalchemy import Column, Integer, DateTime, JSON
from sqlalchemy.sql import func
from app.database import Base


class Snapshot(Base):
    __tablename__ = "snapshots"

    id = Column(Integer, primary_key=True, index=True)
    captured_at = Column(DateTime(timezone=True), server_default=func.now())
    assets_summary = Column(JSON, nullable=False)
    connections_count = Column(JSON, nullable=False)
    alerts_summary = Column(JSON, nullable=False)
    attack_paths_count = Column(Integer, nullable=False)
    highest_path_score = Column(Integer, nullable=True)
    # Lot 4 — état complet au moment du cycle : relations actives et attributs des actifs (NULL pour l'historique antérieur)
    state = Column(JSON, nullable=True)
