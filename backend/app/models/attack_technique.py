from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Float, Index
from sqlalchemy.sql import func
from app.database import Base


class AttackTechnique(Base):
    """Référentiel des techniques MITRE ATT&CK connues de CYBERMORPH (sous-ensemble pertinent, pas le catalogue complet)."""
    __tablename__ = "attack_techniques"

    id = Column(Integer, primary_key=True, index=True)
    technique_id = Column(String, unique=True, nullable=False)  # ex: "T1046"
    name = Column(String, nullable=False)
    tactic = Column(String, nullable=False)  # ex: "Discovery", "Credential Access"
    description = Column(String, nullable=True)
    platform = Column(String, nullable=True)  # ex: "Network", "Linux", "Windows"


class AlertTechniqueMapping(Base):
    """Association entre une alerte observée et une technique ATT&CK, avec un niveau de confiance explicite."""
    __tablename__ = "alert_technique_mappings"
    __table_args__ = (Index("ix_alert_technique_mappings_alert", "alert_id"),)

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False)
    technique_id = Column(Integer, ForeignKey("attack_techniques.id"), nullable=False)
    confidence = Column(Float, nullable=False)  # 0.0 - 1.0 : fiabilité du mapping, pas de l'alerte elle-même
    matched_on = Column(String, nullable=True)  # ce qui a déclenché le mapping (mot-clé, classtype...)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
