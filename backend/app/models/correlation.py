from sqlalchemy import Column, Integer, String, DateTime, Float, JSON, ForeignKey, UniqueConstraint, Index
from app.database import Base


class Correlation(Base):
    """
    Rapprochement explicable d'événements (alertes, écarts, changements) liés à un même actif ou une même adresse.
    `relation` dit la nature du lien : une corrélation temporelle n'est jamais présentée comme une causalité.
    """
    __tablename__ = "correlations"
    __table_args__ = (UniqueConstraint("kind", "fingerprint", name="uq_correlation"), Index("ix_correlations_window", "window_end"))

    id = Column(Integer, primary_key=True)
    kind = Column(String, nullable=False)            # port_probe, new_service_activity, profile_change, address_activity
    fingerprint = Column(String, nullable=False)     # clé de regroupement : un même ensemble n'est créé qu'une fois
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    ip = Column(String, nullable=True)
    window_start = Column(DateTime(timezone=True), nullable=False)
    window_end = Column(DateTime(timezone=True), nullable=False)
    events = Column(JSON, nullable=False)            # [{type, id, at, summary}] : chaque événement source une seule fois
    event_count = Column(Integer, nullable=False)
    reasoning = Column(String, nullable=False)
    relation = Column(String, nullable=False)        # temporal, same_target, same_address
    confidence = Column(Float, nullable=False)
    techniques = Column(JSON, nullable=True)         # techniques ATT&CK rattachées aux événements sources
    created_at = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False)


class TechniqueEvidence(Base):
    """
    Preuve rattachant une technique ATT&CK à un événement source (alerte IDS ou écart mesuré dans les flux).
    status : observed (comportement mesuré correspondant à la définition), inferred (déduit du nom d'une signature),
    unconfirmed (événement isolé ou rapprochement faible) — jamais une preuve de compromission.
    """
    __tablename__ = "technique_evidence"
    __table_args__ = (
        UniqueConstraint("technique_ref", "event_type", "event_id", name="uq_technique_evidence"),
        Index("ix_technique_evidence_technique", "technique_ref"),
    )

    id = Column(Integer, primary_key=True)
    technique_ref = Column(Integer, ForeignKey("attack_techniques.id"), nullable=False)
    event_type = Column(String, nullable=False)      # alert, deviation
    event_id = Column(Integer, nullable=False)
    status = Column(String, nullable=False)
    source = Column(String, nullable=False)          # suricata_signature, flow_analysis
    confidence = Column(Float, nullable=False)
    reason = Column(String, nullable=True)
    observations = Column(Integer, nullable=False)
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
