"""Lot G — corrélations d'événements et preuves ATT&CK généralisées (alertes et écarts).

Ajouts : tables `correlations` et `technique_evidence`. Les rapprochements alerte → technique existants
(`alert_technique_mappings`, conservée) sont recopiés comme preuves « inférées » (signature IDS).

Revision ID: 0010_correlation
Revises: 0009_vulnerabilities
Create Date: 2026-10-18
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0010_correlation"
down_revision: Union[str, Sequence[str], None] = "0009_vulnerabilities"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "correlations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=True),
        sa.Column("ip", sa.String(), nullable=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("events", sa.JSON(), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("reasoning", sa.String(), nullable=False),
        sa.Column("relation", sa.String(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("techniques", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("kind", "fingerprint", name="uq_correlation"),
    )
    op.create_index("ix_correlations_window", "correlations", ["window_end"])
    op.create_table(
        "technique_evidence",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("technique_ref", sa.Integer(), sa.ForeignKey("attack_techniques.id"), nullable=False),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("event_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("reason", sa.String(), nullable=True),
        sa.Column("observations", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("technique_ref", "event_type", "event_id", name="uq_technique_evidence"),
    )
    op.create_index("ix_technique_evidence_technique", "technique_evidence", ["technique_ref"])
    op.execute(
        "INSERT INTO technique_evidence (technique_ref, event_type, event_id, status, source, confidence, reason, observations, first_seen, last_seen) "
        "SELECT m.technique_id, 'alert', m.alert_id, "
        "CASE WHEN a.occurrence_count >= 3 THEN 'inferred' ELSE 'unconfirmed' END, "
        "'suricata_signature', m.confidence, m.matched_on, a.occurrence_count, a.first_seen, a.last_seen "
        "FROM alert_technique_mappings m JOIN alerts a ON a.id = m.alert_id"
    )


def downgrade() -> None:
    op.drop_index("ix_technique_evidence_technique", table_name="technique_evidence")
    op.drop_table("technique_evidence")
    op.drop_index("ix_correlations_window", table_name="correlations")
    op.drop_table("correlations")
