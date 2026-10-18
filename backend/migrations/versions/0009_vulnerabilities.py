"""Lot E — correspondances logiciel ↔ vulnérabilités, avec statut de validation.

Ajout uniquement : table `vulnerability_findings`. Aucune donnée n'est créée par la migration : les correspondances
ne viennent que d'une source configurée (flux local au format NVD, ou API NVD si activée).

Revision ID: 0009_vulnerabilities
Revises: 0008_risk_history
Create Date: 2026-10-18
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0009_vulnerabilities"
down_revision: Union[str, Sequence[str], None] = "0008_risk_history"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "vulnerability_findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("cpe", sa.String(), nullable=True),
        sa.Column("product", sa.String(), nullable=True),
        sa.Column("version", sa.String(), nullable=True),
        sa.Column("cve_id", sa.String(), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(), nullable=True),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column("affected", sa.JSON(), nullable=True),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("references", sa.JSON(), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("status_reason", sa.String(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("validated_note", sa.String(), nullable=True),
        sa.UniqueConstraint("asset_id", "port", "cve_id", name="uq_vulnerability_finding"),
    )
    op.create_index("ix_vulnerability_findings_asset", "vulnerability_findings", ["asset_id", "status"])


def downgrade() -> None:
    op.drop_index("ix_vulnerability_findings_asset", table_name="vulnerability_findings")
    op.drop_table("vulnerability_findings")
