"""Lot D — historique des scores de risque.

Ajout uniquement : table `risk_history` (une ligne quand le score, le niveau ou la confiance changent, et au moins
une par heure et par actif).

Revision ID: 0008_risk_history
Revises: 0007_relations
Create Date: 2026-10-18
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0008_risk_history"
down_revision: Union[str, Sequence[str], None] = "0007_relations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "risk_history",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("level", sa.String(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("model_version", sa.Integer(), nullable=False),
        sa.Column("breakdown", sa.JSON(), nullable=True),
    )
    op.create_index("ix_risk_history_asset", "risk_history", ["asset_id", "computed_at"])


def downgrade() -> None:
    op.drop_index("ix_risk_history_asset", table_name="risk_history")
    op.drop_table("risk_history")
