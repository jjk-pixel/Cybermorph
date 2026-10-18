"""Lot 1 — classification explicable et criticité des actifs.

Ajouts uniquement (colonnes nullables) : aucune donnée existante n'est modifiée.

Revision ID: 0002_asset_exposure
Revises: 0001_baseline
Create Date: 2026-10-18
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002_asset_exposure"
down_revision: Union[str, Sequence[str], None] = "0001_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("assets") as batch_op:
        batch_op.add_column(sa.Column("asset_type_source", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("classification", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("criticality", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("criticality_reason", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("criticality_updated_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("assets") as batch_op:
        batch_op.drop_column("criticality_updated_at")
        batch_op.drop_column("criticality_reason")
        batch_op.drop_column("criticality")
        batch_op.drop_column("classification")
        batch_op.drop_column("asset_type_source")
