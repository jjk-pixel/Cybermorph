"""Lot 2 — journal d'observations, changements d'inventaire, réglages durables, autorisation et drapeau scanner.

Ajouts uniquement : nouvelles tables et colonnes nullables sur `assets`.

Revision ID: 0003_inventory
Revises: 0002_asset_exposure
Create Date: 2026-10-18
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0003_inventory"
down_revision: Union[str, Sequence[str], None] = "0002_asset_exposure"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "asset_observations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=True),
        sa.Column("ip", sa.String(), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("attribute", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("seen_count", sa.Integer(), nullable=False),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("ip", "source", "attribute", "value", name="uq_observation"),
    )
    op.create_index("ix_asset_observations_asset", "asset_observations", ["asset_id", "attribute"])

    op.create_table(
        "asset_changes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=True),
        sa.Column("ip", sa.String(), nullable=True),
        sa.Column("change_type", sa.String(), nullable=False),
        sa.Column("attribute", sa.String(), nullable=True),
        sa.Column("old_value", sa.String(), nullable=True),
        sa.Column("new_value", sa.String(), nullable=True),
        sa.Column("source", sa.String(), nullable=True),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("explanation", sa.String(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_asset_changes_asset_id", "asset_changes", ["asset_id"])
    op.create_index("ix_asset_changes_detected", "asset_changes", ["detected_at"])

    op.create_table(
        "cybermorph_settings",
        sa.Column("key", sa.String(), primary_key=True),
        sa.Column("value", sa.JSON(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
    )

    with op.batch_alter_table("assets") as batch_op:
        batch_op.add_column(sa.Column("authorization", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("authorization_source", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("is_scanner", sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column("scanner_reason", sa.String(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("assets") as batch_op:
        batch_op.drop_column("scanner_reason")
        batch_op.drop_column("is_scanner")
        batch_op.drop_column("authorization_source")
        batch_op.drop_column("authorization")
    op.drop_table("cybermorph_settings")
    op.drop_index("ix_asset_changes_detected", table_name="asset_changes")
    op.drop_index("ix_asset_changes_asset_id", table_name="asset_changes")
    op.drop_table("asset_changes")
    op.drop_index("ix_asset_observations_asset", table_name="asset_observations")
    op.drop_table("asset_observations")
