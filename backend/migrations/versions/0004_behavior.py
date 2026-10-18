"""Lot 3 — activités observées (flux Suricata), écarts à la référence, provenance des relations.

Ajouts : tables `communications` et `deviations`, colonne `network_connections.source`.
Renommage sans perte : `assets.authorization` → `authorization_status` (mot réservé PostgreSQL).

Revision ID: 0004_behavior
Revises: 0003_inventory
Create Date: 2026-10-18
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0004_behavior"
down_revision: Union[str, Sequence[str], None] = "0003_inventory"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "communications",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("src_ip", sa.String(), nullable=False),
        sa.Column("dst_key", sa.String(), nullable=False),
        sa.Column("dst_scope", sa.String(), nullable=False),
        sa.Column("src_asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=True),
        sa.Column("dst_asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=True),
        sa.Column("proto", sa.String(), nullable=False),
        sa.Column("dst_port", sa.Integer(), nullable=False),
        sa.Column("app_proto", sa.String(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("flow_count", sa.Integer(), nullable=False),
        sa.Column("established_count", sa.Integer(), nullable=False),
        sa.Column("bytes_toserver", sa.BigInteger(), nullable=False),
        sa.Column("bytes_toclient", sa.BigInteger(), nullable=False),
        sa.Column("baseline_state", sa.String(), nullable=False),
        sa.Column("learned_via", sa.String(), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.UniqueConstraint("src_ip", "dst_key", "proto", "dst_port", "app_proto", name="uq_communication"),
    )
    op.create_index("ix_communications_assets", "communications", ["src_asset_id", "dst_asset_id"])

    op.create_table(
        "deviations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("src_ip", sa.String(), nullable=True),
        sa.Column("dst_ip", sa.String(), nullable=True),
        sa.Column("src_asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=True),
        sa.Column("dst_asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=True),
        sa.Column("communication_id", sa.Integer(), sa.ForeignKey("communications.id"), nullable=True),
        sa.Column("explanation", sa.String(), nullable=False),
        sa.Column("reasons", sa.JSON(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("occurrences", sa.Integer(), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_deviations_status", "deviations", ["status", "last_seen"])

    with op.batch_alter_table("network_connections") as batch_op:
        batch_op.add_column(sa.Column("source", sa.String(), nullable=True))
    with op.batch_alter_table("assets") as batch_op:
        batch_op.alter_column("authorization", new_column_name="authorization_status")


def downgrade() -> None:
    with op.batch_alter_table("assets") as batch_op:
        batch_op.alter_column("authorization_status", new_column_name="authorization")
    with op.batch_alter_table("network_connections") as batch_op:
        batch_op.drop_column("source")
    op.drop_index("ix_deviations_status", table_name="deviations")
    op.drop_table("deviations")
    op.drop_index("ix_communications_assets", table_name="communications")
    op.drop_table("communications")
