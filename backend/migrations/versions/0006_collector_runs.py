"""Lot B — journal des exécutions de collecte et compteur de balayages manqués.

Ajouts uniquement : table `collector_runs`, colonne `assets.missed_scans` (0 par défaut).

Revision ID: 0006_collector_runs
Revises: 0005_traceability
Create Date: 2026-10-18
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0006_collector_runs"
down_revision: Union[str, Sequence[str], None] = "0005_traceability"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "collector_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cycle_id", sa.String(), nullable=True),
        sa.Column("collector", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_s", sa.Float(), nullable=True),
        sa.Column("error", sa.String(), nullable=True),
        sa.Column("stats", sa.JSON(), nullable=True),
    )
    op.create_index("ix_collector_runs_collector", "collector_runs", ["collector", "started_at"])
    op.create_index("ix_collector_runs_cycle_id", "collector_runs", ["cycle_id"])
    with op.batch_alter_table("assets") as batch_op:
        batch_op.add_column(sa.Column("missed_scans", sa.Integer(), nullable=False, server_default="0"))


def downgrade() -> None:
    with op.batch_alter_table("assets") as batch_op:
        batch_op.drop_column("missed_scans")
    op.drop_index("ix_collector_runs_cycle_id", table_name="collector_runs")
    op.drop_index("ix_collector_runs_collector", table_name="collector_runs")
    op.drop_table("collector_runs")
