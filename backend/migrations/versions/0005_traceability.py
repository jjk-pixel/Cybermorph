"""Lot 4 — preuves sources des alertes et état complet (topologie, actifs) dans les snapshots.

Ajouts uniquement : colonnes JSON nullables ; les snapshots existants gardent leur résumé.

Revision ID: 0005_traceability
Revises: 0004_behavior
Create Date: 2026-10-18
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0005_traceability"
down_revision: Union[str, Sequence[str], None] = "0004_behavior"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("alerts") as batch_op:
        batch_op.add_column(sa.Column("evidence", sa.JSON(), nullable=True))
    with op.batch_alter_table("snapshots") as batch_op:
        batch_op.add_column(sa.Column("state", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("snapshots") as batch_op:
        batch_op.drop_column("state")
    with op.batch_alter_table("alerts") as batch_op:
        batch_op.drop_column("evidence")
