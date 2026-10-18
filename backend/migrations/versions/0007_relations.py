"""Lot C — qualité des relations : confiance, fin de validité, preuves, motif de déclaration.

Ajouts uniquement (colonnes nullables). Rétro-remplissage des relations existantes à partir de leur provenance :
flux Suricata 0,9 (valides 24 h après la dernière observation), voisinage ARP 0,5 (30 min), relation « detected »
sans provenance connue 0,4 (antérieure au suivi), déclaration 1,0.

Revision ID: 0007_relations
Revises: 0006_collector_runs
Create Date: 2026-10-18
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0007_relations"
down_revision: Union[str, Sequence[str], None] = "0006_collector_runs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("network_connections") as batch_op:
        batch_op.add_column(sa.Column("confidence", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("evidence", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("note", sa.String(), nullable=True))
    conn = op.get_bind()
    is_pg = conn.dialect.name == "postgresql"
    plus = (lambda col, minutes: f"{col} + interval '{minutes} minutes'") if is_pg else (lambda col, minutes: f"datetime({col}, '+{minutes} minutes')")
    conn.execute(sa.text(
        f"UPDATE network_connections SET confidence = 0.9, valid_until = {plus('last_seen', 1440)} "
        "WHERE connection_type = 'detected' AND source = 'suricata_flow'"))
    conn.execute(sa.text(
        f"UPDATE network_connections SET confidence = 0.5, valid_until = {plus('last_seen', 30)} "
        "WHERE connection_type = 'neighbor_detected'"))
    conn.execute(sa.text(
        "UPDATE network_connections SET confidence = 0.4, note = 'Relation antérieure au suivi de provenance' "
        "WHERE connection_type = 'detected' AND source IS NULL"))
    conn.execute(sa.text("UPDATE network_connections SET confidence = 1.0 WHERE connection_type = 'declared'"))


def downgrade() -> None:
    with op.batch_alter_table("network_connections") as batch_op:
        batch_op.drop_column("note")
        batch_op.drop_column("evidence")
        batch_op.drop_column("valid_until")
        batch_op.drop_column("confidence")
