"""Lot I — index des requêtes fréquentes (collecteurs, flux live, graphe, supervision).

Ajout d'index uniquement, aucune donnée modifiée.

Revision ID: 0011_indexes
Revises: 0010_correlation
Create Date: 2026-10-18
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0011_indexes"
down_revision: Union[str, Sequence[str], None] = "0010_correlation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

INDEXES = [
    # Rattachement d'une ligne fast.log à son alerte agrégée (une requête par ligne lue)
    ("ix_alerts_signature_pair", "alerts", ["signature_id", "source_ip", "destination_ip"]),
    ("ix_alerts_pair", "alerts", ["source_ip", "destination_ip"]),
    ("ix_alerts_last_seen", "alerts", ["last_seen"]),
    ("ix_network_connections_pair", "network_connections", ["source_asset_id", "destination_asset_id"]),
    ("ix_network_connections_status", "network_connections", ["status"]),
    ("ix_snapshots_captured_at", "snapshots", ["captured_at"]),
    ("ix_incidents_status_last_seen", "incidents", ["status", "last_seen"]),
    ("ix_alert_technique_mappings_alert", "alert_technique_mappings", ["alert_id"]),
    ("ix_deviations_kind", "deviations", ["kind", "src_ip", "status"]),
]


def upgrade() -> None:
    for name, table, columns in INDEXES:
        op.create_index(name, table, columns)


def downgrade() -> None:
    for name, table, _ in reversed(INDEXES):
        op.drop_index(name, table_name=table)
