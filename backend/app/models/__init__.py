"""Import de tous les modèles : Base.metadata est alors complet (API, Alembic, tests)."""
from app.models import (  # noqa: F401
    alert, asset, attack_path_step, attack_technique, incident, network_connection, simulation, snapshot,
)
