"""
Criticité des actifs : DÉCLARÉE par l'opérateur, sinon INFÉRÉE à partir de faits observés.

La criticité déclarée prime toujours et n'est jamais modifiée par un scan. La criticité inférée est recalculée à
chaque lecture, publiée avec ses raisons et une confiance, pour que l'opérateur puisse la confirmer ou la corriger.

Calibrage : les points apportés au score de risque (critère « criticité », 20 points au maximum) reprennent
exactement l'ancienne échelle par type (routeur 20, serveur 15, poste 5, inconnu 0). Tant que rien n'est déclaré,
les scores existants ne changent donc pas.
"""
from app.inventory.classification import database_ports, parse_list, parse_ports

LEVELS = ["low", "medium", "high", "critical"]
LEVEL_LABEL = {"low": "faible", "medium": "moyenne", "high": "élevée", "critical": "critique"}
LEVEL_POINTS = {"low": 0, "medium": 5, "high": 15, "critical": 20}

# Les cibles des chemins d'attaque : actifs dont la criticité atteint ce niveau
TARGET_LEVELS = ("high", "critical")

TYPE_BASELINE = {
    "router": ("critical", "Équipement réseau : le trafic des autres actifs y transite"),
    "firewall": ("critical", "Pare-feu : contrôle les flux entre segments"),
    "server": ("high", "Serveur exposant des services"),
    "pc": ("medium", "Poste de travail"),
    "iot": ("medium", "Objet connecté"),
}


def level_index(level: str) -> int:
    return LEVELS.index(level) if level in LEVELS else 0


def infer_criticality(
    asset_type: str, open_ports: list[int], services: list[str], type_confidence: float | None, roles: list[dict] | None = None,
) -> dict:
    level, reason = TYPE_BASELINE.get(asset_type, ("low", "Type non identifié"))
    reasons = [reason]
    # La criticité inférée du type ne peut pas être plus sûre que la classification qui la fonde
    confidence = type_confidence if type_confidence is not None else 0.5

    gateway = next((r for r in roles or [] if r.get("role") == "gateway"), None)
    if gateway:
        if level_index(level) < level_index("critical"):
            level = "critical"
        reasons.append("Passerelle par défaut du segment (table de routage)")
        confidence = max(confidence, gateway.get("confidence", 0.9))

    db = database_ports(open_ports, services)
    if db:
        reasons.append(f"Héberge une base de données : {', '.join(db)}")
        if level_index(level) < level_index("high"):
            level = "high"
        # Fait observé directement (port ouvert) : plus sûr que le rôle deviné
        confidence = max(confidence, 0.7)

    return {"level": level, "source": "inferred", "confidence": round(confidence, 2), "reasons": reasons}


def effective_criticality(asset) -> dict:
    """Criticité retenue pour un actif ORM : déclarée si elle existe, sinon inférée."""
    declared = getattr(asset, "criticality", None)
    if declared in LEVELS:
        reason = getattr(asset, "criticality_reason", None) or "Déclarée par l'opérateur"
        return {"level": declared, "source": "declared", "confidence": 1.0, "reasons": [reason]}

    classification = getattr(asset, "classification", None) or {}
    type_confidence = classification.get("confidence") if isinstance(classification, dict) else None
    if getattr(asset, "asset_type_source", None) == "declared":
        type_confidence = 1.0
    roles = classification.get("roles") if isinstance(classification, dict) else None
    return infer_criticality(asset.asset_type, parse_ports(asset.open_ports), parse_list(asset.services), type_confidence, roles)


def is_target_level(level: str | None) -> bool:
    return level in TARGET_LEVELS
