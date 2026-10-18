"""
Qualité des relations de topologie : classe (observée, inférée, déclarée), confiance, période de validité.

- **Observée** : une communication réellement constatée, c'est-à-dire un flux établi vu par Suricata
  (`detected` + `suricata_flow`). Une relation `detected` sans provenance date d'avant ce suivi : on ne sait plus ce
  qui l'a constatée, sa confiance est réduite.
- **Inférée** : le voisinage ARP prouve que deux équipements partagent un segment, pas qu'ils communiquent.
- **Déclarée** : saisie par l'opérateur, avec un motif. Elle vaut tant qu'elle n'est pas retirée.

Une relation n'est jamais déduite de l'appartenance au même sous-réseau. Une relation dont la période de validité est
dépassée est « périmée » : elle reste dans l'historique, mais le graphe ne s'en sert plus.
"""
from datetime import datetime, timedelta, UTC

RELATION_CLASS = {"detected": "observed", "neighbor_detected": "inferred", "inferred": "inferred", "declared": "declared"}

VALIDITY = {
    "suricata_flow": timedelta(hours=24),
    "arp": timedelta(minutes=30),
}

REASONS = {
    "suricata_flow": "Flux établi observé par Suricata (poignée de main complète)",
    "arp": "Voisinage ARP : même segment de niveau 2, communication non démontrée",
    "legacy": "Relation antérieure au suivi de provenance : capteur d'origine inconnu",
    "operator": "Déclarée par l'opérateur",
    "inferred": "Relation inférée",
}


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def provenance_of(conn) -> str:
    if conn.connection_type == "declared":
        return "operator"
    if conn.connection_type == "neighbor_detected":
        return "arp"
    if conn.connection_type == "detected":
        return conn.source or "legacy"
    return conn.source or "inferred"


def assess(conn, now: datetime | None = None) -> dict:
    """Classe, confiance, fin de validité et justification d'une relation (pur, sans accès base)."""
    now = now or datetime.now(UTC)
    origin = provenance_of(conn)
    relation_class = RELATION_CLASS.get(conn.connection_type, "inferred")
    confidence = {"suricata_flow": 0.9, "arp": 0.5, "legacy": 0.4, "operator": 1.0}.get(origin, 0.3)
    last_seen = _utc(conn.last_seen)
    validity = VALIDITY.get(origin)
    valid_until = last_seen + validity if (validity and last_seen) else None
    stale = bool(valid_until and valid_until < now) or conn.status != "active"
    return {
        "relation_class": relation_class,
        "origin": origin,
        "confidence": confidence,
        "valid_from": _utc(getattr(conn, "created_at", None)),
        "valid_until": valid_until,
        "stale": stale,
        "reason": conn.note if origin == "operator" and conn.note else REASONS.get(origin, REASONS["inferred"]),
    }


def refresh_quality(conn, now: datetime | None = None) -> None:
    """Recopie confiance et fin de validité dans la ligne (conservées avec la relation)."""
    quality = assess(conn, now)
    conn.confidence = quality["confidence"]
    conn.valid_until = quality["valid_until"]
