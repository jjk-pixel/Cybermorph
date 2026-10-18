import math
from sqlalchemy.orm import Session
from app.models.alert import Alert

# Poids de sévérité selon la priorité Suricata (1 = le plus sévère)
SEVERITY_WEIGHTS = {1: 40, 2: 25, 3: 10, 4: 5}


def get_alerts_for_pair(db: Session, source_ip: str, destination_ip: str) -> list[Alert]:
    """
    Récupère toutes les alertes Suricata correspondant à cette paire précise,
    dans le même sens que la transition d'attaque évaluée (source -> destination).
    """
    return (
        db.query(Alert)
        .filter(Alert.source_ip == source_ip, Alert.destination_ip == destination_ip)
        .all()
    )


def compute_alert_score(alerts: list[Alert]) -> tuple[float, dict | None]:
    """
    Calcule un score de corroboration (0-60) basé sur :
    - la sévérité de l'alerte la plus grave observée sur cette paire
    - la fréquence cumulée (occurrence_count), avec une échelle logarithmique
      pour qu'une alerte répétée 10x pèse plus qu'une alerte isolée, sans
      qu'une alerte répétée 10000x n'écrase totalement le reste du calcul.

    Retourne (score, résumé) où résumé contient le détail explicatif,
    ou (0.0, None) si aucune alerte ne corrobore cette transition.
    """
    if not alerts:
        return 0.0, None

    # Une alerte sans priorité est traitée comme la moins sévère, plutôt que de faire échouer le calcul
    highest_priority = min((a.priority for a in alerts if a.priority is not None), default=4)
    total_occurrences = sum(a.occurrence_count or 0 for a in alerts)

    severity_weight = SEVERITY_WEIGHTS.get(highest_priority, 5)
    frequency_weight = min(math.log10(total_occurrences + 1) * 10, 30)

    score = round(min(severity_weight + frequency_weight, 60), 1)

    top_alert = min(alerts, key=lambda a: a.priority or 99)
    summary = {
        "message": top_alert.message,
        "priority": top_alert.priority,
        "total_occurrences": total_occurrences,
        "alert_count": len(alerts),
        "score_contribution": score,
    }

    return score, summary
