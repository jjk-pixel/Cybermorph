import json
from datetime import datetime, timedelta, UTC

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.asset import Asset
from app.models.risk import RiskHistory
from app.risk.risk_engine import calculate_risk, format_risk_summary
from app.risk.signals import collect_signals

HISTORY_HEARTBEAT = timedelta(hours=1)


def record_history(db: Session, asset: Asset, result: dict, now: datetime) -> RiskHistory | None:
    """Ajoute un point d'historique si le score, le niveau ou la confiance changent, ou si le dernier a plus d'une heure."""
    last = (
        db.query(RiskHistory).filter(RiskHistory.asset_id == asset.id)
        .order_by(RiskHistory.computed_at.desc(), RiskHistory.id.desc()).first()
    )
    confidence = result["confidence"]["value"]
    if last is not None:
        last_at = last.computed_at if last.computed_at.tzinfo else last.computed_at.replace(tzinfo=UTC)
        unchanged = (last.score, last.level, last.confidence) == (result["risk_score"], result["risk_level"], confidence)
        if unchanged and now - last_at < HISTORY_HEARTBEAT:
            return None
    entry = RiskHistory(asset_id=asset.id, computed_at=now, score=result["risk_score"], level=result["risk_level"],
                        confidence=confidence, model_version=result["model_version"], breakdown=result["breakdown"])
    db.add(entry)
    return entry


def score_assets(db: Session, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    signals = collect_signals(db, now)
    recorded = 0
    assets = db.query(Asset).all()
    for asset in assets:
        result = calculate_risk(asset, signals.get(asset.id), now)
        asset.risk_score = result["risk_score"]
        asset.risk_factors = json.dumps(result, ensure_ascii=False, default=str)
        if record_history(db, asset, result, now):
            recorded += 1
        print(format_risk_summary(asset.name, result))
    db.flush()
    return {"assets": len(assets), "history_points": recorded}


def apply_risk_scoring() -> dict:
    db: Session = SessionLocal()
    try:
        stats = score_assets(db)
        db.commit()
    finally:
        db.close()
    print("[CYBERMORPH][Risk] Scoring terminé.")
    return stats


if __name__ == "__main__":
    apply_risk_scoring()
