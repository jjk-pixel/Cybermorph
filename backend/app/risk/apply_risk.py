import json
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.asset import Asset
from app.risk.risk_engine import calculate_risk, format_risk_summary
from app.risk.signals import collect_signals


def apply_risk_scoring():
    db: Session = SessionLocal()
    try:
        assets = db.query(Asset).all()
        print(f"[CYBERMORPH][Risk] Calcul du risque pour {len(assets)} asset(s)...")

        signals = collect_signals(db)
        for asset in assets:
            result = calculate_risk(asset, signals.get(asset.id))
            asset.risk_score = result["risk_score"]
            asset.risk_factors = json.dumps(result, ensure_ascii=False)
            print(format_risk_summary(asset.name, result))

        db.commit()
    finally:
        db.close()

    print("[CYBERMORPH][Risk] Scoring terminé.")


if __name__ == "__main__":
    apply_risk_scoring()
