import json
from datetime import datetime, UTC
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.database import get_db
from app.models.asset import Asset
from app.schemas.asset import AssetCreate, AssetDeclaration, AssetOut
from app.risk.risk_engine import calculate_risk

router = APIRouter(prefix="/api/assets", tags=["assets"])

@router.post("/", response_model=AssetOut)
def create_asset(asset: AssetCreate, db: Session = Depends(get_db)):
    db_asset = Asset(**asset.model_dump())
    db.add(db_asset)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Un asset avec cette IP existe déjà")
    db.refresh(db_asset)
    return db_asset

@router.get("/", response_model=list[AssetOut])
def list_assets(db: Session = Depends(get_db)):
    return db.query(Asset).all()

@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset introuvable")
    return asset


@router.patch("/{asset_id}", response_model=AssetOut)
def declare_asset_attributes(asset_id: int, declaration: AssetDeclaration, db: Session = Depends(get_db)):
    """Déclare (ou retire) la criticité et le type d'un actif ; une déclaration n'est jamais écrasée par un scan."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset introuvable")
    provided = declaration.model_fields_set

    if "criticality" in provided:
        asset.criticality = declaration.criticality
        asset.criticality_reason = (declaration.criticality_reason or None) if declaration.criticality else None
        asset.criticality_updated_at = datetime.now(UTC)
    elif "criticality_reason" in provided and asset.criticality:
        asset.criticality_reason = declaration.criticality_reason or None

    if "asset_type" in provided:
        if declaration.asset_type:
            asset.asset_type = declaration.asset_type
            asset.asset_type_source = "declared"
        else:
            asset.asset_type_source = None
            inferred = (asset.classification or {}).get("type")
            if inferred:
                asset.asset_type = inferred

    # Le score de risque dépend de la criticité : recalcul immédiat plutôt qu'au prochain cycle
    result = calculate_risk(asset)
    asset.risk_score = result["risk_score"]
    asset.risk_factors = json.dumps(result, ensure_ascii=False, default=str)
    db.commit()
    db.refresh(asset)
    return asset
