from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.exposure.exposure_engine import DEFAULT_MAX_LENGTH, DEFAULT_MIN_SCORE, analyze_exposure, blast_radius

router = APIRouter(prefix="/api/exposure", tags=["exposure"])


@router.get("/")
def get_exposure(
    db: Session = Depends(get_db),
    min_score: float = Query(DEFAULT_MIN_SCORE, ge=0, le=100),
    max_length: int = Query(DEFAULT_MAX_LENGTH, ge=1, le=6),
):
    """Cibles critiques, points d'entrée qualifiés, points de blocage et recommandations chiffrées."""
    return analyze_exposure(db, min_score=min_score, max_length=max_length)


@router.get("/blast-radius/{asset_id}")
def get_blast_radius(
    asset_id: int,
    db: Session = Depends(get_db),
    max_length: int = Query(DEFAULT_MAX_LENGTH, ge=1, le=6),
):
    result = blast_radius(db, asset_id, max_length=max_length)
    if result is None:
        raise HTTPException(status_code=404, detail="Asset introuvable")
    return result
