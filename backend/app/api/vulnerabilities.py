from datetime import datetime, UTC
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.vulnerability import VulnerabilityFinding
from app.vulnerabilities.service import finding_out, software_inventory, sources_status

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


class FindingDecision(BaseModel):
    """Décision de l'opérateur sur une correspondance : la confirmer (vérifiée) ou la rejeter (faux positif)."""
    model_config = ConfigDict(extra="forbid")
    status: Literal["confirmed", "rejected"]
    note: str = Field(min_length=3, max_length=500)


@router.get("/")
def list_findings(
    db: Session = Depends(get_db),
    asset_id: int | None = Query(None, gt=0),
    status: str | None = Query(None, pattern="^(probable|uncertain|confirmed|rejected|not_observed)$"),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    query = db.query(VulnerabilityFinding)
    if asset_id is not None:
        query = query.filter(VulnerabilityFinding.asset_id == asset_id)
    if status:
        query = query.filter(VulnerabilityFinding.status == status)
    rows = query.order_by(VulnerabilityFinding.cvss_score.desc().nullslast(), VulnerabilityFinding.id).offset(offset).limit(limit).all()
    return [finding_out(f) for f in rows]


@router.get("/software")
def list_software(db: Session = Depends(get_db)):
    """Logiciels identifiés (Nmap -sV) : seuls ceux qui ont un CPE peuvent être rapprochés d'une CVE."""
    return software_inventory(db)


@router.get("/sources")
def get_sources(db: Session = Depends(get_db)):
    return sources_status(db)


@router.patch("/{finding_id}")
def decide_finding(finding_id: int, decision: FindingDecision, db: Session = Depends(get_db)):
    finding = db.get(VulnerabilityFinding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Correspondance introuvable")
    finding.status = decision.status
    finding.status_reason = "Confirmée par l'opérateur" if decision.status == "confirmed" else "Rejetée par l'opérateur (faux positif)"
    finding.validated_at = datetime.now(UTC)
    finding.validated_note = decision.note
    db.commit()
    db.refresh(finding)
    return finding_out(finding)
