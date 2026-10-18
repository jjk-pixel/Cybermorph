from pydantic import BaseModel
from datetime import datetime
from typing import Literal, Optional

class AssetBase(BaseModel):
    name: str
    hostname: Optional[str] = None
    ip_address: str
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    asset_type: str
    os_detected: Optional[str] = None
    open_ports: Optional[str] = None
    services: Optional[str] = None
    status: Optional[str] = "unknown"
    risk_score: Optional[float] = 0.0
    zone: Optional[str] = None

class AssetCreate(AssetBase):
    pass

class AssetOut(AssetBase):
    id: int
    risk_factors: Optional[str] = None  # JSON stringifié produit par le moteur de risque
    last_seen: datetime
    created_at: datetime
    updated_at: Optional[datetime] = None
    asset_type_source: Optional[str] = None
    classification: Optional[dict] = None
    criticality: Optional[str] = None
    criticality_reason: Optional[str] = None

    class Config:
        from_attributes = True


CriticalityLevel = Literal["low", "medium", "high", "critical"]
AssetTypeValue = Literal["router", "server", "pc", "iot", "unknown"]


class AssetDeclaration(BaseModel):
    """
    Attributs déclarés par l'opérateur. Seuls les champs présents dans la requête sont modifiés ;
    `null` retire la déclaration et rend la main à l'inférence.
    """
    criticality: Optional[CriticalityLevel] = None
    criticality_reason: Optional[str] = None
    asset_type: Optional[AssetTypeValue] = None
