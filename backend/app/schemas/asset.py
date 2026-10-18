from pydantic import BaseModel
from datetime import datetime
from typing import Optional

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

    class Config:
        from_attributes = True
