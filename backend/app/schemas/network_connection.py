from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class NetworkConnectionBase(BaseModel):
    source_asset_id: int
    destination_asset_id: int
    protocol: Optional[str] = None
    port: Optional[int] = None
    connection_type: Optional[str] = "detected"
    status: Optional[str] = "active"

class NetworkConnectionCreate(NetworkConnectionBase):
    pass

class NetworkConnectionOut(NetworkConnectionBase):
    id: int
    last_seen: datetime
    created_at: datetime

    class Config:
        from_attributes = True
