from pydantic import BaseModel, ConfigDict, Field, model_validator
from datetime import datetime
from typing import Literal, Optional


class NetworkConnectionBase(BaseModel):
    source_asset_id: int
    destination_asset_id: int
    protocol: Optional[str] = None
    port: Optional[int] = None
    connection_type: Optional[str] = "detected"
    status: Optional[str] = "active"


class NetworkConnectionDeclare(BaseModel):
    """
    Relation DÉCLARÉE par l'opérateur. L'API ne permet pas de créer une relation « observée » : seules les sondes
    (Suricata, ARP) en produisent. Le motif est obligatoire, pour que la déclaration reste explicable.
    """
    model_config = ConfigDict(extra="forbid")

    source_asset_id: int = Field(gt=0)
    destination_asset_id: int = Field(gt=0)
    protocol: Optional[Literal["tcp", "udp", "icmp"]] = None
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    reason: str = Field(min_length=3, max_length=500)
    # Compatibilité : accepté seulement s'il vaut « declared »
    connection_type: Optional[Literal["declared"]] = None

    @model_validator(mode="after")
    def check(self):
        if self.source_asset_id == self.destination_asset_id:
            raise ValueError("La source et la destination doivent être deux actifs distincts")
        if self.port is not None and self.protocol not in ("tcp", "udp"):
            raise ValueError("Un port exige le protocole tcp ou udp")
        return self


class NetworkConnectionOut(NetworkConnectionBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    last_seen: datetime
    created_at: datetime
    source: Optional[str] = None
    confidence: Optional[float] = None
    valid_until: Optional[datetime] = None
    evidence: Optional[dict] = None
    note: Optional[str] = None
    relation_class: Optional[str] = None
    stale: Optional[bool] = None
    reason: Optional[str] = None
