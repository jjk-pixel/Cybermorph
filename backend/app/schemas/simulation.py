from pydantic import BaseModel, ConfigDict, Field
from datetime import datetime
from typing import Annotated, Literal, Optional, Any, Union


class SimulationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=2000)


class AssetCompromised(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["asset_compromised"]
    asset_id: int = Field(gt=0)


class NewServiceExposed(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["new_service_exposed"]
    asset_id: int = Field(gt=0)
    port: Optional[int] = Field(default=None, ge=1, le=65535)


class ConnectionRemoved(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["connection_removed"]
    source_asset_id: int = Field(gt=0)
    destination_asset_id: int = Field(gt=0)


Hypothesis = Annotated[Union[AssetCompromised, NewServiceExposed, ConnectionRemoved], Field(discriminator="type")]


class SimulationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: Optional[str]
    status: str
    hypothesis: Optional[Any] = None
    result: Optional[Any] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
