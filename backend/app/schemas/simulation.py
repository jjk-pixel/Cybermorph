from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Any


class SimulationCreate(BaseModel):
    name: str
    description: Optional[str] = None


class SimulationOut(BaseModel):
    id: int
    name: str
    description: Optional[str]
    status: str
    hypothesis: Optional[Any] = None
    result: Optional[Any] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True
