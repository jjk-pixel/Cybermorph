from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.network_connection import NetworkConnection
from app.models.asset import Asset
from app.schemas.network_connection import NetworkConnectionCreate, NetworkConnectionOut

router = APIRouter(prefix="/api/connections", tags=["connections"])

@router.post("/", response_model=NetworkConnectionOut)
def create_connection(conn: NetworkConnectionCreate, db: Session = Depends(get_db)):
    source = db.query(Asset).filter(Asset.id == conn.source_asset_id).first()
    dest = db.query(Asset).filter(Asset.id == conn.destination_asset_id).first()
    if not source or not dest:
        raise HTTPException(status_code=404, detail="Asset source ou destination introuvable")

    db_conn = NetworkConnection(**conn.model_dump())
    db.add(db_conn)
    db.commit()
    db.refresh(db_conn)
    return db_conn

@router.get("/", response_model=list[NetworkConnectionOut])
def list_connections(db: Session = Depends(get_db)):
    return db.query(NetworkConnection).all()

@router.get("/topology")
def get_topology(db: Session = Depends(get_db)):
    """Retourne un format simple nodes/edges, prêt pour la 3D plus tard."""
    assets = db.query(Asset).all()
    connections = db.query(NetworkConnection).all()

    nodes = [
        {
            "id": a.id,
            "name": a.name,
            "ip": a.ip_address,
            "type": a.asset_type,
            "status": a.status,
        }
        for a in assets
    ]
    edges = [
        {
            "source": c.source_asset_id,
            "target": c.destination_asset_id,
            "protocol": c.protocol,
            "port": c.port,
        }
        for c in connections
    ]
    return {"nodes": nodes, "edges": edges}
