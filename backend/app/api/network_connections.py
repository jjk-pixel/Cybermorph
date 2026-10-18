from datetime import datetime, UTC

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.asset import Asset
from app.models.network_connection import NetworkConnection
from app.schemas.network_connection import NetworkConnectionDeclare, NetworkConnectionOut
from app.topology.relations import assess, refresh_quality

router = APIRouter(prefix="/api/connections", tags=["connections"])


def connection_out(c: NetworkConnection, now: datetime | None = None) -> NetworkConnectionOut:
    quality = assess(c, now)
    out = NetworkConnectionOut.model_validate(c)
    return out.model_copy(update={
        "relation_class": quality["relation_class"], "stale": quality["stale"], "reason": quality["reason"],
        "confidence": quality["confidence"], "valid_until": quality["valid_until"],
    })


@router.post("/", response_model=NetworkConnectionOut, status_code=201)
def declare_connection(conn: NetworkConnectionDeclare, db: Session = Depends(get_db)):
    """Déclare une relation connue de l'opérateur (flux autorisé, liaison non visible des capteurs…)."""
    source = db.get(Asset, conn.source_asset_id)
    dest = db.get(Asset, conn.destination_asset_id)
    if not source or not dest:
        raise HTTPException(status_code=404, detail="Asset source ou destination introuvable")
    existing = db.query(NetworkConnection).filter(
        NetworkConnection.source_asset_id == conn.source_asset_id,
        NetworkConnection.destination_asset_id == conn.destination_asset_id,
        NetworkConnection.connection_type == "declared", NetworkConnection.status == "active",
        NetworkConnection.protocol == conn.protocol, NetworkConnection.port == conn.port,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Relation déjà déclarée (#{existing.id})")
    now = datetime.now(UTC)
    db_conn = NetworkConnection(
        source_asset_id=conn.source_asset_id, destination_asset_id=conn.destination_asset_id,
        protocol=conn.protocol, port=conn.port, connection_type="declared", status="active",
        source="operator", note=conn.reason, created_at=now, last_seen=now,
    )
    refresh_quality(db_conn, now)
    db.add(db_conn)
    db.commit()
    db.refresh(db_conn)
    return connection_out(db_conn)


@router.delete("/{connection_id}", response_model=NetworkConnectionOut)
def withdraw_connection(connection_id: int, db: Session = Depends(get_db)):
    """Retire une relation déclarée : elle devient inactive (conservée dans l'historique). Les observations ne se retirent pas."""
    conn = db.get(NetworkConnection, connection_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Relation introuvable")
    if conn.connection_type != "declared":
        raise HTTPException(status_code=409, detail="Seule une relation déclarée peut être retirée ; une observation expire d'elle-même")
    conn.status = "inactive"
    db.commit()
    db.refresh(conn)
    return connection_out(conn)


@router.get("/", response_model=list[NetworkConnectionOut])
def list_connections(
    db: Session = Depends(get_db),
    status: str | None = Query(None, pattern="^(active|inactive)$"),
    relation_class: str | None = Query(None, pattern="^(observed|inferred|declared)$"),
    limit: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
):
    query = db.query(NetworkConnection)
    if status:
        query = query.filter(NetworkConnection.status == status)
    now = datetime.now(UTC)
    rows = [connection_out(c, now) for c in query.order_by(NetworkConnection.id).all()]
    if relation_class:
        rows = [r for r in rows if r.relation_class == relation_class]
    return rows[offset: offset + limit]


@router.get("/topology")
def get_topology(db: Session = Depends(get_db)):
    """Nœuds et relations, chacune avec sa classe, sa confiance et sa validité."""
    assets = db.query(Asset).all()
    now = datetime.now(UTC)
    nodes = [{"id": a.id, "name": a.name, "ip": a.ip_address, "type": a.asset_type, "status": a.status} for a in assets]
    edges = []
    for c in db.query(NetworkConnection).order_by(NetworkConnection.id).all():
        q = assess(c, now)
        edges.append({
            "id": c.id, "source": c.source_asset_id, "target": c.destination_asset_id, "protocol": c.protocol,
            "port": c.port, "status": c.status, "relation_class": q["relation_class"], "origin": q["origin"],
            "confidence": q["confidence"], "valid_until": q["valid_until"], "stale": q["stale"], "reason": q["reason"],
        })
    return {"nodes": nodes, "edges": edges}
