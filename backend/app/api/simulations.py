from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.simulation import Simulation
from app.schemas.simulation import SimulationCreate, SimulationOut
from datetime import datetime, UTC
from app.simulation.simulation_engine import run_what_if, HYPOTHESIS_TYPES

router = APIRouter(prefix="/api/simulations", tags=["simulations"])


@router.post("/", response_model=SimulationOut)
def create_simulation(sim: SimulationCreate, db: Session = Depends(get_db)):
    db_sim = Simulation(
        name=sim.name,
        description=sim.description,
        status="created",
    )
    db.add(db_sim)
    db.commit()
    db.refresh(db_sim)
    return db_sim


@router.get("/", response_model=list[SimulationOut])
def list_simulations(db: Session = Depends(get_db)):
    return db.query(Simulation).order_by(Simulation.created_at.desc()).all()


@router.get("/hypothesis-types")
def list_hypothesis_types():
    return HYPOTHESIS_TYPES


@router.get("/{simulation_id}", response_model=SimulationOut)
def get_simulation(simulation_id: int, db: Session = Depends(get_db)):
    sim = db.query(Simulation).filter(Simulation.id == simulation_id).first()
    if not sim:
        raise HTTPException(status_code=404, detail="Simulation introuvable")
    return sim


@router.post("/{simulation_id}/hypothesis")
def apply_simulation_hypothesis(simulation_id: int, hypothesis: dict, db: Session = Depends(get_db)):
    sim = db.query(Simulation).filter(Simulation.id == simulation_id).first()
    if not sim:
        raise HTTPException(status_code=404, detail="Simulation introuvable")

    if hypothesis.get("type") not in HYPOTHESIS_TYPES:
        raise HTTPException(status_code=400, detail=f"Type d'hypothèse invalide. Valeurs possibles : {list(HYPOTHESIS_TYPES.keys())}")

    try:
        result = run_what_if(db, hypothesis)
    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"Champ manquant dans l'hypothèse : {e}")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    sim.hypothesis = hypothesis
    sim.result = result
    sim.status = "completed"
    sim.completed_at = datetime.now(UTC)
    db.commit()
    db.refresh(sim)

    return {"status": "completed", "summary": {
        "paths_before": result["paths_before_count"],
        "paths_after": result["paths_after_count"],
        "new_paths": result["new_paths_count"],
        "escalated_paths": result.get("escalated_paths_count", 0),
    }}


@router.get("/{simulation_id}/result")
def get_simulation_result(simulation_id: int, db: Session = Depends(get_db)):
    sim = db.query(Simulation).filter(Simulation.id == simulation_id).first()
    if not sim:
        raise HTTPException(status_code=404, detail="Simulation introuvable")
    if sim.status != "completed":
        raise HTTPException(status_code=400, detail=f"Simulation non terminée (status: {sim.status})")

    return {
        "simulation_id": sim.id,
        "name": sim.name,
        "hypothesis": sim.hypothesis,
        "result": sim.result,
        "completed_at": sim.completed_at,
    }
