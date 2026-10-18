from fastapi import FastAPI
from app import models  # noqa: F401  (enregistre toutes les tables)
from app.api import assets, network_connections, attack_paths, alerts, attack_techniques, simulations, timeline, live, incidents, exposure
from fastapi.middleware.cors import CORSMiddleware
from app.security import TokenAuthMiddleware, CORS_ORIGINS

# Le schéma est géré par Alembic (`alembic upgrade head` depuis backend/), plus par create_all.

app = FastAPI(
    title="CYBERMORPH",
    description="Cybersecurity Network Digital Twin",
    version="0.4.0"
)
app.add_middleware(TokenAuthMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,  # origines du frontend (CYBERMORPH_CORS_ORIGINS), jamais "*"
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(assets.router)
app.include_router(network_connections.router)
app.include_router(attack_paths.router)
app.include_router(alerts.router)
app.include_router(attack_techniques.router)
app.include_router(simulations.router)
app.include_router(timeline.router)
app.include_router(live.router)
app.include_router(incidents.router)
app.include_router(exposure.router)

@app.get("/")
def root():
    return {
        "project": "CYBERMORPH",
        "status": "online",
        "version": "0.4.0"
    }

@app.get("/api/health")
def health():
    return {"status": "healthy"}
