import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from app import models  # noqa: F401  (enregistre toutes les tables)
from app.api import assets, network_connections, attack_paths, alerts, attack_techniques, simulations, timeline, live, incidents, exposure, inventory, behavior, history, trace, vulnerabilities, correlations, system
from fastapi.middleware.cors import CORSMiddleware
from app.security import TokenAuthMiddleware, CORS_ORIGINS
from app.logging_config import describe_exception

# Le schéma est géré par Alembic (`alembic upgrade head` depuis backend/), plus par create_all.

app = FastAPI(
    title="CYBERMORPH",
    description="Cybersecurity Network Digital Twin",
    version="0.4.0"
)
logger = logging.getLogger("cybermorph.api")


@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception):
    """Erreur inattendue : réponse JSON homogène, sans trace ni détail interne ; le détail reste dans le journal."""
    logger.error("api_error", extra={"path": request.url.path, "method": request.method, **describe_exception(exc)})
    return JSONResponse({"detail": "Erreur interne du serveur"}, status_code=500)


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
app.include_router(inventory.router)
app.include_router(behavior.router)
app.include_router(history.router)
app.include_router(trace.router)
app.include_router(vulnerabilities.router)
app.include_router(correlations.router)
app.include_router(system.router)

@app.get("/")
def root():
    return {
        "project": "CYBERMORPH",
        "status": "online",
        "version": "0.4.0"
    }

@app.get("/api/health")
def health():
    """Vivacité de l'API seulement (route publique). La santé de la collecte est servie par /api/system/health."""
    return {"status": "healthy", "scope": "api", "collection_health": "/api/system/health"}
