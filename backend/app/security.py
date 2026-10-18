"""
Contrôle d'accès minimal de l'API CYBERMORPH.

- Si CYBERMORPH_API_TOKEN est défini, toute requête /api/* et toute connexion /ws/*
  doit présenter ce jeton (en-tête `Authorization: Bearer <jeton>`, ou `?token=` pour
  les WebSockets dont les navigateurs ne permettent pas de fixer les en-têtes).
- Sans jeton configuré, l'API reste en mode lab : elle doit alors être lancée sur
  127.0.0.1 uniquement (voir README), jamais exposée sur le réseau. Même dans ce mode, les opérations
  sensibles (écritures : déclarations, relations, décisions, simulations, acquittements) ne sont acceptées que
  depuis la boucle locale — le proxy Vite, qui tourne sur la même machine, en fait partie.
"""
import hmac
import os

from dotenv import load_dotenv
from fastapi import Request, WebSocket
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

load_dotenv()

API_TOKEN = os.getenv("CYBERMORPH_API_TOKEN") or None

# Origines autorisées pour CORS (le frontend passe normalement par le proxy Vite, même origine)
CORS_ORIGINS = [
    o.strip()
    for o in os.getenv("CYBERMORPH_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
    if o.strip()
]

PUBLIC_PATHS = {"/", "/api/health"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _token_matches(candidate: str | None) -> bool:
    return bool(candidate) and hmac.compare_digest(candidate, API_TOKEN)


def _bearer(value: str | None) -> str | None:
    if value and value.lower().startswith("bearer "):
        return value[7:].strip()
    return None


def _is_loopback(request: Request) -> bool:
    # L'adresse de la connexion TCP, jamais un en-tête X-Forwarded-For (falsifiable)
    return bool(request.client) and request.client.host in LOOPBACK_HOSTS


class TokenAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path.startswith("/api") and path not in PUBLIC_PATHS and request.method != "OPTIONS":
            if API_TOKEN:
                if not _token_matches(_bearer(request.headers.get("authorization"))):
                    return JSONResponse({"detail": "Authentification requise"}, status_code=401)
            elif request.method in WRITE_METHODS and not _is_loopback(request):
                return JSONResponse(
                    {"detail": "Opération d'écriture refusée : sans CYBERMORPH_API_TOKEN, elle n'est acceptée que depuis la machine locale"},
                    status_code=403,
                )
        return await call_next(request)


def websocket_authorized(websocket: WebSocket) -> bool:
    if not API_TOKEN:
        return True
    candidate = _bearer(websocket.headers.get("authorization")) or websocket.query_params.get("token")
    return _token_matches(candidate)
