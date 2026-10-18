"""
Contrôle d'accès minimal de l'API CYBERMORPH.

- Si CYBERMORPH_API_TOKEN est défini, toute requête /api/* et toute connexion /ws/*
  doit présenter ce jeton (en-tête `Authorization: Bearer <jeton>`, ou `?token=` pour
  les WebSockets dont les navigateurs ne permettent pas de fixer les en-têtes).
- Sans jeton configuré, l'API reste en mode lab : elle doit alors être lancée sur
  127.0.0.1 uniquement (voir README), jamais exposée sur le réseau.
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


def _token_matches(candidate: str | None) -> bool:
    return bool(candidate) and hmac.compare_digest(candidate, API_TOKEN)


def _bearer(value: str | None) -> str | None:
    if value and value.lower().startswith("bearer "):
        return value[7:].strip()
    return None


class TokenAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if API_TOKEN and request.url.path.startswith("/api") and request.url.path not in PUBLIC_PATHS:
            if request.method != "OPTIONS" and not _token_matches(_bearer(request.headers.get("authorization"))):
                return JSONResponse({"detail": "Authentification requise"}, status_code=401)
        return await call_next(request)


def websocket_authorized(websocket: WebSocket) -> bool:
    if not API_TOKEN:
        return True
    candidate = _bearer(websocket.headers.get("authorization")) or websocket.query_params.get("token")
    return _token_matches(candidate)
