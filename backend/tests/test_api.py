"""
Lot I — API de bout en bout (requêtes HTTP sur l'application ASGI) : validation stricte, erreurs homogènes,
écritures réservées à la boucle locale sans jeton, jeton exigé s'il est configuré, réponses vides.

Aucune dépendance de test ajoutée : un client ASGI minimal envoie les requêtes ; la base est un SQLite en mémoire
substitué à PostgreSQL (dependency_overrides), jamais la base réelle.
"""
import asyncio
import json
import unittest
from unittest import mock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.security as security
from app.database import Base, get_db
from app.main import app
from app.models.asset import Asset


def call(method: str, path: str, body=None, client_host: str = "127.0.0.1", headers: dict | None = None) -> tuple[int, object]:
    """Une requête HTTP à l'application ASGI ; retourne (statut, corps JSON)."""
    raw_path, _, query = path.partition("?")
    payload = json.dumps(body).encode() if body is not None else b""
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method, "scheme": "http",
        "path": raw_path, "raw_path": raw_path.encode(), "query_string": query.encode(), "root_path": "",
        "headers": [(b"content-type", b"application/json"), (b"host", b"test")]
                   + [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": (client_host, 50000), "server": ("test", 80),
    }
    messages = [{"type": "http.request", "body": payload, "more_body": False}]
    sent = []

    async def receive():
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    try:
        asyncio.run(app(scope, receive, send))
    except Exception:  # noqa: BLE001 — Starlette relance l'exception après avoir envoyé la réponse 500
        pass
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    data = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, json.loads(data) if data else None


class ApiTestCase(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.factory = sessionmaker(bind=engine)
        db = self.factory()
        db.add(Asset(id=1, name="a", ip_address="10.0.0.1", asset_type="pc", status="up"))
        db.add(Asset(id=2, name="b", ip_address="10.0.0.2", asset_type="server", status="up"))
        db.commit()
        db.close()

        def override():
            session = self.factory()
            try:
                yield session
            finally:
                session.close()
        app.dependency_overrides[get_db] = override
        self.addCleanup(app.dependency_overrides.clear)


class ValidationTest(ApiTestCase):
    def test_invalid_inputs_are_rejected_with_422(self):
        cases = [
            ("PATCH", "/api/assets/1", {"criticality": "extreme"}),
            ("PATCH", "/api/assets/1", {"asset_type": "toaster"}),
            ("POST", "/api/connections/", {"source_asset_id": 1, "destination_asset_id": 2, "connection_type": "detected", "reason": "faux"}),
            ("POST", "/api/connections/", {"source_asset_id": 1, "destination_asset_id": 1, "reason": "boucle"}),
            ("POST", "/api/simulations/", {"name": ""}),
            ("PATCH", "/api/vulnerabilities/1", {"status": "probable", "note": "pas une décision"}),
            ("GET", "/api/alerts/?limit=0", None),
            ("GET", "/api/alerts/?limit=5000", None),
            ("GET", "/api/changes/?min_severity=critical", None),
            ("GET", "/api/attack-paths/?max_length=50", None),
            ("GET", "/api/correlations/?kind=causal", None),
        ]
        for method, path, body in cases:
            status, data = call(method, path, body)
            self.assertEqual(status, 422, (method, path, body, data))
            self.assertIn("detail", data)

    def test_invalid_hypothesis(self):
        status, sim = call("POST", "/api/simulations/", {"name": "essai"})
        self.assertEqual(status, 200)
        for hypothesis in ({"type": "asset_compromised"}, {"type": "meteor_strike", "asset_id": 1},
                           {"type": "asset_compromised", "asset_id": -3}, {"type": "asset_compromised", "asset_id": 1, "extra": 1}):
            status, _ = call("POST", f"/api/simulations/{sim['id']}/hypothesis", hypothesis)
            self.assertEqual(status, 422, hypothesis)
        status, data = call("POST", f"/api/simulations/{sim['id']}/hypothesis", {"type": "asset_compromised", "asset_id": 99})
        self.assertEqual((status, data["detail"]), (404, "Asset #99 introuvable dans le graphe"))

    def test_not_found_is_json(self):
        self.assertEqual(call("GET", "/api/assets/999"), (404, {"detail": "Asset introuvable"}))
        self.assertEqual(call("GET", "/api/correlations/5")[0], 404)


class EmptyResponsesTest(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        factory = sessionmaker(bind=engine)

        def override():
            session = factory()
            try:
                yield session
            finally:
                session.close()
        app.dependency_overrides[get_db] = override
        self.addCleanup(app.dependency_overrides.clear)

    def test_empty_database_gives_empty_but_valid_answers(self):
        for path, expected in (("/api/correlations/", []), ("/api/vulnerabilities/", []), ("/api/alerts/", []),
                               ("/api/connections/", []), ("/api/attack-techniques/observed", [])):
            self.assertEqual(call("GET", path), (200, expected), path)
        status, health = call("GET", "/api/system/health")
        self.assertEqual((status, health["status"]), (200, "failing"))  # aucun cycle : pas « tout va bien »
        status, paths = call("GET", "/api/attack-paths/")
        self.assertEqual((status, paths["count"]), (200, 0))


class AccessControlTest(ApiTestCase):
    def test_writes_without_token_are_local_only(self):
        body = {"criticality": "high", "criticality_reason": "Serveur de fichiers"}
        status, data = call("PATCH", "/api/assets/1", body, client_host="192.168.43.50")
        self.assertEqual(status, 403)
        self.assertIn("machine locale", data["detail"])
        self.assertEqual(call("GET", "/api/assets/1", client_host="192.168.43.50")[0], 200)  # lecture autorisée
        status, data = call("PATCH", "/api/assets/1", body, client_host="127.0.0.1")
        self.assertEqual((status, data["criticality"]), (200, "high"))

    def test_forwarded_header_does_not_bypass(self):
        status, _ = call("PATCH", "/api/assets/1", {"criticality": "low"}, client_host="10.9.9.9",
                         headers={"X-Forwarded-For": "127.0.0.1"})
        self.assertEqual(status, 403)

    def test_token_is_required_when_configured(self):
        with mock.patch.object(security, "API_TOKEN", "s3cret-token"):
            self.assertEqual(call("GET", "/api/assets/")[0], 401)
            self.assertEqual(call("GET", "/api/assets/", headers={"Authorization": "Bearer wrong"})[0], 401)
            self.assertEqual(call("GET", "/api/assets/", headers={"Authorization": "Bearer s3cret-token"})[0], 200)
            # Avec un jeton valide, l'écriture est possible depuis le réseau
            status, _ = call("PATCH", "/api/assets/1", {"criticality": "low"}, client_host="192.168.43.50",
                             headers={"Authorization": "Bearer s3cret-token"})
            self.assertEqual(status, 200)
            self.assertEqual(call("GET", "/api/health")[0], 200)  # vivacité publique

    def test_unexpected_error_is_a_clean_json_500(self):
        def broken():
            raise RuntimeError("postgresql://user:password@db/cybermorph injoignable")
            yield  # pragma: no cover
        app.dependency_overrides[get_db] = broken
        status, data = call("GET", "/api/assets/")
        self.assertEqual((status, data), (500, {"detail": "Erreur interne du serveur"}))



class RedactionTest(unittest.TestCase):
    def test_secrets_are_masked_in_logs(self):
        from app.logging_config import describe_exception, redact
        self.assertEqual(redact("échec postgresql://cyber:s3cret@db:5432/x"), "échec postgresql://<identifiants masqués>@db:5432/x")
        self.assertEqual(redact("Authorization: Bearer abc.def-123"), "Authorization: Bearer <masqué>")
        try:
            raise RuntimeError("connexion postgresql://u:p@h/db refusée")
        except RuntimeError as e:
            described = describe_exception(e)
        self.assertNotIn(":p@", described["error"])
        self.assertEqual(described["error_type"], "RuntimeError")


if __name__ == "__main__":
    unittest.main()
