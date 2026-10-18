"""
Lot 1 — classification explicable, criticité, exposition (points de blocage, recommandations, rayon d'impact)
et cohérence des migrations Alembic. SQLite en mémoire ou fichier temporaire : PostgreSQL n'est jamais touché.
"""
import json
import tempfile
import unittest
from datetime import datetime, UTC
from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine

from app.database import Base
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.network_connection import NetworkConnection
from app.inventory.classification import classify_asset, classify_sensor_host
from app.collectors.nmap_collector import guess_asset_type
from app.exposure.criticality import effective_criticality, LEVEL_POINTS
from app.exposure.exposure_engine import analyze_exposure, blast_radius, compute_choke_points
from app.attack_graph.graph_engine import build_graph, find_paths_on_graph
from app.risk.risk_engine import calculate_risk
from app.api.assets import declare_asset_attributes
from app.schemas.asset import AssetDeclaration
from tests.test_engines import make_session

BACKEND = Path(__file__).resolve().parents[1]


class ClassificationTest(unittest.TestCase):
    def test_historical_decisions_are_preserved(self):
        # Mêmes décisions que l'ancien guess_asset_type, premier critère prioritaire
        self.assertEqual(guess_asset_type([53], "VMware", ["domain"]), "router")
        self.assertEqual(guess_asset_type([22], "VMware", ["ssh"]), "server")
        self.assertEqual(guess_asset_type([3306], "", ["mysql"]), "server")
        self.assertEqual(guess_asset_type([445], "", []), "pc")
        self.assertEqual(guess_asset_type([], "Cisco Systems", []), "router")
        self.assertEqual(guess_asset_type([], "", []), "unknown")

    def test_contradicting_evidence_lowers_confidence_and_is_published(self):
        alone = classify_asset([3306], ["mysql"], "VMware", None)
        contradicted = classify_asset([3306], ["mysql"], "VMware", "Microsoft Windows 11 21H2")
        self.assertEqual(contradicted["type"], "server")
        self.assertLess(contradicted["confidence"], alone["confidence"])
        self.assertEqual(contradicted["alternatives"][0]["type"], "pc")
        self.assertTrue(any(not r["supports"] for r in contradicted["reasons"]))

    def test_corroborating_evidence_raises_confidence(self):
        dns_only = classify_asset([53], ["domain"], "VMware", None)
        with_os = classify_asset([53], ["domain"], "VMware", "VMware Player virtual NAT device")
        self.assertGreater(with_os["confidence"], dns_only["confidence"])

    def test_os_hint_alone_classifies_but_never_overrides_a_service(self):
        self.assertEqual(classify_asset([], [], None, "Microsoft Windows 10")["type"], "pc")
        self.assertEqual(classify_asset([22], ["ssh"], None, "Microsoft Windows 10")["type"], "server")

    def test_unknown_has_low_confidence_and_a_reason(self):
        result = classify_asset([], [], "VMware", None)
        self.assertEqual(result["type"], "unknown")
        self.assertLessEqual(result["confidence"], 0.3)
        self.assertTrue(result["reasons"])

    def test_sensor_host(self):
        self.assertEqual(classify_sensor_host()["type"], "server")


class CriticalityTest(unittest.TestCase):
    def test_inferred_scale_reproduces_historical_risk_points(self):
        # Ancienne échelle du critère « criticité » : routeur 20, serveur 15, poste 5, inconnu 0
        expected = {"router": 20, "server": 15, "pc": 5, "unknown": 0}
        for asset_type, points in expected.items():
            crit = effective_criticality(Asset(asset_type=asset_type, open_ports="", services=""))
            self.assertEqual(LEVEL_POINTS[crit["level"]], points, asset_type)
            self.assertEqual(crit["source"], "inferred")

    def test_database_hosting_raises_criticality(self):
        crit = effective_criticality(Asset(asset_type="pc", open_ports="5432", services="postgres"))
        self.assertEqual(crit["level"], "high")
        self.assertTrue(any("base de données" in r for r in crit["reasons"]))

    def test_declared_wins(self):
        crit = effective_criticality(Asset(asset_type="router", criticality="low", criticality_reason="Routeur de test"))
        self.assertEqual(crit, {"level": "low", "source": "declared", "confidence": 1.0, "reasons": ["Routeur de test"]})

    def test_declared_criticality_changes_risk(self):
        router = Asset(asset_type="router", open_ports="53", services="domain", status="up", last_seen=datetime.now(UTC))
        before = calculate_risk(router)["risk_score"]
        router.criticality = "low"
        after = calculate_risk(router)
        self.assertAlmostEqual(before - after["risk_score"], 20.0)
        self.assertEqual(after["criticality"]["source"], "declared")


def seed_chain(db):
    """Deux postes (1, 4) → serveur de rebond (2) → base de données (3) ; 5 isolé et non critique."""
    now = datetime.now(UTC)
    db.add_all([
        Asset(id=1, name="poste-a", ip_address="10.0.0.11", asset_type="pc", status="up", risk_score=10, open_ports="445", services="microsoft-ds"),
        Asset(id=4, name="poste-b", ip_address="10.0.0.12", asset_type="pc", status="up", risk_score=10),
        Asset(id=2, name="rebond", ip_address="10.0.0.20", asset_type="server", status="up", risk_score=30, open_ports="22", services="ssh"),
        Asset(id=3, name="bdd", ip_address="10.0.0.30", asset_type="server", status="up", risk_score=40, open_ports="5432", services="postgresql"),
        Asset(id=5, name="capteur", ip_address="10.0.0.99", asset_type="unknown", status="up", risk_score=0),
    ])
    db.add_all([
        NetworkConnection(source_asset_id=1, destination_asset_id=2, protocol="tcp", port=22, connection_type="detected", status="active"),
        NetworkConnection(source_asset_id=4, destination_asset_id=2, protocol="tcp", port=22, connection_type="detected", status="active"),
        NetworkConnection(source_asset_id=2, destination_asset_id=3, protocol="tcp", port=5432, connection_type="detected", status="active"),
    ])
    db.add(Alert(source_ip="10.0.0.11", destination_ip="10.0.0.20", message="ET SCAN Nmap", priority=2,
                 occurrence_count=3, first_seen=now, last_seen=now))
    db.commit()


class ExposureTest(unittest.TestCase):
    def setUp(self):
        self.db = make_session()
        seed_chain(self.db)

    def tearDown(self):
        self.db.close()

    def test_choke_point_is_the_shared_intermediate(self):
        paths = find_paths_on_graph(build_graph(self.db), min_score=0)
        chokes = compute_choke_points(paths)
        self.assertEqual(chokes[0]["asset_id"], 2)
        self.assertEqual(chokes[0]["targets"], [3])
        self.assertEqual(chokes[0]["sources"], [1, 4])

    def test_recommendations_are_counterfactual_and_ranked(self):
        result = analyze_exposure(self.db, min_score=0)
        top = result["recommendations"][0]
        # Couper 2 → 3 (ou isoler 2) protège la base : c'est la mesure la plus efficace
        self.assertIn(3, top["targets_protected"])
        self.assertGreater(top["score_reduction"], 0)
        edge = next(r for r in result["recommendations"] if r["kind"] == "edge" and r["destination_asset_id"] == 3)
        self.assertIn("tcp/5432", edge["action"])
        # Le graphe réel n'est pas modifié par les essais
        self.assertEqual(len(find_paths_on_graph(build_graph(self.db), min_score=0)), result["summary"]["paths"])

    def test_entry_points_are_qualified_by_facts_only(self):
        result = analyze_exposure(self.db, min_score=0)
        entries = {e["asset_id"]: {f["kind"] for f in e["facts"]} for e in result["entry_points"]}
        self.assertEqual(entries[1], {"ids_alert_source", "dangerous_service"})
        self.assertNotIn(4, entries)
        from_4 = next(p for p in result["paths"] if p["source"] == 4)
        self.assertEqual(from_4["entry"][0]["kind"], "assumed")

    def test_declared_low_criticality_removes_a_target(self):
        before = {t["asset_id"] for t in analyze_exposure(self.db, min_score=0)["targets"]}
        self.assertIn(2, before)
        declare_asset_attributes(2, AssetDeclaration(criticality="low"), self.db)
        after = {t["asset_id"] for t in analyze_exposure(self.db, min_score=0)["targets"]}
        self.assertNotIn(2, after)
        self.assertIn(3, after)

    def test_blast_radius(self):
        radius = blast_radius(self.db, 1, max_length=4)
        reached = {r["asset_id"]: r for r in radius["reachable"]}
        self.assertEqual(set(reached), {2, 3})
        self.assertEqual(reached[3]["nodes"], [1, 2, 3])
        self.assertIn(5, radius["unreachable"])
        self.assertIsNone(blast_radius(self.db, 999))


class DeclarationApiTest(unittest.TestCase):
    def setUp(self):
        self.db = make_session()
        seed_chain(self.db)

    def tearDown(self):
        self.db.close()

    def test_declare_then_clear(self):
        out = declare_asset_attributes(3, AssetDeclaration(criticality="critical", criticality_reason="Données clients"), self.db)
        self.assertEqual(out.criticality, "critical")
        self.assertEqual(json.loads(out.risk_factors)["criticality"]["source"], "declared")
        # Champ absent : la déclaration est conservée
        declare_asset_attributes(3, AssetDeclaration(), self.db)
        self.assertEqual(self.db.get(Asset, 3).criticality, "critical")
        # null explicite : retour à l'inférence
        out = declare_asset_attributes(3, AssetDeclaration(criticality=None), self.db)
        self.assertIsNone(out.criticality)
        self.assertIsNone(out.criticality_reason)

    def test_declared_type_is_kept_and_can_be_released(self):
        asset = self.db.get(Asset, 5)
        asset.classification = {"type": "unknown", "confidence": 0.2, "reasons": [], "alternatives": []}
        self.db.commit()
        declare_asset_attributes(5, AssetDeclaration(asset_type="iot"), self.db)
        self.assertEqual((asset.asset_type, asset.asset_type_source), ("iot", "declared"))
        declare_asset_attributes(5, AssetDeclaration(asset_type=None), self.db)
        self.assertEqual((asset.asset_type, asset.asset_type_source), ("unknown", None))


class MigrationTest(unittest.TestCase):
    def test_upgrade_head_matches_models(self):
        with tempfile.TemporaryDirectory() as tmp:
            url = f"sqlite:///{tmp}/schema.db"
            cfg = Config(str(BACKEND / "alembic.ini"))
            cfg.set_main_option("script_location", str(BACKEND / "migrations"))
            cfg.set_main_option("sqlalchemy.url", url)
            command.upgrade(cfg, "head")
            engine = create_engine(url)
            with engine.connect() as conn:
                diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
            engine.dispose()
            self.assertEqual(diff, [])
            command.downgrade(cfg, "0001_baseline")


if __name__ == "__main__":
    unittest.main()
