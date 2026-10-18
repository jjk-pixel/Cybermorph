"""
Tests des moteurs CYBERMORPH sur une base SQLite en mémoire (la base PostgreSQL n'est jamais touchée).

    cd backend && ../venv/bin/python -m unittest discover -s tests -v
"""
import json
import tempfile
import unittest
from datetime import datetime, timedelta, UTC
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models import asset, network_connection, alert, attack_technique, simulation, snapshot, incident, attack_path_step  # noqa: F401
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.attack_path_step import AttackPathStep
from app.models.incident import Incident
from app.models.network_connection import NetworkConnection
from app.attack_graph.graph_engine import build_graph, find_attack_paths, find_paths_on_graph, MAX_PATHS_PER_PAIR
from app.correlation.alert_correlation import compute_alert_score
from app.simulation.simulation_engine import run_what_if
from app.incidents.incident_engine import create_incident_from_alert, mark_dormant_incidents, utcnow
from app.incidents.attack_progression import create_potential_steps, advance_incident
from app.api.live import get_live_state, _iso
from app.api import simulations as simulations_api
from app.schemas.simulation import SimulationCreate
import app.collectors.suricata_collector as suricata


def make_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def seed_lab(db):
    """Lab minimal : poste attaquant (1) → serveur (2) → routeur (3)."""
    db.add_all([
        Asset(id=1, name="attaquant", ip_address="10.0.0.5", asset_type="pc", status="up", risk_score=10),
        Asset(id=2, name="srv", ip_address="10.0.0.10", asset_type="server", status="up", risk_score=40, services="ssh,mysql"),
        Asset(id=3, name="gw", ip_address="10.0.0.1", asset_type="router", status="up", risk_score=20, services="domain"),
    ])
    db.add_all([
        NetworkConnection(source_asset_id=1, destination_asset_id=2, protocol="tcp", port=22, connection_type="detected", status="active"),
        NetworkConnection(source_asset_id=1, destination_asset_id=2, protocol="arp", connection_type="neighbor_detected", status="active"),
        NetworkConnection(source_asset_id=2, destination_asset_id=3, protocol="arp", connection_type="neighbor_detected", status="active"),
        NetworkConnection(source_asset_id=3, destination_asset_id=1, protocol="arp", connection_type="neighbor_detected", status="inactive"),
    ])
    now = datetime.now(UTC)
    db.add(Alert(id=1, source_ip="10.0.0.5", destination_ip="10.0.0.10", message="ET SCAN Nmap Scripting Engine",
                 classification="Attempted Information Leak", priority=2, occurrence_count=12, first_seen=now, last_seen=now))
    db.commit()


class AlertCorrelationTest(unittest.TestCase):
    def test_no_alert_means_no_score(self):
        self.assertEqual(compute_alert_score([]), (0.0, None))

    def test_alerts_without_priority_do_not_crash(self):
        score, summary = compute_alert_score([Alert(message="x", priority=None, occurrence_count=3)])
        self.assertGreater(score, 0)
        self.assertEqual(summary["alert_count"], 1)


class AttackGraphTest(unittest.TestCase):
    def setUp(self):
        self.db = make_session()
        seed_lab(self.db)

    def tearDown(self):
        self.db.close()

    def test_inactive_connections_are_ignored(self):
        graph = build_graph(self.db)
        self.assertTrue(graph.has_edge(1, 2))
        self.assertFalse(graph.has_edge(3, 1))

    def test_alert_corroborates_edge(self):
        edge = build_graph(self.db).edges[1, 2]
        self.assertIn("alert", edge["connection_types"])
        self.assertIsNotNone(edge["alert_summary"])

    def test_evidence_is_strongest_per_edge_then_weakest_link(self):
        paths = {tuple(p["nodes"]): p for p in find_attack_paths(self.db)}
        # 1→2 : ARP + trafic observé + alerte IDS sur la même paire => la preuve de l'arête est l'alerte
        self.assertEqual(paths[(1, 2)]["evidence_level"], "alerte_ids")
        # 1→2→3 : le maillon 2→3 n'est qu'un voisinage ARP => c'est le niveau du chemin
        self.assertEqual(paths[(1, 2, 3)]["evidence_level"], "voisinage_detecte")
        self.assertLess(paths[(1, 2, 3)]["score"], 100)

    def test_min_score_filters(self):
        self.assertTrue(all(p["score"] >= 60 for p in find_attack_paths(self.db, min_score=60)))

    def test_path_enumeration_is_capped(self):
        import networkx as nx
        dense = nx.complete_graph(9, create_using=nx.DiGraph)
        for n in dense.nodes:
            dense.nodes[n].update(asset_type="server", risk_score=60)
        for u, v in dense.edges:
            dense.edges[u, v].update(weight=50, connection_types=["detected"])
        per_pair = {}
        for p in find_paths_on_graph(dense, max_length=4):
            per_pair[(p["source"], p["target"])] = per_pair.get((p["source"], p["target"]), 0) + 1
        self.assertLessEqual(max(per_pair.values()), MAX_PATHS_PER_PAIR)


class SimulationTest(unittest.TestCase):
    def setUp(self):
        self.db = make_session()
        seed_lab(self.db)

    def tearDown(self):
        self.db.close()

    def test_connection_removed_cuts_paths_without_touching_db(self):
        result = run_what_if(self.db, {"type": "connection_removed", "source_asset_id": 2, "destination_asset_id": 3})
        self.assertLess(result["paths_after_count"], result["paths_before_count"])
        self.assertEqual(self.db.query(NetworkConnection).filter_by(status="active").count(), 3)

    def test_new_service_exposed_escalates_incoming_paths(self):
        result = run_what_if(self.db, {"type": "new_service_exposed", "asset_id": 2})
        self.assertGreater(result["escalated_paths_count"], 0)
        for p in result["escalated_paths"]:
            self.assertGreater(p["score"], p["score_before"])

    def test_simulation_api_flow(self):
        sim = simulations_api.create_simulation(SimulationCreate(name="test"), db=self.db)
        summary = simulations_api.apply_simulation_hypothesis(sim.id, {"type": "asset_compromised", "asset_id": 1}, db=self.db)
        self.assertEqual(summary["status"], "completed")
        self.assertIn("escalated_paths", summary["summary"])
        result = simulations_api.get_simulation_result(sim.id, db=self.db)
        self.assertEqual(result["hypothesis"]["asset_id"], 1)

    def test_simulation_api_rejects_incomplete_hypothesis(self):
        from fastapi import HTTPException
        sim = simulations_api.create_simulation(SimulationCreate(name="test"), db=self.db)
        with self.assertRaises(HTTPException) as ctx:
            simulations_api.apply_simulation_hypothesis(sim.id, {"type": "asset_compromised"}, db=self.db)
        self.assertEqual(ctx.exception.status_code, 400)


class IncidentEngineTest(unittest.TestCase):
    def setUp(self):
        self.db = make_session()
        seed_lab(self.db)
        self.alert = self.db.get(Alert, 1)

    def tearDown(self):
        self.db.close()

    def test_incident_lifecycle(self):
        incident = create_incident_from_alert(self.db, self.alert)
        self.assertEqual((incident.source_asset_id, incident.current_asset_id, incident.status), (1, 2, "detected"))

        create_potential_steps(self.db, incident)
        steps = self.db.query(AttackPathStep).filter_by(incident_id=incident.id).all()
        self.assertEqual([(s.source_asset_id, s.destination_asset_id, s.status) for s in steps], [(2, 3, "potential")])
        self.assertEqual(incident.total_steps, 2)

        # Pas encore de preuve que le serveur attaque le routeur : pas de progression
        self.assertIsNone(advance_incident(self.db, incident))

        # Le serveur compromis scanne le routeur => l'étape 2→3 est confirmée
        now = datetime.now(UTC)
        self.db.add(Alert(source_ip="10.0.0.10", destination_ip="10.0.0.1", message="ET EXPLOIT Router RCE attempt",
                          classification="Attempted Administrator Privilege Gain", priority=1, occurrence_count=1,
                          first_seen=now, last_seen=now))
        self.db.commit()
        step = advance_incident(self.db, incident)
        self.assertIsNotNone(step)
        self.assertEqual(step.status, "confirmed")
        self.assertEqual((incident.current_asset_id, incident.current_step, incident.status), (3, 2, "progressing"))

        # Une nouvelle alerte de la même paire se rattache au même incident, même après progression
        again = create_incident_from_alert(self.db, self.alert)
        self.assertEqual(again.id, incident.id)
        self.assertEqual(self.db.query(Incident).count(), 1)

    def test_irrelevant_or_low_priority_alerts_do_not_open_incidents(self):
        self.alert.message = "SURICATA ICMPv4 unknown code"
        self.alert.classification = "Generic Protocol Command Decode"
        self.assertIsNone(create_incident_from_alert(self.db, self.alert))

    def test_stale_incidents_become_dormant(self):
        incident = create_incident_from_alert(self.db, self.alert)
        incident.last_seen = utcnow() - timedelta(hours=2)
        self.db.commit()
        self.assertEqual(mark_dormant_incidents(self.db), 1)
        self.assertEqual(self.db.get(Incident, incident.id).status, "dormant")
        self.assertEqual(self.db.query(Incident).count(), 1)  # rien n'est supprimé


class LiveStateTest(unittest.TestCase):
    def test_live_state_shape(self):
        db = make_session()
        seed_lab(db)
        incident = create_incident_from_alert(db, db.get(Alert, 1))
        create_potential_steps(db, incident)
        state = get_live_state(db)
        db.close()

        for key in ("type", "assets", "edges", "links", "attack_paths", "active_incidents", "recent_alerts", "stats"):
            self.assertIn(key, state)
        self.assertEqual(state["stats"]["assets"], 3)
        self.assertEqual(state["stats"]["active_incidents"], 1)
        self.assertTrue(all("nodes" in p for p in state["attack_paths"]))
        self.assertTrue(state["active_incidents"][0]["started_at"].endswith("Z"))
        json.dumps(state, default=str)

    def test_iso_assumes_utc_for_naive_datetimes(self):
        self.assertEqual(_iso(datetime(2026, 10, 17, 15, 0, 0)), "2026-10-17T15:00:00Z")
        self.assertIsNone(_iso(None))


class SuricataOffsetTest(unittest.TestCase):
    LINE = ("10/17/2026-15:40:54.123456  [**] [1:2010937:3] ET SCAN Test [**] "
            "[Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.0.0.5:5555 -> 10.0.0.10:3306\n")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = Path(self.tmp.name) / "fast.log"
        self.original_state = suricata.OFFSET_STATE_PATH
        suricata.OFFSET_STATE_PATH = Path(self.tmp.name) / "offset.json"

    def tearDown(self):
        suricata.OFFSET_STATE_PATH = self.original_state
        self.tmp.cleanup()

    def read(self):
        lines, inode, offset = suricata.read_new_lines(str(self.log))
        suricata._save_offset(inode, offset)
        return suricata.parse_fast_log_lines(lines)

    def test_incremental_reading(self):
        self.log.write_text(self.LINE * 2 + self.LINE[:20])
        self.assertEqual(len(self.read()), 2)             # la ligne partielle attend
        with open(self.log, "a") as f:
            f.write(self.LINE[20:] + self.LINE)
        self.assertEqual(len(self.read()), 2)             # ligne complétée + nouvelle
        self.assertEqual(len(self.read()), 0)             # rien de neuf
        self.log.write_text(self.LINE)                    # logrotate copytruncate
        self.assertEqual(len(self.read()), 1)

    def test_missing_file(self):
        self.assertIsNone(suricata.read_new_lines(str(self.log)))

    def test_parse_fields(self):
        (record,) = suricata.parse_fast_log_lines([self.LINE])
        self.assertEqual((record["src_ip"], record["dst_ip"], record["priority"]), ("10.0.0.5", "10.0.0.10", "2"))


if __name__ == "__main__":
    unittest.main()
