"""
Lot C — relations : classe observée / inférée / déclarée, confiance, validité, création limitée aux déclarations.
"""
import unittest
from datetime import datetime, timedelta, UTC

from fastapi import HTTPException
from pydantic import ValidationError

from app.api.network_connections import declare_connection, get_topology, list_connections, withdraw_connection
from app.attack_graph.graph_engine import build_graph
from app.models.asset import Asset
from app.models.network_connection import NetworkConnection
from app.schemas.network_connection import NetworkConnectionDeclare
from app.topology.relations import assess
from tests.test_engines import make_session

NOW = datetime.now(UTC)


def relation(**kw):
    defaults = dict(source_asset_id=1, destination_asset_id=2, status="active", last_seen=NOW, created_at=NOW - timedelta(days=1))
    return NetworkConnection(**{**defaults, **kw})


class AssessTest(unittest.TestCase):
    def test_classes_and_confidence(self):
        flow = assess(relation(connection_type="detected", source="suricata_flow", protocol="tcp", port=22), NOW)
        self.assertEqual((flow["relation_class"], flow["confidence"], flow["stale"]), ("observed", 0.9, False))
        self.assertEqual(flow["valid_until"], NOW + timedelta(hours=24))
        arp = assess(relation(connection_type="neighbor_detected", protocol="arp"), NOW)
        self.assertEqual((arp["relation_class"], arp["confidence"]), ("inferred", 0.5))
        self.assertIn("communication non démontrée", arp["reason"])
        legacy = assess(relation(connection_type="detected", source=None), NOW)
        self.assertEqual((legacy["origin"], legacy["confidence"], legacy["valid_until"]), ("legacy", 0.4, None))
        declared = assess(relation(connection_type="declared", source="operator", note="Sauvegarde nocturne"), NOW)
        self.assertEqual((declared["relation_class"], declared["confidence"], declared["reason"]), ("declared", 1.0, "Sauvegarde nocturne"))

    def test_expired_relation_is_stale(self):
        old = assess(relation(connection_type="neighbor_detected", last_seen=NOW - timedelta(hours=2)), NOW)
        self.assertTrue(old["stale"])


class GraphFromPersistedRelationsTest(unittest.TestCase):
    def setUp(self):
        self.db = make_session()
        self.db.add_all([
            Asset(id=1, name="a", ip_address="10.0.0.1", asset_type="pc", status="up"),
            Asset(id=2, name="b", ip_address="10.0.0.2", asset_type="server", status="up", services="ssh", open_ports="22"),
            Asset(id=3, name="c", ip_address="10.0.0.3", asset_type="server", status="up"),
        ])
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_same_subnet_does_not_create_edges(self):
        self.assertEqual(build_graph(self.db).number_of_edges(), 0)

    def test_stale_relation_is_excluded_but_kept(self):
        self.db.add_all([
            relation(id=1, connection_type="detected", source="suricata_flow", protocol="tcp", port=22),
            relation(id=2, source_asset_id=1, destination_asset_id=3, connection_type="neighbor_detected", protocol="arp",
                     last_seen=NOW - timedelta(hours=3)),
        ])
        self.db.commit()
        graph = build_graph(self.db, now=NOW)
        self.assertEqual(list(graph.edges), [(1, 2)])
        edge = graph.edges[1, 2]
        self.assertEqual((edge["confidence"], edge["relation_classes"]), (0.9, ["observed"]))
        self.assertEqual(edge["details"][0]["origin"], "suricata_flow")
        stale = [c for c in list_connections(self.db, status=None, relation_class=None, limit=500, offset=0) if c.stale]
        self.assertEqual([c.id for c in stale], [2])


class DeclarationTest(unittest.TestCase):
    def setUp(self):
        self.db = make_session()
        self.db.add_all([Asset(id=1, name="a", ip_address="10.0.0.1", asset_type="pc", status="up"),
                         Asset(id=2, name="b", ip_address="10.0.0.2", asset_type="server", status="up")])
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_invalid_declarations_are_rejected(self):
        for payload in (
            {"source_asset_id": 1, "destination_asset_id": 1, "reason": "boucle"},
            {"source_asset_id": 1, "destination_asset_id": 2, "port": 22, "reason": "port sans protocole"},
            {"source_asset_id": 1, "destination_asset_id": 2, "protocol": "tcp", "port": 70000, "reason": "port hors bornes"},
            {"source_asset_id": 1, "destination_asset_id": 2, "connection_type": "detected", "reason": "fausse observation"},
            {"source_asset_id": 1, "destination_asset_id": 2},
            {"source_asset_id": 1, "destination_asset_id": 2, "reason": "ok", "confidence": 1.0},
        ):
            with self.assertRaises(ValidationError, msg=payload):
                NetworkConnectionDeclare(**payload)

    def test_declare_duplicate_and_withdraw(self):
        payload = NetworkConnectionDeclare(source_asset_id=1, destination_asset_id=2, protocol="tcp", port=5432,
                                           reason="Réplication de base autorisée")
        out = declare_connection(payload, self.db)
        self.assertEqual((out.connection_type, out.source, out.relation_class, out.confidence), ("declared", "operator", "declared", 1.0))
        self.assertEqual(out.note, "Réplication de base autorisée")
        with self.assertRaises(HTTPException) as dup:
            declare_connection(payload, self.db)
        self.assertEqual(dup.exception.status_code, 409)
        self.assertEqual(withdraw_connection(out.id, self.db).status, "inactive")
        self.assertEqual(build_graph(self.db).number_of_edges(), 0)

    def test_observed_relation_cannot_be_withdrawn(self):
        self.db.add(relation(id=9, connection_type="detected", source="suricata_flow"))
        self.db.commit()
        with self.assertRaises(HTTPException) as err:
            withdraw_connection(9, self.db)
        self.assertEqual(err.exception.status_code, 409)

    def test_unknown_asset(self):
        with self.assertRaises(HTTPException) as err:
            declare_connection(NetworkConnectionDeclare(source_asset_id=1, destination_asset_id=99, reason="inconnu"), self.db)
        self.assertEqual(err.exception.status_code, 404)

    def test_topology_exposes_quality(self):
        self.db.add(relation(id=5, connection_type="neighbor_detected", protocol="arp"))
        self.db.commit()
        edge = get_topology(self.db)["edges"][0]
        self.assertEqual((edge["relation_class"], edge["origin"], edge["confidence"]), ("inferred", "arp", 0.5))


if __name__ == "__main__":
    unittest.main()
