"""
Lot F — graphe d'attaque crédible : préconditions par saut, service atteignable exigé, chemins observés ou
hypothétiques, cycles, limites signalées, déterminisme.
"""
import unittest
from datetime import datetime, UTC

import networkx as nx

from app.api.attack_paths import get_attack_paths
from app.attack_graph.graph_engine import build_graph, search_paths
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.network_connection import NetworkConnection
from app.models.vulnerability import VulnerabilityFinding
from tests.test_engines import make_session

NOW = datetime.now(UTC)


def flow(src, dst, port, **kw):
    return NetworkConnection(source_asset_id=src, destination_asset_id=dst, protocol="tcp", port=port,
                             connection_type="detected", source="suricata_flow", status="active", last_seen=NOW, **kw)


def arp(src, dst):
    return NetworkConnection(source_asset_id=src, destination_asset_id=dst, protocol="arp", connection_type="neighbor_detected",
                             source="arp", status="active", last_seen=NOW)


class AttackGraphTestCase(unittest.TestCase):
    def setUp(self):
        self.db = make_session()
        self.db.add_all([
            Asset(id=1, name="poste", ip_address="10.0.0.5", asset_type="pc", status="up", risk_score=10),
            Asset(id=2, name="rebond", ip_address="10.0.0.10", asset_type="server", status="up", risk_score=30, open_ports="22", services="ssh"),
            Asset(id=3, name="bdd", ip_address="10.0.0.30", asset_type="server", status="up", risk_score=40, open_ports="5432", services="postgresql"),
            Asset(id=4, name="muet", ip_address="10.0.0.40", asset_type="server", status="up", risk_score=60),  # aucun port
        ])
        self.db.commit()

    def tearDown(self):
        self.db.close()


class TransitionTest(AttackGraphTestCase):
    def test_hop_without_reachable_service_is_excluded(self):
        self.db.add_all([arp(1, 4), flow(1, 2, 22)])
        self.db.commit()
        graph = build_graph(self.db)
        self.assertFalse(graph.edges[1, 4]["transition"]["plausible"])
        paths, meta = search_paths(graph)
        self.assertFalse(any(p["target"] == 4 for p in paths))
        self.assertEqual(meta["excluded_transitions"], [{"source": 1, "target": 4, "reason": "Aucun service atteignable connu sur la cible"}])

    def test_preconditions_explain_each_step(self):
        self.db.add_all([flow(1, 2, 22), arp(2, 3)])
        self.db.commit()
        path = next(p for p in search_paths(build_graph(self.db))[0] if p["nodes"] == [1, 2, 3])
        first, second = path["steps"]
        self.assertEqual(first["services"], [22])
        statuses = {c["condition"]: c["status"] for c in first["preconditions"]}
        self.assertEqual(statuses["Service atteignable sur la cible"], "satisfied")
        self.assertEqual(statuses["Moyen d'exploitation (vulnérabilité confirmée, identifiants ou mauvaise configuration)"], "unknown")
        self.assertEqual(statuses["Activité hostile observée sur cette paire"], "not_observed")
        self.assertIn("Relation seulement inférée (voisinage ARP) : aucune communication observée", second["uncertainties"])
        self.assertEqual((path["nature"], path["exploitation_demonstrated"]), ("hypothetical", False))
        self.assertEqual(path["confidence"], 0.5)  # maillon le plus faible : voisinage ARP

    def test_observed_path_and_confirmed_vulnerability(self):
        self.db.add(flow(1, 2, 22))
        self.db.add(Alert(source_ip="10.0.0.5", destination_ip="10.0.0.10", message="ET EXPLOIT SSH", priority=1,
                          occurrence_count=4, first_seen=NOW, last_seen=NOW))
        self.db.add(VulnerabilityFinding(asset_id=2, port=22, cve_id="CVE-0000-0001", source="local_feed", status="confirmed",
                                         first_seen=NOW, last_checked_at=NOW))
        self.db.commit()
        path = next(p for p in search_paths(build_graph(self.db))[0] if p["nodes"] == [1, 2])
        self.assertEqual((path["nature"], path["exploitation_demonstrated"]), ("observed", True))
        self.assertEqual(path["steps"][0]["exploit_evidence"], ["CVE-0000-0001"])

    def test_insufficient_evidence_path_stays_hypothetical(self):
        self.db.add(arp(1, 2))
        self.db.commit()
        path = search_paths(build_graph(self.db))[0][0]
        self.assertEqual(path["nature"], "hypothetical")
        self.assertIn("Service non vu en usage depuis la source : accessibilité supposée sur le segment", path["uncertainties"])
        self.assertIn("Exploitation non démontrée", path["uncertainties"])


class CycleAndLimitTest(AttackGraphTestCase):
    def test_cycles_do_not_loop(self):
        self.db.add_all([flow(1, 2, 22), flow(2, 3, 5432), arp(3, 1), arp(3, 2), flow(2, 1, 22)])
        self.db.get(Asset, 1).open_ports = "445"
        self.db.commit()
        paths, _ = search_paths(build_graph(self.db), max_length=6)
        for p in paths:
            self.assertEqual(len(p["nodes"]), len(set(p["nodes"])))  # chemins simples, sans retour
        self.assertIn([1, 2, 3], [p["nodes"] for p in paths])

    def test_truncation_is_reported_and_results_are_deterministic(self):
        dense = nx.complete_graph(9, create_using=nx.DiGraph)
        for n in dense.nodes:
            dense.nodes[n].update(asset_type="server", risk_score=60)
        for u, v in dense.edges:
            dense.edges[u, v].update(weight=50, connection_types=["detected"])
        paths, meta = search_paths(dense, max_length=4)
        self.assertTrue(meta["truncated_pairs"])
        self.assertTrue(meta["total_limit_reached"])
        again, _ = search_paths(dense, max_length=4)
        self.assertEqual([p["nodes"] for p in paths], [p["nodes"] for p in again])

    def test_api_returns_limits_and_note(self):
        self.db.add(flow(1, 2, 22))
        self.db.commit()
        out = get_attack_paths(self.db, min_score=0, max_length=4)
        self.assertIn("excluded_transitions", out["limits"])
        self.assertIn("analyse défensive", out["note"])
        self.assertEqual(out["paths"][0]["path_ips"], ["10.0.0.5", "10.0.0.10"])


if __name__ == "__main__":
    unittest.main()
