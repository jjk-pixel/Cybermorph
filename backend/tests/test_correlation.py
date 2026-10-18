"""
Lot G — corrélation d'événements et ATT&CK traçable : événements sources conservés une seule fois, raisonnement,
confiance, corrélation temporelle ≠ causalité, statuts observé / inféré / non confirmé, catalogue valide.
"""
import re
import unittest
from datetime import datetime, timedelta, UTC

from app.api.attack_techniques import list_observed_techniques, technique_evidence
from app.api.correlations import list_correlations
from app.correlation.engine import correlate
from app.mitre.mapping_engine import alert_status, apply_mitre_mapping
from app.mitre.technique_catalog import DEVIATION_RULES, MAPPING_RULES, TECHNIQUES
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.behavior import Deviation
from app.models.correlation import Correlation, TechniqueEvidence
from app.models.observation import AssetChange
from tests.test_engines import make_session

NOW = datetime.now(UTC).replace(microsecond=0)


class CatalogTest(unittest.TestCase):
    def test_technique_ids_are_valid_and_referenced(self):
        ids = [t["technique_id"] for t in TECHNIQUES]
        self.assertEqual(len(ids), len(set(ids)))
        for technique_id in ids:
            self.assertRegex(technique_id, r"^T\d{4}(\.\d{3})?$")
        for rule in MAPPING_RULES + list(DEVIATION_RULES.values()):
            self.assertIn(rule["technique_id"], ids)

    def test_isolated_alert_is_unconfirmed(self):
        self.assertEqual(alert_status(1), "unconfirmed")
        self.assertEqual(alert_status(None), "unconfirmed")
        self.assertEqual(alert_status(3), "inferred")


class CorrelationTestCase(unittest.TestCase):
    def setUp(self):
        self.db = make_session()
        self.db.add_all([
            Asset(id=1, name="poste", ip_address="10.0.0.5", asset_type="pc", status="up"),
            Asset(id=2, name="srv", ip_address="10.0.0.10", asset_type="server", status="up"),
        ])
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def scan_deviation(self, id_=1, at=NOW):
        return Deviation(id=id_, kind="port_scan", severity="warning", status="open", src_ip="10.0.0.5", dst_ip="10.0.0.10",
                         src_asset_id=1, dst_asset_id=2, explanation="Balayage de 40 ports", evidence={"distinct_ports": 40},
                         first_seen=at - timedelta(minutes=2), last_seen=at, occurrences=1)

    def alert(self, id_, message="ET SCAN Nmap", priority=2, count=5, at=NOW, src="10.0.0.5", dst="10.0.0.10"):
        return Alert(id=id_, source_ip=src, destination_ip=dst, message=message, priority=priority,
                     occurrence_count=count, first_seen=at, last_seen=at)


class MitreEvidenceTest(CorrelationTestCase):
    def test_measured_scan_is_observed_and_signature_is_inferred(self):
        self.db.add_all([self.scan_deviation(), self.alert(10, count=1), self.alert(11, "ET SCAN Nmap Scripting Engine", count=12)])
        self.db.commit()
        apply_mitre_mapping(self.db)
        evidence = {(e.event_type, e.event_id): e for e in self.db.query(TechniqueEvidence).all()}
        self.assertEqual(evidence[("deviation", 1)].status, "observed")
        self.assertEqual(evidence[("deviation", 1)].source, "flow_analysis")
        self.assertEqual(evidence[("alert", 10)].status, "unconfirmed")   # alerte isolée
        self.assertEqual(evidence[("alert", 11)].status, "inferred")
        apply_mitre_mapping(self.db)                                       # idempotent
        self.assertEqual(self.db.query(TechniqueEvidence).count(), 3)

    def test_from_technique_back_to_source_events(self):
        self.db.add_all([self.scan_deviation(), self.alert(11, count=12)])
        self.db.commit()
        apply_mitre_mapping(self.db)
        observed = {t["technique_id"]: t for t in list_observed_techniques(self.db)}
        self.assertEqual(observed["T1046"]["status"], "observed")
        self.assertIn("pas une preuve de compromission", observed["T1046"]["note"])
        detail = technique_evidence("T1046", self.db)
        self.assertEqual(detail["evidence"][0]["event"]["message"], "Balayage de 40 ports")
        self.assertEqual(observed["T1595"]["alerts"][0]["alert_id"], 11)  # format historique conservé


class CorrelationRulesTest(CorrelationTestCase):
    def test_port_probe_groups_scan_and_alerts_once(self):
        self.db.add_all([self.scan_deviation(), self.alert(10), self.alert(12, at=NOW - timedelta(hours=3))])
        self.db.commit()
        stats = correlate(self.db, NOW)
        # Balayage + « même adresse » pour chacune des deux IP (alerte et écart dans la même heure)
        self.assertEqual(stats["created"], 3)
        c = self.db.query(Correlation).filter_by(kind="port_probe").one()
        self.assertEqual({(e["type"], e["id"]) for e in c.events}, {("deviation", 1), ("alert", 10)})  # hors fenêtre exclue
        self.assertEqual((c.relation, c.confidence), ("same_target", 0.9))
        self.assertIn("40 ports distincts", c.reasoning)
        self.assertEqual(correlate(self.db, NOW), {"created": 0, "updated": 0})  # aucun double comptage
        self.db.add(self.alert(13, at=NOW + timedelta(minutes=5)))
        self.db.commit()
        correlate(self.db, NOW + timedelta(minutes=6))
        self.assertEqual(self.db.query(Correlation).filter_by(kind="port_probe").one().event_count, 3)

    def test_new_service_then_activity_is_temporal_not_causal(self):
        self.db.add(AssetChange(id=1, asset_id=2, ip="10.0.0.10", change_type="port_opened", new_value="8080", severity="notice",
                                explanation="Port 8080 ouvert", detected_at=NOW - timedelta(minutes=30)))
        self.db.add(self.alert(20, "ET WEB_SERVER probe", priority=2, at=NOW - timedelta(minutes=10)))
        self.db.commit()
        correlate(self.db, NOW)
        c = self.db.query(Correlation).filter_by(kind="new_service_activity").one()
        self.assertEqual(c.relation, "temporal")
        self.assertIn("ne démontre pas une relation de cause à effet", c.reasoning)
        self.assertEqual([e["type"] for e in c.events], ["change", "alert"])

    def test_activity_before_the_change_is_not_correlated(self):
        self.db.add(AssetChange(id=1, asset_id=2, ip="10.0.0.10", change_type="port_opened", new_value="8080", severity="notice",
                                explanation="Port 8080 ouvert", detected_at=NOW))
        self.db.add(self.alert(20, at=NOW - timedelta(minutes=20)))
        self.db.commit()
        correlate(self.db, NOW)
        self.assertEqual(self.db.query(Correlation).filter_by(kind="new_service_activity").count(), 0)

    def test_profile_change_needs_two_kinds(self):
        self.db.add(AssetChange(id=1, asset_id=1, ip="10.0.0.5", change_type="os_changed", severity="info", explanation="OS", detected_at=NOW))
        self.db.commit()
        correlate(self.db, NOW)
        self.assertEqual(self.db.query(Correlation).filter_by(kind="profile_change").count(), 0)
        self.db.add(AssetChange(id=2, asset_id=1, ip="10.0.0.5", change_type="identity_conflict", severity="warning",
                                explanation="MAC", detected_at=NOW + timedelta(minutes=10)))
        self.db.commit()
        correlate(self.db, NOW + timedelta(minutes=11))
        c = self.db.query(Correlation).filter_by(kind="profile_change").one()
        self.assertEqual(c.event_count, 2)
        self.assertAlmostEqual(c.confidence, 0.5)

    def test_same_address_multiple_categories(self):
        self.db.add_all([self.scan_deviation(), self.alert(10)])
        self.db.add(AssetChange(id=1, asset_id=2, ip="10.0.0.10", change_type="port_opened", new_value="23", severity="warning",
                                explanation="Port 23 ouvert", detected_at=NOW))
        self.db.commit()
        correlate(self.db, NOW)
        rows = {c.ip: c for c in self.db.query(Correlation).filter_by(kind="address_activity").all()}
        self.assertIn("10.0.0.10", rows)
        self.assertEqual(rows["10.0.0.10"].relation, "same_address")
        self.assertEqual(len(list_correlations(self.db, asset_id=2, kind=None, limit=100, offset=0)), len(
            self.db.query(Correlation).filter_by(asset_id=2).all()))

    def test_correlation_lists_attack_techniques_of_its_events(self):
        self.db.add_all([self.scan_deviation(), self.alert(10, count=8)])
        self.db.commit()
        apply_mitre_mapping(self.db)
        correlate(self.db, NOW)
        c = self.db.query(Correlation).filter_by(kind="port_probe").one()
        self.assertEqual(c.techniques, ["T1046", "T1595"])
        self.assertTrue(all(re.match(r"^T\d{4}$", t) for t in c.techniques))


if __name__ == "__main__":
    unittest.main()
