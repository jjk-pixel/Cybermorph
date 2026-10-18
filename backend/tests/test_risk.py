"""
Lot D — moteur de risque explicable : bornes, déterminisme, données manquantes, double comptage, historique,
risque potentiel ≠ compromission constatée.
"""
import unittest
from datetime import datetime, timedelta, UTC

from app.models.alert import Alert
from app.models.asset import Asset
from app.models.attack_path_step import AttackPathStep
from app.models.behavior import Deviation
from app.models.risk import RiskHistory
from app.risk.apply_risk import score_assets
from app.risk.risk_engine import CRITERIA, RISK_LEVELS, calculate_risk, level_for
from app.risk.signals import collect_signals
from tests.test_engines import make_session

NOW = datetime(2026, 10, 18, 12, 0, tzinfo=UTC)


def asset(**kw):
    defaults = dict(id=1, name="a", ip_address="10.0.0.5", asset_type="pc", status="up", open_ports="", services="",
                    os_detected="Linux 5.15", mac_address="00:11:22:33:44:55", last_seen=NOW)
    return Asset(**{**defaults, **kw})


def context(signals=(), vulnerabilities=(), flow_visibility=True):
    return {"signals": list(signals), "vulnerabilities": list(vulnerabilities), "flow_visibility": flow_visibility,
            "compromise_indicators": []}


class FormulaTest(unittest.TestCase):
    def test_weights_sum_to_100_and_levels_are_ordered(self):
        self.assertEqual(sum(c["max"] for c in CRITERIA.values()), 100)
        self.assertEqual([t for t, _ in RISK_LEVELS], sorted([t for t, _ in RISK_LEVELS], reverse=True))
        self.assertEqual([level_for(s) for s in (0, 24.9, 25, 49.9, 50, 74.9, 75, 100)],
                         ["FAIBLE", "FAIBLE", "MODÉRÉ", "MODÉRÉ", "ÉLEVÉ", "ÉLEVÉ", "CRITIQUE", "CRITIQUE"])

    def test_score_is_bounded(self):
        worst = asset(asset_type="router", open_ports="21,23,139,445,3306,3389,5432", os_detected="Windows XP SP3",
                      authorization="unauthorized")
        signals = [{"points": 80, "label": f"s{i}", "evidence": [f"deviation:{i}"], "kind": "deviation"} for i in range(5)]
        vulns = [{"id": i, "cve_id": f"CVE-2099-000{i}", "status": "confirmed", "cvss_score": 10.0} for i in range(4)]
        result = calculate_risk(worst, context(signals, vulns), NOW)
        self.assertLessEqual(result["risk_score"], 100.0)
        self.assertEqual(result["risk_score"], 100.0)
        best = calculate_risk(asset(asset_type="unknown"), context(), NOW)
        self.assertEqual(best["risk_score"], 0.0)

    def test_deterministic_at_equal_data_and_date(self):
        a = asset(open_ports="22,3389", last_seen=NOW - timedelta(minutes=20))
        self.assertEqual(calculate_risk(a, context(), NOW), calculate_risk(a, context(), NOW))

    def test_ordinary_open_ports_do_not_add_risk(self):
        none = calculate_risk(asset(open_ports=""), context(), NOW)
        many = calculate_risk(asset(open_ports="22,80,443,8080,9000"), context(), NOW)
        self.assertEqual(none["breakdown"]["exposition_reseau"], many["breakdown"]["exposition_reseau"])
        self.assertIn("non comptés", many["contributors"][0]["note"])
        rdp = calculate_risk(asset(open_ports="3389,3389"), context(), NOW)
        self.assertEqual(rdp["breakdown"]["exposition_reseau"], 6.0)  # 20 × 30 %, compté une fois

    def test_missing_data_lowers_confidence_not_score(self):
        complete = calculate_risk(asset(), context(), NOW)
        sparse = calculate_risk(asset(os_detected=None, mac_address=None, last_seen=None), context(flow_visibility=False), NOW)
        self.assertEqual(sparse["risk_score"], complete["risk_score"])
        self.assertLess(sparse["confidence"]["value"], complete["confidence"]["value"])
        self.assertTrue(any("non identifié" in m for m in sparse["missing_data"]))
        self.assertTrue(any("Aucun flux" in m for m in sparse["missing_data"]))

    def test_offline_and_stale_affect_confidence_only(self):
        up = calculate_risk(asset(), context(), NOW)
        down = calculate_risk(asset(status="down", last_seen=NOW - timedelta(days=3)), context(), NOW)
        self.assertEqual(down["risk_score"], up["risk_score"])
        self.assertLessEqual(down["confidence"]["value"], 0.5)

    def test_unconfirmed_or_incomplete_vulnerabilities_do_not_count(self):
        pending = [{"id": 1, "cve_id": "CVE-2024-0001", "status": "probable", "cvss_score": 9.8},
                   {"id": 2, "cve_id": "CVE-2024-0002", "status": "uncertain", "cvss_score": None}]
        result = calculate_risk(asset(), context(vulnerabilities=pending), NOW)
        self.assertEqual(result["breakdown"]["vulnerabilites"], 0.0)
        self.assertIn("non confirmée", result["contributors"][1]["note"])
        confirmed_without_cvss = [{"id": 3, "cve_id": "CVE-2024-0003", "status": "confirmed", "cvss_score": None}]
        result = calculate_risk(asset(), context(vulnerabilities=confirmed_without_cvss), NOW)
        self.assertEqual(result["breakdown"]["vulnerabilites"], 12.5)  # CVSS inconnu : valeur médiane, signalée
        self.assertIn("CVSS inconnu", result["contributors"][1]["items"][0]["justification"])

    def test_outdated_os_is_an_estimate(self):
        result = calculate_risk(asset(os_detected="Microsoft Windows 7 SP1"), context(), NOW)
        self.assertEqual(result["breakdown"]["vulnerabilites"], 10.0)
        self.assertIn("estimation", result["contributors"][1]["items"][0]["justification"])

    def test_contributors_are_structured_and_assessment_is_potential(self):
        result = calculate_risk(asset(open_ports="445"), context(), NOW)
        self.assertEqual(result["assessment"], "potential")
        self.assertIn("pas une probabilité", result["disclaimer"])
        self.assertEqual(result["computed_at"], NOW.isoformat())
        smb = result["contributors"][0]["items"][0]
        self.assertEqual((smb["label"], smb["raw"], smb["evidence"]), ("SMB exposé", 20, ["port:445"]))
        self.assertAlmostEqual(sum(c["points"] for c in result["contributors"]), result["risk_score"])

    def test_without_context(self):
        result = calculate_risk(asset(), None, NOW)
        self.assertIn("Signaux comportementaux non évalués", result["missing_data"])


class SignalsTest(unittest.TestCase):
    def setUp(self):
        self.db = make_session()
        self.db.add_all([asset(), asset(id=2, ip_address="10.0.0.10", name="b", asset_type="server")])
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_alert_counted_in_a_deviation_is_not_counted_twice(self):
        self.db.add(Alert(id=7, source_ip="10.0.0.5", destination_ip="10.0.0.10", message="ET EXPLOIT", priority=1,
                          occurrence_count=1, first_seen=NOW, last_seen=NOW))
        self.db.add(Deviation(id=3, kind="new_communication", severity="warning", status="open", src_asset_id=1, dst_asset_id=2,
                              explanation="x", evidence={"alert_ids": [7]}, first_seen=NOW, last_seen=NOW, occurrences=1))
        self.db.commit()
        signals = collect_signals(self.db, NOW)[1]["signals"]
        self.assertEqual([s["kind"] for s in signals], ["deviation"])
        self.assertIn("alert:7", signals[0]["evidence"])
        target = collect_signals(self.db, NOW)[2]["signals"]
        self.assertEqual([s["kind"] for s in target], ["deviation"])  # la cible voit l'écart, pas l'alerte en double

    def test_independent_alert_is_counted(self):
        self.db.add(Alert(id=8, source_ip="10.0.0.5", destination_ip="10.0.0.10", message="ET SCAN", priority=2,
                          occurrence_count=3, first_seen=NOW, last_seen=NOW))
        self.db.commit()
        signals = collect_signals(self.db, NOW)
        self.assertEqual([s["kind"] for s in signals[1]["signals"]], ["ids_source"])
        self.assertEqual([s["kind"] for s in signals[2]["signals"]], ["ids_target"])

    def test_down_is_not_a_risk_signal_and_compromise_is_only_an_indicator(self):
        self.db.get(Asset, 2).status = "down"
        self.db.add(AttackPathStep(incident_id=4, sequence=2, source_asset_id=1, destination_asset_id=2, status="confirmed",
                                   evidence_type="ids_alert", confidence=0.7))
        self.db.commit()
        ctx = collect_signals(self.db, NOW)[2]
        self.assertEqual(ctx["signals"], [])
        result = calculate_risk(self.db.get(Asset, 2), ctx, NOW)
        self.assertEqual(result["assessment"], "potential")
        self.assertIn("non vérifiée par un analyste", result["compromise_indicators"][0]["label"])


class HistoryTest(unittest.TestCase):
    def test_history_records_changes_and_hourly_heartbeat(self):
        db = make_session()
        db.add(asset(open_ports="3389"))
        db.commit()
        score_assets(db, NOW)
        score_assets(db, NOW + timedelta(minutes=5))       # inchangé : rien
        self.assertEqual(db.query(RiskHistory).count(), 1)
        db.get(Asset, 1).open_ports = "3389,23"
        score_assets(db, NOW + timedelta(minutes=10))      # score modifié
        score_assets(db, NOW + timedelta(minutes=80))      # inchangé mais > 1 h depuis le dernier point
        rows = db.query(RiskHistory).order_by(RiskHistory.computed_at).all()
        self.assertEqual(len(rows), 3)
        self.assertLess(rows[0].score, rows[1].score)
        self.assertEqual(rows[1].breakdown["exposition_reseau"], 13.5)
        db.close()


if __name__ == "__main__":
    unittest.main()
