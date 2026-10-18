"""
Lot H — supervision : retards de collecte, erreurs des collecteurs, perte de visibilité, fraîcheur par actif.
"""
import subprocess
import unittest
from datetime import datetime, timedelta, UTC

from app.api.live import get_live_state
from app.inventory.observations import set_setting
from app.models.asset import Asset
from app.models.collector import CollectorRun
from app.monitoring.health import asset_freshness, system_health, timer_state
from tests.test_engines import make_session

NOW = datetime(2026, 10, 18, 12, 0, tzinfo=UTC)


def no_systemd(*args, **kwargs):
    raise FileNotFoundError("systemctl")


def run(collector, status, minutes_ago, error=None, cycle="c1"):
    at = NOW - timedelta(minutes=minutes_ago)
    return CollectorRun(cycle_id=cycle, collector=collector, status=status, started_at=at, finished_at=at, duration_s=1.0, error=error)


class HealthTest(unittest.TestCase):
    def setUp(self):
        self.db = make_session()
        self.db.add_all([
            Asset(id=1, name="a", ip_address="10.0.0.1", asset_type="router", status="up", last_seen=NOW - timedelta(minutes=3)),
            Asset(id=2, name="b", ip_address="10.0.0.2", asset_type="pc", status="down", last_seen=NOW - timedelta(days=2)),
        ])
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_no_cycle_is_critical(self):
        health = system_health(self.db, NOW, runner=no_systemd)
        self.assertEqual(health["status"], "failing")
        self.assertTrue(health["cycle"]["late"])
        self.assertFalse(health["timer"]["available"])

    def test_healthy_cycle(self):
        self.db.add_all([run("cycle", "success", 4), run("nmap", "success", 4), run("vulnerabilities", "skipped", 4)])
        self.db.commit()
        health = system_health(self.db, NOW, runner=no_systemd)
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["last_scan"]["status"], "success")
        self.assertTrue(any("CVE ne sont pas évaluées" in i["message"] for i in health["issues"]))
        self.assertTrue(any("obsolètes" in i["message"] for i in health["issues"]))
        self.assertIn("toutes les 5 min", health["refresh_note"])

    def test_late_collection(self):
        self.db.add(run("cycle", "success", 25))
        self.db.commit()
        health = system_health(self.db, NOW, runner=no_systemd)
        self.assertEqual(health["status"], "failing")
        self.assertIn("en retard", health["issues"][0]["message"])

    def test_collector_error_means_lost_visibility_not_safety(self):
        self.db.add_all([run("cycle", "partial", 4), run("nmap", "success", 9, cycle="c0"),
                         run("nmap", "failed", 4, error="nmap: interface down")])
        self.db.commit()
        health = system_health(self.db, NOW, runner=no_systemd)
        nmap = next(s for s in health["steps"] if s["collector"] == "nmap")
        self.assertEqual((nmap["last_status"], nmap["consecutive_failures"]), ("failed", 1))
        self.assertEqual(nmap["last_success_at"], NOW - timedelta(minutes=9))
        issue = next(i for i in health["issues"] if i.get("collector") == "nmap")
        self.assertIn("pas une absence de menace", issue["message"])
        self.assertEqual(health["status"], "degraded")

    def test_repeated_failures_become_critical(self):
        self.db.add(run("cycle", "partial", 1))
        self.db.add_all([run("eve", "failed", m, error="Fichier introuvable") for m in (1, 6, 11)])
        self.db.commit()
        self.assertEqual(system_health(self.db, NOW, runner=no_systemd)["status"], "failing")

    def test_missing_eve_file_is_reported(self):
        self.db.add(run("cycle", "success", 2))
        set_setting(self.db, "eve_last_run", {"at": NOW.isoformat(), "error": "Fichier introuvable : /var/log/suricata/eve.json"})
        self.db.commit()
        self.assertTrue(any("Comportement non observé" in i["message"] for i in system_health(self.db, NOW, runner=no_systemd)["issues"]))

    def test_asset_freshness(self):
        self.assertEqual(asset_freshness(self.db.get(Asset, 1), NOW)["freshness"], "fresh")
        self.assertEqual(asset_freshness(self.db.get(Asset, 2), NOW)["freshness"], "obsolete")
        self.assertEqual(asset_freshness(Asset(id=3, ip_address="x", last_seen=None), NOW)["freshness"], "unknown")

    def test_timer_state_parsing(self):
        def fake(*args, **kwargs):
            return subprocess.CompletedProcess(args, 0, stdout="ActiveState=active\nLastTriggerUSec=Sun 2026-10-18 03:45:07 UTC\nNextElapseUSecRealtime=\n")
        state = timer_state(fake)
        self.assertEqual((state["available"], state["active_state"], state["next_elapse"]), (True, "active", None))

    def test_live_state_carries_collection_and_freshness(self):
        self.db.add(run("cycle", "success", 1))
        self.db.commit()
        state = get_live_state(self.db)
        self.assertIn("collection", state)
        self.assertEqual({a["id"]: a["freshness"] for a in state["assets"]}[2], "obsolete")


if __name__ == "__main__":
    unittest.main()
