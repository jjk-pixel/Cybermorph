"""
Lot B — découverte Nmap maîtrisée : portée validée, présence (hors ligne ≠ non observé), continuité d'identité,
changements de service, interruption, verrou de cycle et journal des exécutions.

Nmap n'est jamais lancé : un faux PortScanner rejoue des résultats fixés. SQLite en mémoire.
"""
import os
import tempfile
import unittest
from datetime import datetime, timedelta, UTC
from unittest import mock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.collectors import runs
from app.collectors.nmap_collector import scan_network
from app.collectors.scope import ScopeError, validate_args, validate_targets, _networks
from app.database import Base
from app.inventory.observations import reconcile_cycle, set_setting
from app.models.asset import Asset
from app.models.collector import CollectorRun
from app.models.observation import AssetChange, AssetObservation

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
CYCLE = timedelta(minutes=5)
NET = "10.0.0.0/24"


def host(mac, ports, os_name="Linux 5.15", accuracy="95"):
    """Résultat Nmap minimal au format python-nmap."""
    return {
        "addresses": {"ipv4": "x", "mac": mac},
        "vendor": {mac: "Dell"},
        "hostnames": [{"name": "", "type": ""}],
        "osmatch": [{"name": os_name, "accuracy": accuracy, "osclass": [{"type": "general purpose", "osfamily": "Linux", "accuracy": accuracy}]}],
        "tcp": {p: {"state": "open", "name": n, "product": prod, "version": ver, "extrainfo": "", "conf": "10",
                    "cpe": f"cpe:/a:{prod.lower()}:{prod.lower()}:{ver}" if prod else ""}
                for p, (n, prod, ver) in ports.items()},
    }


class FakeNmap:
    """Rejoue un balayage : `network` = {ip: host_data} ; `fail` = IP dont l'identification échoue."""

    def __init__(self, network: dict, fail: set | None = None, sweep_error: Exception | None = None, calls: list | None = None):
        self.network, self.fail, self.sweep_error, self.calls = network, fail or set(), sweep_error, calls
        self._hosts = {}

    def __call__(self):
        return FakeNmap(self.network, self.fail, self.sweep_error, self.calls)

    def scan(self, hosts, arguments, timeout=0):
        if self.calls is not None:
            self.calls.append((hosts, arguments, timeout))
        if "/" in hosts:
            if self.sweep_error:
                raise self.sweep_error
            self._hosts = {ip: {} for ip in self.network}
        else:
            if hosts in self.fail:
                raise RuntimeError("timeout")
            self._hosts = {hosts: self.network[hosts]} if hosts in self.network else {}

    def all_hosts(self):
        return list(self._hosts)

    def __getitem__(self, ip):
        return self._hosts[ip]


A = ("00:11:22:33:44:01", {22: ("ssh", "OpenSSH", "9.6p1"), 443: ("https", "nginx", "1.24.0")})
B = ("00:11:22:33:44:02", {3306: ("mysql", "MySQL", "8.0.36")})


class DiscoveryTestCase(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.factory = sessionmaker(bind=self.engine)
        self.db = self.factory()
        set_setting(self.db, "learning", {"started_at": (T0 - timedelta(days=10)).isoformat(), "hours": 48})
        self.db.commit()
        patcher = mock.patch("app.collectors.nmap_collector.resolve_hostname_mdns", return_value="")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(runs.stop_requested.clear)

    def tearDown(self):
        self.db.close()

    def scan(self, n, network, **kw):
        """Cycle n : balayage, puis rapprochement de fin de cycle (comme l'orchestrateur)."""
        start = T0 + n * CYCLE
        before = {a.id: a.status for a in self.db.query(Asset).all()}
        stats = scan_network(NET, scanner_factory=FakeNmap(network, **kw), session_factory=self.factory,
                             gateway_ip="10.0.0.1", now=start + timedelta(seconds=30))
        self.db.expire_all()
        changes = reconcile_cycle(self.db, start, before, now=start + timedelta(minutes=2))
        self.db.commit()
        return stats, changes

    def asset(self, ip):
        self.db.expire_all()
        return self.db.query(Asset).filter_by(ip_address=ip).one_or_none()


class ScopeTest(unittest.TestCase):
    def test_public_large_and_out_of_scope_targets_are_refused(self):
        allowed = _networks("192.168.43.0/24")
        with self.assertRaisesRegex(ScopeError, "privé"):
            validate_targets(_networks("8.8.8.0/24"), allowed)
        with self.assertRaisesRegex(ScopeError, "limite"):
            validate_targets(_networks("10.0.0.0/16"), _networks("10.0.0.0/8"))
        with self.assertRaisesRegex(ScopeError, "hors des réseaux autorisés"):
            validate_targets(_networks("192.168.44.0/24"), allowed)
        self.assertEqual([str(n) for n in validate_targets(_networks("192.168.43.0/25"), allowed)], ["192.168.43.0/25"])

    def test_intrusive_options_are_refused(self):
        for args in ("-sV --script vuln", "-A", "-sV -T5", "-sn --min-rate 5000"):
            with self.assertRaises(ScopeError, msg=args):
                validate_args(args)
        self.assertEqual(validate_args("-sV  -O --host-timeout 30s"), "-sV -O --host-timeout 30s")

    def test_out_of_scope_configuration_never_launches_nmap(self):
        calls = []
        with mock.patch.dict(os.environ, {"CYBERMORPH_SCAN_TARGETS": "172.16.0.0/24", "CYBERMORPH_SCAN_ALLOWED": NET}):
            with self.assertRaises(ScopeError):
                scan_network(NET, scanner_factory=FakeNmap({}, calls=calls), gateway_ip="")
        self.assertEqual(calls, [])


class PresenceTest(DiscoveryTestCase):
    def test_scan_records_services_versions_and_cpe(self):
        # Journal actif au niveau INFO, comme en production (un champ réservé de LogRecord y lèverait une erreur)
        with self.assertLogs("cybermorph.nmap", level="INFO") as logs:
            stats, _ = self.scan(0, {"10.0.0.10": host(*A)})
        self.assertIn("nmap_discovery", logs.output[0])
        self.assertEqual((stats["status"], stats["hosts_up"], stats["identified"]), ("success", 1, 1))
        values = {(o.attribute, o.value) for o in self.db.query(AssetObservation).all()}
        self.assertIn(("port_service", "22/tcp ssh OpenSSH 9.6p1"), values)
        self.assertIn(("cpe", "443/tcp cpe:/a:nginx:nginx:1.24.0"), values)
        services = self.asset("10.0.0.10").classification["services"]
        self.assertEqual(services[0]["version"], "9.6p1")

    def test_temporary_disappearance_is_unobserved_before_offline(self):
        both = {"10.0.0.10": host(*A), "10.0.0.11": host(*B)}
        self.scan(0, both)
        _, changes = self.scan(1, {"10.0.0.10": host(*A)})
        b = self.asset("10.0.0.11")
        self.assertEqual((b.status, b.missed_scans), ("unknown", 1))
        self.assertEqual(changes, [])  # une absence isolée n'est pas un changement
        _, changes = self.scan(2, {"10.0.0.10": host(*A)})
        self.assertEqual(self.asset("10.0.0.11").status, "down")
        self.assertEqual([c.change_type for c in changes], ["went_offline"])
        _, changes = self.scan(3, both)
        self.assertEqual((self.asset("10.0.0.11").status, self.asset("10.0.0.11").missed_scans), ("up", 0))
        self.assertEqual([c.change_type for c in changes], ["back_online"])

    def test_returning_after_a_single_miss_is_not_a_change(self):
        both = {"10.0.0.10": host(*A), "10.0.0.11": host(*B)}
        self.scan(0, both)
        self.scan(1, {"10.0.0.10": host(*A)})
        _, changes = self.scan(2, both)
        self.assertEqual(changes, [])

    def test_failed_sweep_changes_nothing(self):
        self.scan(0, {"10.0.0.10": host(*A)})
        status, _ = runs.run_step(
            "nmap", lambda: scan_network(NET, scanner_factory=FakeNmap({}, sweep_error=RuntimeError("nmap: interface down")),
                                         session_factory=self.factory, gateway_ip=""),
            "c1", session_factory=self.factory)
        self.assertEqual(status, "failed")
        self.assertEqual(self.asset("10.0.0.10").status, "up")
        run = self.db.query(CollectorRun).one()
        self.assertEqual((run.collector, run.status, run.error), ("nmap", "failed", "nmap: interface down"))

    def test_identification_failure_is_partial_and_host_stays_up(self):
        stats, _ = self.scan(0, {"10.0.0.10": host(*A), "10.0.0.11": host(*B)}, fail={"10.0.0.11"})
        self.assertEqual(stats["status"], "partial")
        self.assertEqual(stats["failures"][0]["ip"], "10.0.0.11")
        self.assertIsNone(self.asset("10.0.0.11"))  # jamais identifié : pas d'actif inventé
        self.scan(1, {"10.0.0.10": host(*A), "10.0.0.11": host(*B)})
        self.scan(2, {"10.0.0.10": host(*A), "10.0.0.11": host(*B)}, fail={"10.0.0.11"})
        self.assertEqual(self.asset("10.0.0.11").status, "up")

    def test_interruption_stops_between_hosts_without_presence_update(self):
        both = {"10.0.0.10": host(*A), "10.0.0.11": host(*B)}
        self.scan(0, both)
        original = FakeNmap.scan

        def stop_after_first(fake, hosts, arguments, timeout=0):
            original(fake, hosts, arguments, timeout)
            if hosts == "10.0.0.10":
                runs.stop_requested.set()
        with mock.patch.object(FakeNmap, "scan", stop_after_first):
            stats = scan_network(NET, scanner_factory=FakeNmap(both), session_factory=self.factory,
                                 gateway_ip="", now=T0 + CYCLE)
        self.assertEqual((stats["status"], stats["identified"], stats["interrupted_before"]), ("interrupted", 1, "10.0.0.11"))
        self.assertEqual(self.asset("10.0.0.11").status, "up")  # ni marqué absent, ni modifié

    def test_ip_change_follows_the_same_device(self):
        self.scan(0, {"10.0.0.10": host(*A)})
        original_id = self.asset("10.0.0.10").id
        stats, _ = self.scan(1, {"10.0.0.42": host(*A)})
        moved = self.asset("10.0.0.42")
        self.assertEqual(moved.id, original_id)
        self.assertIsNone(self.asset("10.0.0.10"))
        self.assertEqual(self.db.query(Asset).count(), 1)
        self.assertEqual(stats["ip_changes"][0]["old_ip"], "10.0.0.10")
        change = self.db.query(AssetChange).filter_by(change_type="ip_changed").one()
        self.assertEqual((change.old_value, change.new_value), ("10.0.0.10", "10.0.0.42"))

    def test_same_mac_on_two_responding_ips_is_not_merged(self):
        self.scan(0, {"10.0.0.10": host(*A)})
        self.scan(1, {"10.0.0.10": host(*A), "10.0.0.42": host(*A)})
        self.assertEqual(self.db.query(Asset).count(), 2)
        self.assertEqual(self.db.query(AssetChange).filter_by(change_type="ip_changed").count(), 0)

    def test_port_and_service_changes_between_scans(self):
        self.scan(0, {"10.0.0.10": host(*A)})
        upgraded = (A[0], {22: ("ssh", "OpenSSH", "9.7p1"), 443: ("https", "nginx", "1.24.0"), 23: ("telnet", "", "")})
        _, changes = self.scan(1, {"10.0.0.10": host(*upgraded)})
        kinds = {(c.change_type, c.severity) for c in changes}
        self.assertIn(("port_opened", "warning"), kinds)
        self.assertIn(("service_changed", "notice"), kinds)
        changed = next(c for c in changes if c.change_type == "service_changed")
        self.assertEqual((changed.old_value, changed.new_value), ("22/tcp ssh OpenSSH 9.6p1", "22/tcp ssh OpenSSH 9.7p1"))


class RunControlTest(unittest.TestCase):
    def test_concurrent_cycle_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "cycle.lock")
            with runs.cycle_lock(path):
                with self.assertRaises(runs.CycleBusy):
                    with runs.cycle_lock(path):
                        pass
            with runs.cycle_lock(path):  # libéré à la sortie
                pass

    def test_collector_error_is_recorded_without_secret(self):
        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        factory = sessionmaker(bind=engine)
        secret_url = "postgresql://cyber:s3cret@localhost/cybermorph"

        def broken():
            raise RuntimeError(f"connexion impossible à {secret_url}\ndétail")
        with mock.patch.dict(os.environ, {"DATABASE_URL": secret_url}):
            status, _ = runs.run_step("arp", broken, "c2", session_factory=factory)
        run = factory().query(CollectorRun).one()
        self.assertEqual(status, "failed")
        self.assertNotIn("s3cret", run.error)
        self.assertEqual(run.error, "connexion impossible à <DATABASE_URL>")

    def test_step_result_status_and_error_are_kept(self):
        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        factory = sessionmaker(bind=engine)
        status, _ = runs.run_step("suricata", lambda: {"status": "failed", "error": "Fichier introuvable : fast.log"}, session_factory=factory)
        run = factory().query(CollectorRun).one()
        self.assertEqual((status, run.error, run.stats), ("failed", "Fichier introuvable : fast.log", {}))



class JsonLogTest(unittest.TestCase):
    def test_json_lines_with_extra_fields(self):
        import json
        import logging
        from app.logging_config import JsonFormatter
        record = logging.getLogger("cybermorph.test").makeRecord(
            "cybermorph.test", logging.INFO, __file__, 1, "collector_step", (), None,
            extra={"collector": "nmap", "status": "failed", "error": "x"})
        entry = json.loads(JsonFormatter().format(record))
        self.assertEqual((entry["msg"], entry["collector"], entry["status"], entry["level"]), ("collector_step", "nmap", "failed", "INFO"))
        self.assertTrue(entry["ts"].endswith("Z"))


if __name__ == "__main__":
    unittest.main()
