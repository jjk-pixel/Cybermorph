"""
Lot 2 — journal d'observations, rapprochement des identités, détection des changements, autorisation.
Le temps est piloté explicitement (cycles de 5 min simulés) ; aucune commande réseau n'est lancée.
"""
import unittest
from datetime import datetime, timedelta, UTC

from app.api.assets import declare_asset_attributes
from app.api.inventory import acknowledge_change, get_inventory, get_inventory_asset, list_changes
from app.inventory.observations import (
    identity_summary, learning_window, reconcile_cycle, record_observation, set_setting,
)
from app.models.asset import Asset
from app.models.observation import AssetChange, AssetObservation
from app.schemas.asset import AssetDeclaration
from tests.test_engines import make_session

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
CYCLE = timedelta(minutes=5)


class InventoryTestCase(unittest.TestCase):
    def setUp(self):
        self.db = make_session()
        self.db.add(Asset(id=1, name="srv", ip_address="10.0.0.10", asset_type="server", status="up", created_at=T0 - timedelta(days=3)))
        self.db.commit()
        # Apprentissage démarré bien avant : terminé
        set_setting(self.db, "learning", {"started_at": (T0 - timedelta(days=10)).isoformat(), "hours": 48})
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def cycle(self, n: int, observe, status_before=None):
        """Simule le cycle n : `observe(seen_at)` enregistre les observations, puis rapprochement."""
        start = T0 + n * CYCLE
        observe(start + timedelta(seconds=30))
        changes = reconcile_cycle(self.db, start, status_before, now=start + timedelta(minutes=2))
        self.db.commit()
        return changes

    def nmap(self, ports=("22",), mac="00:50:56:aa:bb:cc", os_name="Linux 5.x"):
        def observe(at):
            record_observation(self.db, "10.0.0.10", "nmap", "mac", mac, 1, at)
            record_observation(self.db, "10.0.0.10", "nmap", "os", os_name, 1, at)
            for p in ports:
                record_observation(self.db, "10.0.0.10", "nmap", "open_port", p, 1, at)
        return observe


class ObservationTest(InventoryTestCase):
    def test_upsert_counts_and_normalizes_mac(self):
        record_observation(self.db, "10.0.0.10", "nmap", "mac", "00:50:56:aa:bb:cc", 1, T0)
        record_observation(self.db, "10.0.0.10", "nmap", "mac", "00:50:56:AA:BB:CC", 1, T0 + CYCLE)
        rows = self.db.query(AssetObservation).all()
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0].value, rows[0].seen_count), ("00:50:56:AA:BB:CC", 2))

    def test_empty_values_are_ignored(self):
        self.assertIsNone(record_observation(self.db, "10.0.0.10", "nmap", "os", None, 1))
        self.assertIsNone(record_observation(self.db, "10.0.0.10", "nmap", "os", "  ", 1))


class ChangeDetectionTest(InventoryTestCase):
    def test_first_pass_initialises_silently(self):
        changes = self.cycle(0, self.nmap())
        self.assertEqual(changes, [])
        asset = self.db.get(Asset, 1)
        self.assertEqual((asset.authorization, asset.authorization_source), ("authorized", "learning"))

    def test_new_dangerous_port_is_a_warning(self):
        self.cycle(0, self.nmap(ports=("22",)))
        changes = self.cycle(1, self.nmap(ports=("22", "23")))
        self.assertEqual([(c.change_type, c.new_value, c.severity) for c in changes], [("port_opened", "23", "warning")])

    def test_port_closes_only_after_grace_and_when_the_source_saw_the_asset(self):
        self.cycle(0, self.nmap(ports=("22", "80")))
        self.assertEqual(self.cycle(1, self.nmap(ports=("22",))), [])        # 80 absent depuis 5 min : on attend
        self.assertEqual(self.cycle(2, lambda at: None), [])                 # Nmap n'a pas vu l'actif : rien
        self.assertEqual(self.cycle(2, self.nmap(ports=("22",))), [])
        changes = self.cycle(3, self.nmap(ports=("22",)))                   # 80 absent depuis > 12 min
        self.assertEqual([(c.change_type, c.old_value) for c in changes], [("port_closed", "80")])
        reopened = self.cycle(4, self.nmap(ports=("22", "80")))
        self.assertEqual([(c.change_type, c.new_value) for c in reopened], [("port_opened", "80")])

    def test_mac_change_on_same_ip_is_an_identity_conflict(self):
        self.cycle(0, self.nmap(mac="00:50:56:AA:BB:CC"))
        changes = self.cycle(1, self.nmap(mac="00:0C:29:11:22:33"))
        conflict = next(c for c in changes if c.change_type == "identity_conflict")
        self.assertEqual((conflict.old_value, conflict.new_value, conflict.severity), ("00:50:56:AA:BB:CC", "00:0C:29:11:22:33", "warning"))
        old = self.db.query(AssetObservation).filter_by(value="00:50:56:AA:BB:CC").one()
        self.assertIsNotNone(old.retired_at)  # conservée, mais plus courante

    def test_os_estimate_change_is_only_informational(self):
        self.cycle(0, self.nmap(os_name="Linux 4.15 - 5.19"))
        changes = self.cycle(1, self.nmap(os_name="Linux 5.0 - 5.14"))
        self.assertEqual([(c.change_type, c.severity) for c in changes], [("os_changed", "info")])

    def test_new_asset_after_learning_is_unauthorized(self):
        self.cycle(0, self.nmap())
        start = T0 + CYCLE
        self.db.add(Asset(id=2, name="inconnu", ip_address="10.0.0.66", asset_type="unknown", status="up", created_at=start + timedelta(seconds=40)))
        self.db.commit()
        changes = reconcile_cycle(self.db, start, now=start + timedelta(minutes=2))
        new = next(c for c in changes if c.change_type == "new_asset")
        self.assertEqual(new.severity, "warning")
        self.assertEqual(self.db.get(Asset, 2).authorization, "unauthorized")

    def test_new_asset_during_learning_is_authorized(self):
        set_setting(self.db, "learning", {"started_at": T0.isoformat(), "hours": 48})
        self.db.add(Asset(id=2, name="nouveau", ip_address="10.0.0.67", asset_type="pc", status="up", created_at=T0 + timedelta(seconds=10)))
        self.db.commit()
        changes = reconcile_cycle(self.db, T0, now=T0 + timedelta(minutes=2))
        self.assertEqual(next(c for c in changes if c.change_type == "new_asset").severity, "notice")
        self.assertEqual(self.db.get(Asset, 2).authorization, "authorized")

    def test_shared_mac_is_reported_once_and_not_merged(self):
        self.db.add(Asset(id=2, name="alias", ip_address="10.0.0.11", asset_type="server", status="up", created_at=T0 - timedelta(days=3)))
        self.db.commit()

        def both(at):
            record_observation(self.db, "10.0.0.10", "nmap", "mac", "00:50:56:AA:BB:CC", 1, at)
            record_observation(self.db, "10.0.0.11", "arp", "mac", "00:50:56:AA:BB:CC", 2, at)
        first = self.cycle(0, both)
        self.assertEqual([c.change_type for c in first], ["mac_shared"])
        self.assertEqual(self.cycle(1, both), [])
        self.assertEqual(self.db.query(Asset).count(), 2)

    def test_status_transitions(self):
        self.cycle(0, self.nmap())
        asset = self.db.get(Asset, 1)
        asset.status = "down"
        self.db.commit()
        changes = self.cycle(1, lambda at: None, status_before={1: "up"})
        self.assertEqual([(c.change_type, c.severity) for c in changes], [("went_offline", "notice")])


class IdentityTest(InventoryTestCase):
    def test_confidence_grows_with_independent_sources(self):
        record_observation(self.db, "10.0.0.10", "nmap", "mac", "00:50:56:AA:BB:CC", 1, T0)
        record_observation(self.db, "10.0.0.10", "heuristic", "hostname", "vmware-server", 1, T0)
        obs = self.db.query(AssetObservation).all()
        asset = self.db.get(Asset, 1)
        base = identity_summary(asset, obs)
        self.assertEqual(base["confidence"], 0.6)
        self.assertFalse(base["name"]["observed"])  # nom déduit : ne compte pas

        record_observation(self.db, "10.0.0.10", "arp", "mac", "00:50:56:aa:bb:cc", 1, T0)
        record_observation(self.db, "10.0.0.10", "mdns", "hostname", "ASUS", 1, T0)
        full = identity_summary(asset, self.db.query(AssetObservation).all())
        self.assertEqual(full["confidence"], 0.9)
        self.assertEqual(full["name"]["value"], "ASUS")
        self.assertEqual(identity_summary(asset, self.db.query(AssetObservation).all(), open_conflicts=1)["confidence"], 0.6)


class InventoryApiTest(InventoryTestCase):
    def test_inventory_detail_changes_and_acknowledge(self):
        self.cycle(0, self.nmap(ports=("22",)))
        self.cycle(1, self.nmap(ports=("22", "3389"), mac="00:0C:29:11:22:33"))
        inventory = get_inventory(self.db)
        entry = inventory["assets"][0]
        self.assertEqual(entry["identity"]["open_conflicts"], 1)
        self.assertEqual(inventory["stats"]["conflicts"], 1)
        self.assertFalse(inventory["learning"]["in_learning"])

        detail = get_inventory_asset(1, self.db)
        self.assertEqual({o["attribute"] for o in detail["observations"]}, {"mac", "os", "open_port"})
        self.assertEqual(len(detail["changes"]), 2)

        warnings = list_changes(self.db, limit=50, asset_id=None, min_severity="warning", include_acknowledged=True)
        self.assertEqual({c["change_type"] for c in warnings}, {"identity_conflict", "port_opened"})
        conflict = next(c for c in warnings if c["change_type"] == "identity_conflict")
        acknowledge_change(conflict["id"], self.db)
        self.assertEqual(get_inventory(self.db)["assets"][0]["identity"]["open_conflicts"], 0)
        pending = list_changes(self.db, limit=50, asset_id=1, min_severity="info", include_acknowledged=False)
        self.assertNotIn(conflict["id"], [c["id"] for c in pending])

    def test_declare_authorization_and_scanner(self):
        out = declare_asset_attributes(1, AssetDeclaration(authorization="unauthorized"), self.db)
        self.assertEqual((out.authorization, out.authorization_source), ("unauthorized", "declared"))
        out = declare_asset_attributes(1, AssetDeclaration(is_scanner=True), self.db)
        self.assertTrue(out.is_scanner)
        self.assertEqual(out.scanner_reason, "Déclaré par l'opérateur")
        out = declare_asset_attributes(1, AssetDeclaration(is_scanner=False), self.db)
        self.assertIsNone(out.scanner_reason)

    def test_learning_window_is_created_once(self):
        db = make_session()
        first = learning_window(db, T0)
        second = learning_window(db, T0 + timedelta(hours=60))
        self.assertTrue(first["in_learning"])
        self.assertEqual(first["started_at"], second["started_at"])
        self.assertFalse(second["in_learning"])
        db.close()


if __name__ == "__main__":
    unittest.main()
