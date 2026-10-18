"""
Lot 3 — lecture d'eve.json, activités, référence comportementale, écarts explicables, balayages, topologie
observée et signaux de risque. Les flux sont construits au format eve de Suricata ; aucun capteur n'est lancé.
"""
import gzip
import ipaddress
import json
import tempfile
import unittest
from datetime import datetime, timedelta, UTC
from pathlib import Path

from app.api.behavior import acknowledge, behavior_summary, learn, list_communications, list_deviations
from app.behavior.baseline import (
    PORT_SCAN_THRESHOLD, classify_scope, flow_established, mac_from_eui64, process_events,
)
from app.behavior.eve_reader import read_new_lines
from app.inventory.observations import record_observation, set_setting
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.behavior import Communication, Deviation
from app.models.network_connection import NetworkConnection
from app.models.observation import AssetObservation
from app.risk.risk_engine import calculate_risk
from app.risk.signals import collect_signals
from tests.test_engines import make_session

NET = [ipaddress.ip_network("10.0.0.0/24")]
NOW = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)


def flow(src, dst, dport, proto="TCP", app=None, established=True, rst=False, ts=NOW, flow_id=1, toclient=1, bytes_=100):
    event = {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"), "flow_id": flow_id, "event_type": "flow",
        "src_ip": src, "src_port": 50000, "dest_ip": dst, "dest_port": dport, "proto": proto,
        "flow": {"pkts_toserver": 2, "pkts_toclient": toclient if (established or rst) else 0,
                 "bytes_toserver": bytes_, "bytes_toclient": bytes_, "start": ts.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
                 "end": ts.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"), "state": "closed"},
    }
    if app:
        event["app_proto"] = app
    if proto == "TCP":
        event["tcp"] = {"tcp_flags_tc": "12" if established else ("14" if rst else "00")}
    return json.dumps(event, separators=(",", ":"))


def dhcp(mac, ip, hostname=None):
    d = {"type": "reply", "client_mac": mac, "assigned_ip": ip, "dhcp_type": "ack"}
    if hostname:
        d["hostname"] = hostname
    return json.dumps({"timestamp": NOW.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"), "event_type": "dhcp",
                       "src_ip": "10.0.0.1", "dest_ip": ip, "proto": "UDP", "dhcp": d}, separators=(",", ":"))


class ReaderTest(unittest.TestCase):
    def test_incremental_partial_line_truncation_and_rotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "eve.json"
            head = "x" * 600  # empreinte de rotation calculée sur les 512 premiers octets
            path.write_text(f'{{"a":"{head}"}}\n{{"b":2}}\n{{"c":')
            lines, state, _ = read_new_lines(path, None)
            self.assertEqual(len(lines), 2)  # ligne incomplète non consommée
            with open(path, "a") as f:
                f.write('3}\n{"d":4}\n')
            lines, state, _ = read_new_lines(path, state)
            self.assertEqual(lines, ['{"c":3}', '{"d":4}'])

            # Rotation : l'ancien fichier compressé contient une fin non lue
            with open(path, "a") as f:
                f.write('{"e":5}\n')
            with gzip.open(Path(tmp) / "eve.json.1.gz", "wb") as gz:
                gz.write(path.read_bytes())
            path.unlink()
            path.write_text('{"f":6}\n')
            lines, state, info = read_new_lines(path, state)
            self.assertTrue(info["rotated"])
            self.assertEqual(lines, ['{"e":5}', '{"f":6}'])

            path.write_text("")  # copytruncate
            lines, state, info = read_new_lines(path, state)
            self.assertTrue(info["truncated"])
            self.assertIsNone(read_new_lines(Path(tmp) / "absent.json", None))


class FlowPrimitivesTest(unittest.TestCase):
    def test_scope(self):
        self.assertEqual(classify_scope("10.0.0.5", NET), "local")
        self.assertEqual(classify_scope("10.0.0.255", NET), "broadcast")
        self.assertEqual(classify_scope("239.255.255.250", NET), "multicast")
        self.assertEqual(classify_scope("fe80::1", NET), "link-local")
        self.assertEqual(classify_scope("172.16.0.4", NET), "routed")
        self.assertEqual(classify_scope("34.149.66.165", NET), "external")

    def test_eui64(self):
        self.assertEqual(mac_from_eui64("fe80:0000:0000:0000:020c:29ff:fe20:c893"), "00:0C:29:20:C8:93")
        self.assertIsNone(mac_from_eui64("fe80::1234:5678:9abc:def0"))
        self.assertIsNone(mac_from_eui64("10.0.0.1"))

    def test_rst_is_not_an_established_connection(self):
        self.assertTrue(flow_established(json.loads(flow("10.0.0.5", "10.0.0.10", 22))))
        self.assertFalse(flow_established(json.loads(flow("10.0.0.5", "10.0.0.10", 22, established=False, rst=True))))
        self.assertTrue(flow_established(json.loads(flow("10.0.0.5", "10.0.0.10", 53, proto="UDP"))))


class BaselineTest(unittest.TestCase):
    def setUp(self):
        self.db = make_session()
        old = NOW - timedelta(days=30)
        self.db.add_all([
            Asset(id=1, name="poste", ip_address="10.0.0.5", asset_type="pc", status="up", created_at=old, authorization="authorized"),
            Asset(id=2, name="srv", ip_address="10.0.0.10", asset_type="server", status="up", created_at=old, open_ports="22"),
            Asset(id=3, name="capteur", ip_address="10.0.0.99", asset_type="server", status="up", created_at=old, is_scanner=True),
            Asset(id=4, name="poste2", ip_address="10.0.0.6", asset_type="pc", status="up", created_at=old),
            Asset(id=5, name="imprimante", ip_address="10.0.0.20", asset_type="unknown", status="up", created_at=old),
        ])
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def learning(self, active: bool):
        start = NOW - timedelta(hours=1) if active else NOW - timedelta(days=10)
        set_setting(self.db, "learning", {"started_at": start.isoformat(), "hours": 48})
        self.db.commit()

    def run_lines(self, lines, now=NOW):
        stats = process_events(self.db, lines, now, NET)
        self.db.commit()
        return stats

    def test_learning_then_deviation(self):
        self.learning(True)
        self.run_lines([flow("10.0.0.5", "10.0.0.10", 22, app="ssh")])
        comm = self.db.query(Communication).one()
        self.assertEqual((comm.baseline_state, comm.learned_via), ("baseline", "global_learning"))

        self.learning(False)
        stats = self.run_lines([flow("10.0.0.5", "10.0.0.10", 22, app="ssh"), flow("10.0.0.5", "10.0.0.20", 9100)])
        self.assertEqual(stats["deviations_new"], 1)
        deviation = self.db.query(Deviation).one()
        self.assertEqual((deviation.kind, deviation.severity), ("new_communication", "notice"))
        self.assertIn("10.0.0.5 → 10.0.0.20 en tcp/9100", deviation.explanation)

    def test_severity_factors_and_adaptive_attenuation(self):
        self.learning(True)
        self.run_lines([flow("10.0.0.5", "10.0.0.20", 9100)])
        self.learning(False)
        # Port à risque vers une cible critique (serveur) : à vérifier
        self.run_lines([flow("10.0.0.6", "10.0.0.10", 23)])
        # Même activité qu'un autre actif connu : simple information
        self.run_lines([flow("10.0.0.6", "10.0.0.20", 9100)])
        by_port = {d.evidence.get("communication_id"): d for d in self.db.query(Deviation).all()}
        severities = {self.db.get(Communication, cid).dst_port: d.severity for cid, d in by_port.items()}
        self.assertEqual(severities, {23: "warning", 9100: "info"})
        telnet = next(d for d in by_port.values() if d.severity == "warning")
        self.assertTrue(any("Telnet" in r for r in telnet.reasons))
        self.assertTrue(any("critique" in r for r in telnet.reasons))

    def test_ids_alert_on_same_pair_is_correlated(self):
        self.learning(False)
        self.db.add(Alert(source_ip="10.0.0.6", destination_ip="10.0.0.20", message="ET POLICY test", priority=2,
                          occurrence_count=1, first_seen=NOW, last_seen=NOW))
        self.db.commit()
        self.run_lines([flow("10.0.0.6", "10.0.0.20", 8080)])
        deviation = self.db.query(Deviation).one()
        self.assertEqual(deviation.severity, "warning")
        self.assertTrue(deviation.evidence["alert_ids"])

    def test_scanner_probes_and_unanswered_tcp_are_never_learned(self):
        self.learning(True)
        stats = self.run_lines([
            flow("10.0.0.99", "10.0.0.10", 22),                                  # sonde du capteur
            flow("10.0.0.99", "34.149.66.165", 443, app="tls"),                   # mais sa sortie Internet est réelle
            flow("10.0.0.5", "10.0.0.10", 8443, established=False, rst=True),     # RST : pas une communication
        ])
        self.assertEqual((stats["probes_excluded"], stats["unanswered"]), (1, 1))
        comms = self.db.query(Communication).all()
        self.assertEqual([(c.src_ip, c.dst_key) for c in comms], [("10.0.0.99", "external")])
        self.assertEqual(comms[0].details["destinations"], ["34.149.66.165"])

    def test_port_scan_from_a_non_scanner(self):
        self.learning(False)
        lines = [flow("10.0.0.6", "10.0.0.10", 1000 + i, established=False, rst=True, flow_id=i) for i in range(PORT_SCAN_THRESHOLD)]
        self.run_lines(lines)
        scan = self.db.query(Deviation).filter_by(kind="port_scan").one()
        self.assertEqual((scan.severity, scan.evidence["distinct_ports"]), ("warning", PORT_SCAN_THRESHOLD))
        self.run_lines(lines)  # même balayage dans l'heure : regroupé
        self.assertEqual(self.db.query(Deviation).filter_by(kind="port_scan").one().occurrences, 2)
        # Le même volume venant du scanner déclaré est ignoré
        self.run_lines([flow("10.0.0.99", "10.0.0.5", 2000 + i, established=False) for i in range(30)])
        self.assertEqual(self.db.query(Deviation).filter_by(kind="port_scan").count(), 1)

    def test_unknown_local_host_is_flagged_once(self):
        self.learning(True)
        self.run_lines([flow("10.0.0.77", "10.0.0.10", 22), flow("10.0.0.77", "10.0.0.10", 80, flow_id=2)])
        unknown = self.db.query(Deviation).filter_by(kind="unknown_host").all()
        self.assertEqual(len(unknown), 1)
        self.assertEqual(unknown[0].severity, "warning")

    def test_dhcp_identity_and_eui64_resolution(self):
        self.learning(True)
        self.run_lines([dhcp("00:0c:29:20:c8:93", "10.0.0.99", "capteur")])
        obs = {(o.source, o.attribute, o.value) for o in self.db.query(AssetObservation).all()}
        self.assertIn(("dhcp", "mac", "00:0C:29:20:C8:93"), obs)
        self.assertIn(("dhcp", "hostname", "capteur"), obs)
        # Le lien-local IPv6 dérivé de cette MAC est rattaché au capteur (donc traité comme scanner)
        stats = self.run_lines([flow("fe80:0000:0000:0000:020c:29ff:fe20:c893", "ff02::fb", 5353, proto="UDP", app="mdns")])
        comm = self.db.query(Communication).one()
        self.assertEqual((comm.src_ip, comm.src_asset_id, comm.dst_scope), ("10.0.0.99", 3, "multicast"))
        self.assertEqual(stats["probes_excluded"], 0)

    def test_observed_relations_are_deduplicated_and_expire(self):
        self.learning(True)
        self.run_lines([flow("10.0.0.5", "10.0.0.10", 22, flow_id=i) for i in range(5)])
        relations = self.db.query(NetworkConnection).all()
        self.assertEqual(len(relations), 1)
        self.assertEqual((relations[0].connection_type, relations[0].source, relations[0].port), ("detected", "suricata_flow", 22))
        self.run_lines([], now=NOW + timedelta(hours=25))
        self.assertEqual(self.db.query(NetworkConnection).one().status, "inactive")

    def test_learn_and_acknowledge_via_api(self):
        self.learning(False)
        self.run_lines([flow("10.0.0.5", "10.0.0.20", 9100), flow("10.0.0.6", "10.0.0.10", 1000 + 0)])
        deviations = list_deviations(self.db, status="open", asset_id=None, limit=50)
        self.assertEqual(len(deviations), 2)
        learned = learn(deviations[-1]["id"], self.db)
        self.assertEqual(learned["status"], "learned")
        acknowledged = acknowledge(deviations[0]["id"], self.db)
        self.assertEqual(acknowledged["status"], "acknowledged")
        states = {c["dst_port"]: c["baseline_state"] for c in list_communications(self.db, asset_id=None, state=None, limit=50)}
        self.assertIn("accepted", states.values())
        self.assertIn("new", states.values())  # acquitter n'apprend pas
        summary = behavior_summary(self.db)
        self.assertEqual(summary["deviations"], {"open": 0, "acknowledged": 1, "learned": 1})
        # L'activité apprise ne produit plus d'écart
        self.run_lines([flow("10.0.0.5", "10.0.0.20", 9100)] if states.get(9100) == "accepted" else [flow("10.0.0.6", "10.0.0.10", 1000)])
        self.assertEqual(self.db.query(Deviation).count(), 2)

    def test_scan_cannot_be_learned(self):
        self.learning(False)
        self.run_lines([flow("10.0.0.6", "10.0.0.10", 1000 + i, established=False, rst=True) for i in range(PORT_SCAN_THRESHOLD)])
        from fastapi import HTTPException
        with self.assertRaises(HTTPException):
            learn(self.db.query(Deviation).one().id, self.db)


class RiskSignalsTest(unittest.TestCase):
    def test_signals_raise_behavior_and_visibility_feeds_confidence(self):
        db = make_session()
        db.add(Asset(id=1, name="a", ip_address="10.0.0.5", asset_type="pc", status="up", os_detected="Linux",
                     mac_address="00:11:22:33:44:55", last_seen=datetime.now(UTC)))
        db.add(Asset(id=2, name="b", ip_address="10.0.0.10", asset_type="server", status="up", last_seen=datetime.now(UTC)))
        now = datetime.now(UTC)
        db.add(Deviation(kind="new_communication", severity="warning", status="open", src_asset_id=1, dst_asset_id=2,
                         explanation="x", first_seen=now, last_seen=now, occurrences=1))
        db.add(Communication(src_ip="10.0.0.5", dst_key="10.0.0.10", dst_scope="local", src_asset_id=1, dst_asset_id=2,
                             proto="TCP", dst_port=22, app_proto="", first_seen=now, last_seen=now, flow_count=1,
                             established_count=1, bytes_toserver=0, bytes_toclient=0, baseline_state="new"))
        db.add(Alert(source_ip="10.0.0.5", destination_ip="10.0.0.10", message="m", priority=1, occurrence_count=1,
                     first_seen=now, last_seen=now))
        db.commit()
        signals = collect_signals(db)
        a = db.get(Asset, 1)
        without = calculate_risk(a)
        with_ctx = calculate_risk(a, signals[1])
        self.assertEqual(without["breakdown"]["signaux_comportementaux"], 0)
        # Écart (80) + alerte émise (+10) = 90 → 22,5 points sur 25
        self.assertEqual(with_ctx["breakdown"]["signaux_comportementaux"], 22.5)
        self.assertEqual(with_ctx["confidence"]["value"], 1.0)
        b = calculate_risk(db.get(Asset, 2), signals[2])
        self.assertLess(b["confidence"]["value"], 1.0)  # OS et MAC inconnus
        db.close()


if __name__ == "__main__":
    unittest.main()
