"""
Lot 4 — preuves sources des alertes (fast.log, flow_id eve), snapshots complets, reconstitution historique,
chaînes de traçabilité.
"""
import json
import tempfile
import unittest
from unittest import mock
from datetime import datetime, timedelta, UTC
from pathlib import Path

import app.collectors.suricata_collector as suricata
import app.collectors.snapshot_collector as snapshot_collector
from app.api.history import state_at
from app.api.inventory import list_changes
from app.api.timeline import get_snapshot, list_snapshots
from app.api.trace import trace_alert, trace_deviation, trace_incident
from app.behavior.baseline import process_events
from app.inventory.observations import record_observation, set_setting
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.behavior import Communication, Deviation
from app.models.incident import Incident
from app.models.network_connection import NetworkConnection
from app.models.observation import AssetChange, AssetObservation
from app.models.snapshot import Snapshot
from tests.test_behavior import NET, flow
from tests.test_engines import make_session

NOW = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
FAST = "10/20/2026-12:00:00.000000  [**] [1:2010493:3] ET SCAN Non-Allowed Host Tried to Connect to MySQL Server [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.0.0.5:51000 -> 10.0.0.10:3306"


def eve_alert(flow_id):
    return json.dumps({"timestamp": "2026-10-20T12:00:00.000000+0000", "flow_id": flow_id, "event_type": "alert",
                       "src_ip": "10.0.0.5", "src_port": 51000, "dest_ip": "10.0.0.10", "dest_port": 3306, "proto": "TCP",
                       "alert": {"gid": 1, "signature_id": 2010493, "rev": 3, "signature": "ET SCAN"}}, separators=(",", ":"))


class SourceEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.db = make_session()
        self.db.add_all([
            Asset(id=1, name="poste", ip_address="10.0.0.5", asset_type="pc", status="up", created_at=NOW - timedelta(days=9)),
            Asset(id=2, name="bdd", ip_address="10.0.0.10", asset_type="server", status="up", created_at=NOW - timedelta(days=9)),
        ])
        self.db.commit()
        set_setting(self.db, "learning", {"started_at": (NOW - timedelta(hours=1)).isoformat(), "hours": 48})
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_fast_log_offsets_point_to_the_raw_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fast.log"
            path.write_text("ligne non reconnue\n" + FAST + "\n" + FAST + "\n")
            records = suricata.parse_fast_log_lines(path.read_text().splitlines(), 0)
            self.assertEqual(len(records), 2)
            with open(path, "rb") as f:
                f.seek(records[1]["_raw"]["offset"])
                self.assertEqual(f.readline().decode().strip(), FAST)

    def test_full_chain_alert_to_flow_to_activity_to_path(self):
        alert = Alert(source_ip="10.0.0.5", destination_ip="10.0.0.10", source_asset_id=1, destination_asset_id=2,
                      signature_id="1:2010493:3", message="ET SCAN Non-Allowed Host Tried to Connect to MySQL Server",
                      priority=2, occurrence_count=1, first_seen=NOW, last_seen=NOW,
                      evidence={"fast_log_first": {"path": "/var/log/suricata/fast.log", "offset": 0, "line": FAST}})
        self.db.add(alert)
        self.db.commit()
        stats = process_events(self.db, [eve_alert(4242), flow("10.0.0.5", "10.0.0.10", 3306, flow_id=4242)], NOW, NET)
        self.db.commit()
        self.assertEqual(stats["alerts_linked"], 1)
        self.db.add(Incident(status="detected", source_asset_id=1, current_asset_id=2, metadata_json={"trigger_alert_id": alert.id}))
        self.db.commit()

        trace = trace_alert(alert.id, self.db)
        self.assertEqual(trace["sources"]["eve_flow_ids"], [4242])
        self.assertEqual(trace["sources"]["fast_log_first"]["line"], FAST)
        self.assertEqual(trace["communications"][0]["link"], "exact (flow_id)")
        self.assertEqual(trace["incidents"][0]["link"], "déclencheur")
        self.assertTrue(any(p["nodes"][:2] == [1, 2] for p in trace["attack_paths"]))

        incident = self.db.query(Incident).one()
        chain = trace_incident(incident.id, self.db)
        self.assertEqual(chain["trigger"]["alert"]["id"], alert.id)

    def test_legacy_alert_says_what_is_missing(self):
        alert = Alert(source_ip="10.0.0.5", destination_ip="10.0.0.10", message="ancienne", priority=3,
                      occurrence_count=1, first_seen=NOW, last_seen=NOW)
        self.db.add(alert)
        self.db.commit()
        self.assertIsNotNone(trace_alert(alert.id, self.db)["sources"]["note"])

    def test_deviation_trace(self):
        set_setting(self.db, "learning", {"started_at": (NOW - timedelta(days=9)).isoformat(), "hours": 48})
        self.db.commit()
        process_events(self.db, [flow("10.0.0.5", "10.0.0.10", 8080, flow_id=7)], NOW, NET)
        self.db.commit()
        d = self.db.query(Deviation).one()
        trace = trace_deviation(d.id, self.db)
        self.assertEqual(trace["communication"]["details"]["flow_ids"], [7])


class HistoryTest(unittest.TestCase):
    def test_snapshot_state_and_reconstruction_with_coverage(self):
        db = make_session()
        db.add_all([
            Asset(id=1, name="a", ip_address="10.0.0.5", asset_type="pc", status="up", risk_score=10, open_ports="22"),
            Asset(id=2, name="b", ip_address="10.0.0.10", asset_type="server", status="up", risk_score=30),
            NetworkConnection(source_asset_id=1, destination_asset_id=2, protocol="tcp", port=22, connection_type="detected", status="active", source="suricata_flow"),
        ])
        db.add(Snapshot(captured_at=NOW - timedelta(days=30), assets_summary=[], connections_count={}, alerts_summary=[], attack_paths_count=0))
        db.commit()

        # La session de test reste ouverte après la capture (close neutralisé le temps de l'appel)
        with mock.patch.object(snapshot_collector, "SessionLocal", lambda: db), mock.patch.object(db, "close", lambda: None):
            snapshot_collector.capture_snapshot()
        latest = db.query(Snapshot).order_by(Snapshot.id.desc()).first()
        self.assertEqual(latest.state["relations"][0]["origin"], "suricata_flow")
        self.assertEqual({a["criticality"] for a in latest.state["assets"]}, {"medium", "high"})
        listing = list_snapshots(db, limit=10, offset=0)
        self.assertEqual([s["has_state"] for s in listing], [True, False])
        self.assertIsNotNone(get_snapshot(latest.id, db)["state"])

        t1, t2 = NOW - timedelta(hours=2), NOW - timedelta(hours=1)
        record_observation(db, "10.0.0.5", "nmap", "open_port", "22", 1, t1)
        obs80 = record_observation(db, "10.0.0.5", "nmap", "open_port", "80", 1, t1)
        obs80.retired_at = t2
        db.add(AssetChange(asset_id=1, ip="10.0.0.5", change_type="port_closed", severity="info", explanation="80 fermé",
                           detected_at=t2))
        db.commit()

        old = state_at(NOW - timedelta(days=29), db)
        self.assertFalse(old["coverage"]["topology"])
        self.assertEqual(len(old["coverage"]["notes"]), 3)
        between = state_at(t1 + timedelta(minutes=30), db)
        self.assertEqual(between["inventory"]["1"]["open_ports"], [22, 80])
        after = state_at(t2 + timedelta(minutes=1), db)
        self.assertEqual(after["inventory"]["1"]["open_ports"], [22])
        window = list_changes(db, limit=10, asset_id=None, min_severity="info", include_acknowledged=True,
                              since=t1, until=t2)
        self.assertEqual([c["change_type"] for c in window], ["port_closed"])


if __name__ == "__main__":
    unittest.main()
