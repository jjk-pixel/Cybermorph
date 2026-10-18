"""
Lot E — vulnérabilités : versions, CPE, statuts de correspondance, données incomplètes, source indisponible,
décision de l'opérateur, effet sur le risque. Flux de test SYNTHÉTIQUE (CVE-0000-*), aucune CVE réelle.
"""
import unittest
from datetime import datetime, UTC
from pathlib import Path

from fastapi import HTTPException
from pydantic import ValidationError

from app.api.vulnerabilities import FindingDecision, decide_finding, list_findings
from app.models.asset import Asset
from app.models.vulnerability import VulnerabilityFinding
from app.risk.risk_engine import calculate_risk
from app.risk.signals import collect_signals
from app.vulnerabilities.matcher import match
from app.vulnerabilities.service import refresh_findings, software_inventory
from app.vulnerabilities.sources import LocalFeedSource, NvdApiSource, SourceUnavailable, VulnerabilitySource
from app.vulnerabilities.versions import compare, in_range, parse_cpe
from tests.test_engines import make_session

FEED = Path(__file__).parent / "fixtures" / "nvd_synthetic.json"
NOW = datetime(2026, 10, 18, 12, 0, tzinfo=UTC)


def service(port, name, product, version, cpe, extrainfo=None):
    return {"port": port, "proto": "tcp", "name": name, "product": product, "version": version, "cpe": cpe, "extrainfo": extrainfo}


class VersionTest(unittest.TestCase):
    def test_compare(self):
        self.assertEqual(compare("9.6p1", "9.8"), -1)
        self.assertEqual(compare("8.0.36", "8.0.30"), 1)
        self.assertEqual(compare("1.24.0", "1.24.0"), 0)
        self.assertEqual(compare("9.6", "9.6.1"), -1)
        self.assertIsNone(compare("9.6", "9.6p1"))     # suffixe alphabétique : ambigu
        self.assertIsNone(compare(None, "1.0"))
        self.assertIsNone(compare("abc", "1.0"))

    def test_ranges(self):
        self.assertTrue(in_range("9.6p1", {"start_including": "8.5", "end_excluding": "9.8"}))
        self.assertFalse(in_range("9.8p1", {"start_including": "8.5", "end_excluding": "9.8"}))
        self.assertIsNone(in_range("1.0", {}))         # « toutes versions » : trop vague

    def test_cpe(self):
        self.assertEqual(parse_cpe("cpe:/a:openbsd:openssh:9.6p1"), {"part": "a", "vendor": "openbsd", "product": "openssh", "version": "9.6p1"})
        self.assertEqual(parse_cpe("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*")["version"], None)
        self.assertIsNone(parse_cpe("cpe:/a:mysql"))
        self.assertIsNone(parse_cpe("openssh"))


class MatchTest(unittest.TestCase):
    def setUp(self):
        self.source = LocalFeedSource(str(FEED))

    def record(self, vendor, product, cve):
        return next(r for r in self.source.lookup(vendor, product) if r["cve_id"] == cve)

    def test_statuses(self):
        rec = self.record("openbsd", "openssh", "CVE-0000-0001")
        base = {"vendor": "openbsd", "product": "openssh"}
        self.assertEqual(match({**base, "version": "9.6p1", "banner": "OpenSSH 9.6p1"}, rec)["status"], "probable")
        distro = match({**base, "version": "9.6p1", "banner": "OpenSSH 9.6p1 Ubuntu 3ubuntu13.5"}, rec)
        self.assertEqual(distro["status"], "uncertain")
        self.assertIn("rétroporté", distro["reason"])
        self.assertEqual(match({**base, "version": None, "banner": ""}, rec)["status"], "uncertain")
        self.assertIsNone(match({**base, "version": "9.9p1", "banner": ""}, rec))
        self.assertIsNone(match({"vendor": "other", "product": "openssh", "version": "9.6p1"}, rec))

    def test_invalid_records_are_ignored(self):
        ids = {r["cve_id"] for key in [("openbsd", "openssh"), ("nginx", "nginx"), ("mysql", "mysql")] for r in self.source.lookup(*key)}
        self.assertEqual(ids, {"CVE-0000-0001", "CVE-0000-0002", "CVE-0000-0003"})


class BrokenSource(VulnerabilitySource):
    name = "broken"

    def available(self):
        return True

    def lookup(self, vendor, product):
        raise SourceUnavailable("hors service")


class RefreshTest(unittest.TestCase):
    def setUp(self):
        self.db = make_session()
        self.db.add_all([
            Asset(id=1, name="srv", ip_address="10.0.0.10", asset_type="server", status="up", open_ports="22,443,3306",
                  os_detected="Linux", mac_address="00:11:22:33:44:55", last_seen=NOW,
                  classification={"services": [
                      service(22, "ssh", "OpenSSH", "9.6p1", "cpe:/a:openbsd:openssh:9.6p1"),
                      service(443, "https", "nginx", "1.24.0", "cpe:/a:nginx:nginx:1.24.0"),
                      service(3306, "mysql", "MySQL", None, "cpe:/a:mysql:mysql"),
                      service(8080, "http-proxy", None, None, None),
                  ]}),
            Asset(id=2, name="pc", ip_address="10.0.0.20", asset_type="pc", status="up", open_ports="80",
                  classification={"services": [{"port": 80, "name": "http"}]}),
        ])
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_no_source_means_not_evaluated(self):
        stats = refresh_findings(self.db, [], NOW)
        self.assertEqual(stats["status"], "skipped")
        self.assertIn("pas une absence", stats["note"])
        self.assertEqual(self.db.query(VulnerabilityFinding).count(), 0)

    def test_inventory_needs_a_cpe(self):
        inventory = software_inventory(self.db)
        self.assertEqual([(i["port"], i["matchable"]) for i in inventory], [(22, True), (443, True), (3306, True)])

    def test_findings_and_incomplete_data(self):
        stats = refresh_findings(self.db, [LocalFeedSource(str(FEED))], NOW)
        self.assertEqual((stats["matchable"], stats["findings_new"]), (3, 3))
        by_cve = {f.cve_id: f for f in self.db.query(VulnerabilityFinding).all()}
        self.assertEqual(by_cve["CVE-0000-0001"].status, "probable")
        self.assertEqual(by_cve["CVE-0000-0001"].cvss_score, 8.1)
        nginx = by_cve["CVE-0000-0002"]
        self.assertEqual((nginx.status, nginx.cvss_score, nginx.severity), ("probable", None, None))  # CVSS absent : conservé vide
        self.assertEqual(by_cve["CVE-0000-0003"].status, "uncertain")  # version MySQL inconnue
        # Données de vulnérabilité incomplètes : rien n'est compté tant que rien n'est confirmé
        ctx = collect_signals(self.db, NOW)[1]
        self.assertEqual(calculate_risk(self.db.get(Asset, 1), ctx, NOW)["breakdown"]["vulnerabilites"], 0.0)

    def test_operator_decision_is_kept_and_counts(self):
        refresh_findings(self.db, [LocalFeedSource(str(FEED))], NOW)
        f = self.db.query(VulnerabilityFinding).filter_by(cve_id="CVE-0000-0001").one()
        out = decide_finding(f.id, FindingDecision(status="confirmed", note="Version vérifiée sur l'hôte"), self.db)
        self.assertEqual(out["status"], "confirmed")
        refresh_findings(self.db, [LocalFeedSource(str(FEED))], NOW)
        self.assertEqual(self.db.get(VulnerabilityFinding, f.id).status, "confirmed")
        ctx = collect_signals(self.db, NOW)[1]
        self.assertEqual(calculate_risk(self.db.get(Asset, 1), ctx, NOW)["breakdown"]["vulnerabilites"], 20.2)  # 8,1 × 10 × 25 %
        with self.assertRaises(ValidationError):
            FindingDecision(status="probable", note="x" * 5)
        with self.assertRaises(HTTPException):
            decide_finding(999, FindingDecision(status="rejected", note="faux positif"), self.db)

    def test_upgraded_software_is_no_longer_matched(self):
        refresh_findings(self.db, [LocalFeedSource(str(FEED))], NOW)
        asset = self.db.get(Asset, 1)
        services = list(asset.classification["services"])
        services[0] = service(22, "ssh", "OpenSSH", "9.9p1", "cpe:/a:openbsd:openssh:9.9p1")
        asset.classification = {"services": services}
        self.db.commit()
        stats = refresh_findings(self.db, [LocalFeedSource(str(FEED))], NOW)
        self.assertEqual(stats["not_observed"], 1)
        self.assertEqual(self.db.query(VulnerabilityFinding).filter_by(cve_id="CVE-0000-0001").one().status, "not_observed")
        self.assertEqual(len(list_findings(self.db, asset_id=1, status="probable", limit=200, offset=0)), 1)

    def test_unavailable_source_does_not_block_nor_erase(self):
        refresh_findings(self.db, [LocalFeedSource(str(FEED))], NOW)
        stats = refresh_findings(self.db, [BrokenSource()], NOW)
        self.assertEqual(stats["status"], "partial")
        self.assertEqual(stats["errors"][0]["source"], "broken")
        self.assertEqual(self.db.query(VulnerabilityFinding).filter_by(status="not_observed").count(), 0)

    def test_nvd_api_is_off_by_default_and_failures_are_contained(self):
        self.assertFalse(NvdApiSource(False).available())

        def failing_opener(request, timeout):
            raise OSError("réseau indisponible")
        api = NvdApiSource(True, opener=failing_opener, max_lookups=1)
        with self.assertRaises(SourceUnavailable):
            api.lookup("openbsd", "openssh")
        with self.assertRaisesRegex(SourceUnavailable, "Limite"):
            api.lookup("nginx", "nginx")


if __name__ == "__main__":
    unittest.main()
