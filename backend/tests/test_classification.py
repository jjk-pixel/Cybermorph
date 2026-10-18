"""
Classification multi-indices (modèle 2) : type ≠ rôle ≠ services, indices contradictoires, « unknown » par défaut.
Cas exigés : poste Windows avec MySQL, serveur Linux fiable, DNS sans preuve de routeur, port unique, OS inconnu.
"""
import unittest

from app.exposure.criticality import effective_criticality
from app.inventory.classification import classify_asset
from app.models.asset import Asset

WIN11 = [{"type": "general purpose", "vendor": "Microsoft", "osfamily": "Windows", "osgen": "11", "accuracy": "96"}]
LINUX = [{"type": "general purpose", "vendor": "Linux", "osfamily": "Linux", "osgen": "5.X", "accuracy": "98"}]


def roles(result):
    return {r["role"] for r in result["roles"]}


class TypeVersusRoleTest(unittest.TestCase):
    def test_windows_workstation_hosting_mysql_stays_a_workstation(self):
        result = classify_asset([3306], ["mysql"], "VMware", "Microsoft Windows 11 21H2", os_classes=WIN11)
        self.assertEqual(result["type"], "pc")
        self.assertIn("database_server", roles(result))
        # Le service MySQL est publié comme indice contraire, pas ignoré
        self.assertTrue(any(r["type"] == "server" and not r["supports"] for r in result["reasons"]))
        self.assertEqual(result["alternatives"][0]["type"], "server")

    def test_windows_workstation_from_legacy_os_string(self):
        # Données antérieures : nom d'OS sans classes Nmap
        result = classify_asset([3306], ["mysql"], "VMware", "Microsoft Windows 11 21H2")
        self.assertEqual(result["type"], "pc")
        self.assertLess(result["confidence"], 0.5)

    def test_reliably_identified_linux_server(self):
        details = [{"port": 22, "name": "ssh", "product": "OpenSSH", "version": "9.6p1"},
                   {"port": 443, "name": "https", "product": "nginx", "version": "1.24.0"},
                   {"port": 5432, "name": "postgresql", "product": "PostgreSQL DB", "version": None}]
        result = classify_asset([22, 443, 5432], ["ssh", "https", "postgresql"], "Dell", "Linux 5.15", os_classes=LINUX,
                                service_details=details)
        self.assertEqual(result["type"], "server")
        self.assertGreaterEqual(result["confidence"], 0.4)
        self.assertEqual(roles(result), {"ssh_server", "web_server", "database_server"})
        self.assertNotIn("Versions des services inconnues", result["missing"])

    def test_linux_alone_does_not_prove_a_server(self):
        result = classify_asset([22], ["ssh"], None, "Linux 4.15 - 5.19", os_classes=LINUX)
        self.assertEqual((result["type"], result["decision"]), ("unknown", "insufficient"))
        self.assertTrue(any("généraliste" in r["reason"] for r in result["reasons"]))
        self.assertEqual(result["alternatives"][0]["type"], "server")

    def test_dns_port_without_router_evidence(self):
        result = classify_asset([53], ["domain"], "VMware", None)
        self.assertEqual(result["type"], "unknown")
        self.assertIn("dns_server", roles(result))
        self.assertTrue(any("ne prouve pas un routeur" in r["reason"] for r in result["reasons"]))

    def test_gateway_from_routing_table_is_a_router(self):
        result = classify_asset([53], ["domain"], "VMware", "VMware Player virtual NAT device", is_gateway=True)
        self.assertEqual(result["type"], "router")
        self.assertGreaterEqual(result["confidence"], 0.9)
        self.assertEqual(roles(result), {"gateway", "dns_server"})

    def test_single_open_port(self):
        result = classify_asset([8080], ["http-proxy"], None, None)
        self.assertEqual(result["type"], "unknown")
        self.assertEqual(roles(result), {"web_server"})
        self.assertIn("Système d'exploitation non identifié", result["missing"])

    def test_unknown_os_and_nothing_observed(self):
        result = classify_asset([], [], None, None)
        self.assertEqual((result["type"], result["confidence"], result["decision"]), ("unknown", 0.2, "insufficient"))
        self.assertEqual(result["roles"], [])
        self.assertEqual(len(result["missing"]), 3)

    def test_contradictory_evidence_gives_unknown(self):
        # Constructeur réseau (routeur 0.4) contre empreinte de poste Windows (≈0.4) : trop proches pour trancher
        result = classify_asset([], [], "Cisco Systems", "Microsoft Windows 10", os_classes=[{"type": "general purpose", "accuracy": "75"}])
        self.assertEqual((result["type"], result["decision"]), ("unknown", "contradictory"))
        self.assertEqual({a["type"] for a in result["alternatives"]}, {"router", "pc"})

    def test_firewall_and_iot(self):
        fw = classify_asset([443], ["https"], "Fortinet", "FortiOS 7", os_classes=[{"type": "firewall", "accuracy": "95"}])
        self.assertEqual(fw["type"], "firewall")
        printer = classify_asset([631, 9100], ["ipp", "jetdirect"], None, None, os_classes=[{"type": "printer", "accuracy": "90"}])
        self.assertEqual(printer["type"], "iot")
        self.assertIn("printer", roles(printer))

    def test_deterministic(self):
        args = ([22, 80, 3389], ["ssh", "http", "ms-wbt-server"], "VMware", "Microsoft Windows 10")
        self.assertEqual(classify_asset(*args), classify_asset(*args))


class CriticalityFromRolesTest(unittest.TestCase):
    def test_gateway_role_is_critical(self):
        classification = classify_asset([53], ["domain"], "VMware", None, is_gateway=True)
        asset = Asset(asset_type=classification["type"], open_ports="53", services="domain", classification=classification)
        crit = effective_criticality(asset)
        self.assertEqual(crit["level"], "critical")
        self.assertTrue(any("Passerelle" in r for r in crit["reasons"]))

    def test_workstation_with_database_is_high_through_its_role(self):
        classification = classify_asset([3306], ["mysql"], None, "Microsoft Windows 11 21H2")
        asset = Asset(asset_type="pc", open_ports="3306", services="mysql", classification=classification)
        self.assertEqual(effective_criticality(asset)["level"], "high")


if __name__ == "__main__":
    unittest.main()
