"""
Comprehensive Unit Test Suite for Palo Alto Networks (PAN-OS) Engine.
"""

from pathlib import Path
import unittest

from panos_parser import PanOSConfigParser
from panos_log_ingestor import PanOSLogIngestor
from panos_topology_engine import PanOSTopologyEngine
from panos_diff_engine import PanOSDiffEngine
from panos_qa_agent import PanOSQAAgent

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class TestPanOSEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        v1_path = DATA_DIR / "pan_os_v1.set"
        v2_path = DATA_DIR / "pan_os_v2.set"
        log_path = DATA_DIR / "pan_os_traffic.log"

        with open(v1_path, "r") as f:
            cls.v1_raw = f.read()
        with open(v2_path, "r") as f:
            cls.v2_raw = f.read()
        with open(log_path, "r") as f:
            cls.log_raw = f.read()

        cls.parser_v1 = PanOSConfigParser(cls.v1_raw)
        cls.parser_v2 = PanOSConfigParser(cls.v2_raw)
        cls.ingestor = PanOSLogIngestor(cls.log_raw)
        cls.topo_v1 = PanOSTopologyEngine(cls.parser_v1, cls.ingestor)
        cls.topo_v2 = PanOSTopologyEngine(cls.parser_v2, cls.ingestor)
        cls.diff_engine = PanOSDiffEngine(cls.topo_v1, cls.topo_v2)
        cls.qa_agent = PanOSQAAgent(cls.topo_v1, cls.topo_v2, cls.diff_engine, cls.ingestor)

    def test_parser_v1(self):
        self.assertEqual(self.parser_v1.hostname, "PA-NGFW-CORE-01")
        self.assertEqual(self.parser_v1.model, "PA-3410")
        self.assertIn("Untrust", self.parser_v1.zones)
        self.assertIn("DMZ", self.parser_v1.zones)
        self.assertIn("Trust-Internal", self.parser_v1.zones)
        self.assertIn("Legacy-Test", self.parser_v1.zones)
        self.assertGreater(len(self.parser_v1.security_rules), 4)

        # Verify App-ID parsing
        web_rule = next(r for r in self.parser_v1.security_rules if r["name"] == "Allow-Inbound-Web")
        self.assertIn("ssl", web_rule["applications"])
        self.assertIn("web-browsing", web_rule["applications"])
        self.assertEqual(web_rule["action"], "ALLOW")

    def test_parser_v2_pci(self):
        self.assertIn("PCI-Cardholder", self.parser_v2.zones)
        self.assertNotIn("Legacy-Test", self.parser_v2.zones)
        
        rule_pci = next((r for r in self.parser_v2.security_rules if r["name"] == "Allow-DMZ-to-Payment-GW"), None)
        self.assertIsNotNone(rule_pci)
        self.assertEqual(rule_pci["to_zone"], "PCI-Cardholder")
        self.assertIn("ssl", rule_pci["applications"])

    def test_log_ingestor_csv(self):
        self.assertGreater(self.ingestor.stats["total_events"], 5)
        self.assertGreater(self.ingestor.stats["permitted_flows"], 0)
        self.assertGreater(self.ingestor.stats["denied_flows"], 0)
        self.assertIn("ssl", self.ingestor.app_stats)
        self.assertIn("postgresql", self.ingestor.app_stats)

    def test_app_id_simulation(self):
        # 1. External HTTPS to DMZ Web Server with App-ID ssl -> PERMIT
        res1 = self.topo_v2.simulate_panos_packet("198.51.100.45", "192.168.10.80", port=443, app_id="ssl")
        self.assertEqual(res1["action"], "ALLOW")
        self.assertEqual(res1["rule_name"], "Allow-Inbound-Web")

        # 2. External SSH probe to Firewall / DMZ with App-ID ssh -> DROP by Block-Untrust-Scanners
        res2 = self.topo_v2.simulate_panos_packet("198.51.100.22", "192.168.10.80", port=22, app_id="ssh")
        self.assertEqual(res2["action"], "DROP")
        self.assertEqual(res2["rule_name"], "Block-Untrust-Scanners")

        # 3. Direct DMZ Web to DB Server (Postgres 5432) -> DROP by Deny-DMZ-to-DB
        res3 = self.topo_v2.simulate_panos_packet("192.168.10.80", "10.100.1.50", port=5432, app_id="postgresql")
        self.assertEqual(res3["action"], "DROP")
        self.assertEqual(res3["rule_name"], "Deny-DMZ-to-DB")

        # 4. DMZ Web to Payment Gateway (CR-4910) with App-ID ssl -> ALLOW by Allow-DMZ-to-Payment-GW
        res4 = self.topo_v2.simulate_panos_packet("192.168.10.80", "10.200.50.25", port=443, app_id="ssl")
        self.assertEqual(res4["action"], "ALLOW")
        self.assertEqual(res4["rule_name"], "Allow-DMZ-to-Payment-GW")

    def test_diff_engine(self):
        self.assertGreater(self.diff_engine.stats["rules_added"], 0)
        self.assertGreater(self.diff_engine.stats["rules_removed"], 0)
        pci_node = next((n for n in self.diff_engine.composite_nodes if "PCI" in n["id"]), None)
        self.assertIsNotNone(pci_node)
        self.assertEqual(pci_node["diff_status"], "added")

    def test_qa_agent(self):
        # Diff question
        ans_diff = self.qa_agent.answer("What changed in the firewall config in CR-4910?")
        self.assertEqual(ans_diff["category"], "commit_diff")
        self.assertIn("CR-4910", ans_diff["answer"])

        # Drop question
        ans_drop = self.qa_agent.answer("Why was traffic from 198.51.100.22 dropped?")
        self.assertEqual(ans_drop["category"], "log_drop")
        self.assertIn("Block-Untrust-Scanners", ans_drop["answer"])

        # Reachability question
        ans_reach = self.qa_agent.answer("Can DMZ Web reach the Database?")
        self.assertEqual(ans_reach["category"], "reachability")
        self.assertEqual(ans_reach["simulation"]["action"], "DROP")


if __name__ == "__main__":
    unittest.main()
