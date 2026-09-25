"""
Automated unit tests for Firewall Topology Engine.
"""

import unittest
from pathlib import Path

from parser import FirewallConfigParser
from log_ingestor import FirewallLogIngestor
from topology_engine import TopologyEngine
from diff_engine import TopologyDiffEngine
from qa_agent import FirewallQAAgent


class TestFirewallEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data_dir = Path(__file__).resolve().parent.parent / "data"
        cls.v1_raw = (data_dir / "revision_v1.cfg").read_text()
        cls.v2_raw = (data_dir / "revision_v2.cfg").read_text()
        cls.logs_raw = (data_dir / "firewall_traffic.log").read_text()

    def test_parser_v1(self):
        p = FirewallConfigParser(self.v1_raw)
        self.assertEqual(p.hostname, "FW-CORE-01")
        self.assertTrue(len(p.interfaces) >= 4)
        self.assertTrue(len(p.acls) >= 6)
        self.assertTrue(len(p.arp_table) >= 5)
        # Check that legacy test subnet exists in v1
        legacy_iface = next((i for i in p.interfaces if i["zone"] == "LEGACY_TEST"), None)
        self.assertIsNotNone(legacy_iface)
        self.assertEqual(legacy_iface["ip"], "192.168.99.1")

    def test_parser_v2_changes(self):
        p = FirewallConfigParser(self.v2_raw)
        # Check that PCI_ZONE exists in v2
        pci_iface = next((i for i in p.interfaces if i["zone"] == "PCI_ZONE"), None)
        self.assertIsNotNone(pci_iface)
        self.assertEqual(pci_iface["ip"], "10.200.50.1")
        # Legacy test should be gone in v2
        legacy_iface = next((i for i in p.interfaces if i["zone"] == "LEGACY_TEST"), None)
        self.assertIsNone(legacy_iface)

    def test_log_ingestor(self):
        ingestor = FirewallLogIngestor(self.logs_raw)
        self.assertGreater(ingestor.stats["total_events"], 10)
        self.assertGreater(ingestor.stats["permitted_flows"], 0)
        self.assertGreater(ingestor.stats["denied_flows"], 0)
        self.assertGreater(ingestor.stats["total_bytes"], 0)

    def test_topology_and_reachability(self):
        p2 = FirewallConfigParser(self.v2_raw)
        ingestor = FirewallLogIngestor(self.logs_raw)
        topo = TopologyEngine(p2.to_dict(), ingestor.to_dict())
        
        # Test 1: Inbound HTTPS to DMZ Web Server should be PERMITTED (Rule 101)
        sim_https = topo.simulate_packet("198.51.100.45", "192.168.10.80", 443, "TCP")
        self.assertEqual(sim_https["action"], "PERMIT")
        self.assertEqual(sim_https["rule_id"], "101")

        # Test 2: External SSH attempt to Firewall/DMZ should be BLOCKED (Rule 999)
        sim_ssh = topo.simulate_packet("198.51.100.22", "192.168.10.80", 22, "TCP")
        self.assertEqual(sim_ssh["action"], "DENY")
        self.assertEqual(sim_ssh["rule_id"], "999")

        # Test 3: DMZ to DB direct access should be BLOCKED (Rule 203)
        sim_db = topo.simulate_packet("192.168.10.80", "10.100.1.50", 5432, "TCP")
        self.assertEqual(sim_db["action"], "DENY")
        self.assertEqual(sim_db["rule_id"], "203")

        # Test 4: DMZ to Payment Gateway on 443 should be PERMITTED (Rule 205 added in V2)
        sim_payment = topo.simulate_packet("192.168.10.80", "10.200.50.25", 443, "TCP")
        self.assertEqual(sim_payment["action"], "PERMIT")
        self.assertEqual(sim_payment["rule_id"], "205")

    def test_diff_engine(self):
        p1 = FirewallConfigParser(self.v1_raw)
        p2 = FirewallConfigParser(self.v2_raw)
        ingestor = FirewallLogIngestor(self.logs_raw)
        
        topo1 = TopologyEngine(p1.to_dict(), ingestor.to_dict())
        topo2 = TopologyEngine(p2.to_dict(), ingestor.to_dict())
        
        diff = TopologyDiffEngine(topo1.to_dict(), topo2.to_dict())
        result = diff.compute_diff()
        
        self.assertGreater(result["stats"]["nodes_added"], 0)
        self.assertGreater(result["stats"]["nodes_removed"], 0)
        self.assertGreater(len(result["summary_items"]), 0)

    def test_qa_agent(self):
        p1 = FirewallConfigParser(self.v1_raw)
        p2 = FirewallConfigParser(self.v2_raw)
        ingestor = FirewallLogIngestor(self.logs_raw)
        
        topo1 = TopologyEngine(p1.to_dict(), ingestor.to_dict())
        topo2 = TopologyEngine(p2.to_dict(), ingestor.to_dict())
        diff = TopologyDiffEngine(topo1.to_dict(), topo2.to_dict())
        agent = FirewallQAAgent(topo1, topo2, diff, ingestor.to_dict())

        # Test Diff Q
        ans_diff = agent.answer("What changed in the firewall config?")
        self.assertEqual(ans_diff["category"], "topology_diff")
        self.assertIn("CR-4910", ans_diff["answer"])

        # Test Reachability Q
        ans_reach = agent.answer("Can 192.168.10.80 reach 10.200.50.25 on port 443?")
        self.assertEqual(ans_reach["category"], "reachability")
        self.assertEqual(ans_reach["simulation"]["action"], "PERMIT")

        # Test Log Drop Q
        ans_drop = agent.answer("Why was traffic from 198.51.100.22 dropped?")
        self.assertEqual(ans_drop["category"], "log_investigation")
        self.assertIn("198.51.100.22", ans_drop["answer"])


if __name__ == "__main__":
    unittest.main()
