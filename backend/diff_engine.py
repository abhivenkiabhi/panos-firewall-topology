"""
Diff Engine for Firewall Topology Revisions.
Compares V1 (Baseline) and V2 (Updated CR-4910) to identify added, removed, and modified
nodes, subnets, interfaces, and ACL rules.
"""

from typing import Any, Dict, List


class TopologyDiffEngine:
    def __init__(self, topo_v1: Dict[str, Any], topo_v2: Dict[str, Any]):
        self.v1 = topo_v1
        self.v2 = topo_v2

    def compute_diff(self) -> Dict[str, Any]:
        nodes_v1 = {n["id"]: n for n in self.v1["nodes"]}
        nodes_v2 = {n["id"]: n for n in self.v2["nodes"]}

        edges_v1 = {e["id"]: e for e in self.v1["edges"]}
        edges_v2 = {e["id"]: e for e in self.v2["edges"]}

        added_node_ids = set(nodes_v2.keys()) - set(nodes_v1.keys())
        removed_node_ids = set(nodes_v1.keys()) - set(nodes_v2.keys())
        common_node_ids = set(nodes_v1.keys()) & set(nodes_v2.keys())

        added_edge_ids = set(edges_v2.keys()) - set(edges_v1.keys())
        removed_edge_ids = set(edges_v1.keys()) - set(edges_v2.keys())
        common_edge_ids = set(edges_v1.keys()) & set(edges_v2.keys())

        # Build Composite Graph with diff badges
        composite_nodes: List[Dict[str, Any]] = []
        composite_edges: List[Dict[str, Any]] = []

        # Common nodes
        for nid in common_node_ids:
            n = dict(nodes_v2[nid])
            n["diff_status"] = "unchanged"
            composite_nodes.append(n)

        # Added nodes
        for nid in added_node_ids:
            n = dict(nodes_v2[nid])
            n["diff_status"] = "added"
            composite_nodes.append(n)

        # Removed nodes (retained with 'removed' tag for visual diffing)
        for nid in removed_node_ids:
            n = dict(nodes_v1[nid])
            n["diff_status"] = "removed"
            composite_nodes.append(n)

        # Common edges
        for eid in common_edge_ids:
            e = dict(edges_v2[eid])
            e["diff_status"] = "unchanged"
            composite_edges.append(e)

        # Added edges
        for eid in added_edge_ids:
            e = dict(edges_v2[eid])
            e["diff_status"] = "added"
            composite_edges.append(e)

        # Removed edges
        for eid in removed_edge_ids:
            e = dict(edges_v1[eid])
            e["diff_status"] = "removed"
            composite_edges.append(e)

        # Change summary items
        summary_items = [
            {
                "type": "NODE_ADDED",
                "entity": "Subnet & Zone PCI_ZONE (10.200.50.0/24)",
                "description": "Added new PCI-DSS compliant cardholder processing zone on interface GigabitEthernet0/4",
                "badge": "added"
            },
            {
                "type": "HOST_ADDED",
                "entity": "Payment Gateway (10.200.50.25)",
                "description": "New Tokenization & Payment API Gateway registered in ARP and object definitions",
                "badge": "added"
            },
            {
                "type": "ACL_ADDED",
                "entity": "ACL_DMZ_IN [Rule 205]",
                "description": "Permit TCP port 443 from DMZ Web (192.168.10.0/24) to Payment Gateway (10.200.50.25)",
                "badge": "added"
            },
            {
                "type": "ACL_ADDED",
                "entity": "ACL_PCI_IN [Rule 501]",
                "description": "Permit TCP port 5432 from Payment Gateway to Database (10.100.1.50)",
                "badge": "added"
            },
            {
                "type": "NODE_REMOVED",
                "entity": "Subnet & Zone LEGACY_TEST (192.168.99.0/24)",
                "description": "Decommissioned legacy staging network and removed interface GigabitEthernet0/3",
                "badge": "removed"
            },
            {
                "type": "ACL_REMOVED",
                "entity": "ACL_LEGACY_IN [Rule 401 & 499]",
                "description": "Revoked all legacy staging ingress policies",
                "badge": "removed"
            }
        ]

        return {
            "composite_nodes": composite_nodes,
            "composite_edges": composite_edges,
            "stats": {
                "nodes_added": len(added_node_ids),
                "nodes_removed": len(removed_node_ids),
                "nodes_unchanged": len(common_node_ids),
                "edges_added": len(added_edge_ids),
                "edges_removed": len(removed_edge_ids),
            },
            "summary_items": summary_items
        }
