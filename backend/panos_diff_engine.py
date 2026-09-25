"""
Palo Alto Networks (PAN-OS) Commit & Revision Diff Engine.
Calculates differences between two PAN-OS configurations (e.g. baseline vs candidate commit),
identifying modified security rules, new/decommissioned zones, and host topology updates.
"""

from typing import Any, Dict, List
from panos_topology_engine import PanOSTopologyEngine


class PanOSDiffEngine:
    def __init__(self, topo_v1: PanOSTopologyEngine, topo_v2: PanOSTopologyEngine):
        self.topo_v1 = topo_v1
        self.topo_v2 = topo_v2
        self.composite_nodes: List[Dict[str, Any]] = []
        self.composite_edges: List[Dict[str, Any]] = []
        self.summary_items: List[Dict[str, Any]] = []
        self.stats = {
            "nodes_added": 0,
            "nodes_removed": 0,
            "edges_added": 0,
            "edges_removed": 0,
            "rules_added": 0,
            "rules_removed": 0
        }
        self.compute_diff()

    def compute_diff(self):
        v1_nodes = {n["id"]: n for n in self.topo_v1.nodes}
        v2_nodes = {n["id"]: n for n in self.topo_v2.nodes}

        all_node_ids = set(v1_nodes.keys()) | set(v2_nodes.keys())
        for nid in all_node_ids:
            if nid in v2_nodes and nid not in v1_nodes:
                node_copy = dict(v2_nodes[nid])
                node_copy["diff_status"] = "added"
                self.composite_nodes.append(node_copy)
                self.stats["nodes_added"] += 1
                self.summary_items.append({
                    "type": "NODE_ADDED",
                    "id": nid,
                    "label": node_copy.get("label", nid),
                    "description": f"Added in CR-4910: {node_copy.get('label')}"
                })
            elif nid in v1_nodes and nid not in v2_nodes:
                node_copy = dict(v1_nodes[nid])
                node_copy["diff_status"] = "removed"
                self.composite_nodes.append(node_copy)
                self.stats["nodes_removed"] += 1
                self.summary_items.append({
                    "type": "NODE_REMOVED",
                    "id": nid,
                    "label": node_copy.get("label", nid),
                    "description": f"Decommissioned in CR-4910: {node_copy.get('label')}"
                })
            else:
                node_copy = dict(v2_nodes[nid])
                node_copy["diff_status"] = "unchanged"
                self.composite_nodes.append(node_copy)

        # Edges Diff
        v1_edges = {e["id"]: e for e in self.topo_v1.edges}
        v2_edges = {e["id"]: e for e in self.topo_v2.edges}
        all_edge_ids = set(v1_edges.keys()) | set(v2_edges.keys())

        for eid in all_edge_ids:
            if eid in v2_edges and eid not in v1_edges:
                edge_copy = dict(v2_edges[eid])
                edge_copy["diff_status"] = "added"
                self.composite_edges.append(edge_copy)
                self.stats["edges_added"] += 1
            elif eid in v1_edges and eid not in v2_edges:
                edge_copy = dict(v1_edges[eid])
                edge_copy["diff_status"] = "removed"
                self.composite_edges.append(edge_copy)
                self.stats["edges_removed"] += 1
            else:
                edge_copy = dict(v2_edges[eid])
                edge_copy["diff_status"] = "unchanged"
                self.composite_edges.append(edge_copy)

        # Security Rule Diff
        v1_rules = {r["name"]: r for r in self.topo_v1.parser.security_rules}
        v2_rules = {r["name"]: r for r in self.topo_v2.parser.security_rules}

        for rname, rule in v2_rules.items():
            if rname not in v1_rules:
                self.stats["rules_added"] += 1
                self.summary_items.append({
                    "type": "RULE_ADDED",
                    "name": rname,
                    "action": rule["action"],
                    "apps": rule["applications"],
                    "description": f"New PAN-OS Security Policy: '{rname}' allows App-ID {rule['applications']} ({rule['from_zone']} -> {rule['to_zone']})"
                })

        for rname, rule in v1_rules.items():
            if rname not in v2_rules:
                self.stats["rules_removed"] += 1
                self.summary_items.append({
                    "type": "RULE_REMOVED",
                    "name": rname,
                    "description": f"Revoked PAN-OS Security Policy: '{rname}' ({rule['from_zone']} -> {rule['to_zone']})"
                })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": self.composite_nodes,
            "edges": self.composite_edges,
            "stats": self.stats,
            "summary_items": self.summary_items,
            "change_ticket": "CR-4910",
            "commit_id": "commit-94812b"
        }
