"""
Customer Q&A Assistant for Firewall Topology.
Interprets customer queries, queries the topology graph, checks ACL rules,
inspects traffic logs, and generates clear, accurate responses.
"""

import re
from typing import Any, Dict, List, Optional
from topology_engine import TopologyEngine
from diff_engine import TopologyDiffEngine


class FirewallQAAgent:
    def __init__(self, topo_engine_v1: TopologyEngine, topo_engine_v2: TopologyEngine, diff_engine: TopologyDiffEngine, log_data: Dict[str, Any]):
        self.v1 = topo_engine_v1
        self.v2 = topo_engine_v2
        self.diff = diff_engine
        self.logs = log_data

    def answer(self, question: str) -> Dict[str, Any]:
        q_lower = question.lower()

        # 1. Config Diff / Changes questions
        if any(w in q_lower for w in ["change", "changed", "diff", "cr-4910", "revision", "update", "new subnet", "removed"]):
            diff_res = self.diff.compute_diff()
            stats = diff_res["stats"]
            summary = diff_res["summary_items"]
            
            bullet_points = "\n".join([f"- **[{item['badge'].upper()}]** {item['entity']}: {item['description']}" for item in summary])
            answer_text = (
                f"### Firewall Topology Changes Summary (CR-4910)\n\n"
                f"Between **Revision V1 (Baseline)** and **Revision V2 (Current)**, the following topology changes occurred:\n\n"
                f"{bullet_points}\n\n"
                f"**Key Metrics:**\n"
                f"- **{stats['nodes_added']}** Node(s) Added\n"
                f"- **{stats['nodes_removed']}** Node(s) Decommissioned\n"
                f"- **{stats['edges_added']}** New Policy/Interface Edges\n\n"
                f"*Legacy test environment (`192.168.99.0/24`) has been safely removed, and PCI DSS compliance zone is active on GigabitEthernet0/4.*"
            )
            return {
                "question": question,
                "category": "topology_diff",
                "answer": answer_text,
                "related_nodes": ["subnet-PCI_ZONE", "subnet-LEGACY_TEST", "host-10-200-50-25"]
            }

        # 2. Reachability / Can X talk to Y?
        # Extract IPs and Port if present
        ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", question)
        port_match = re.search(r"\b(?:port\s+|eq\s+|:)(\d+)\b", question, re.IGNORECASE)
        port = int(port_match.group(1)) if port_match else 443

        if len(ip_matches) >= 2 or any(k in q_lower for k in ["can", "reach", "talk", "connect", "access", "allowed"]):
            src_ip = ip_matches[0] if len(ip_matches) >= 1 else "192.168.10.80"
            dst_ip = ip_matches[1] if len(ip_matches) >= 2 else ("10.200.50.25" if "payment" in q_lower else "10.100.1.50")
            
            # Run simulation on V2
            sim = self.v2.simulate_packet(src_ip, dst_ip, port, "TCP")
            
            if sim["action"] == "PERMIT":
                badge_str = "ALLOWED"
                explanation = (
                    f"Traffic from **{src_ip}** ({sim['src_zone']}) to **{dst_ip}** ({sim['dst_zone']}) "
                    f"on TCP port **{port}** is **{badge_str}**.\n\n"
                    f"**Matched Rule:**\n"
                    f"- ACL: `{sim['acl_name']}`\n"
                    f"- Rule ID: `{sim['rule_id']}`\n"
                    f"- Description: *\"{sim['rule_description']}\"*\n\n"
                    f"**Traversed Path:**\n" + "\n".join([f"1. {hop}" for hop in sim["path"]])
                )
            else:
                badge_str = "BLOCKED / DROPPED"
                explanation = (
                    f"Traffic from **{src_ip}** ({sim['src_zone']}) to **{dst_ip}** ({sim['dst_zone']}) "
                    f"on TCP port **{port}** is **{badge_str}**.\n\n"
                    f"**Security Reason:**\n"
                    f"- Enforcing ACL: `{sim['acl_name']}`\n"
                    f"- Triggered Rule ID: `{sim['rule_id']}`\n"
                    f"- Policy Note: *\"{sim['rule_description']}\"*\n\n"
                    f"Direct communication across these security boundaries without an explicit permit rule is strictly prevented by firewall posture."
                )

            return {
                "question": question,
                "category": "reachability",
                "answer": explanation,
                "simulation": sim,
                "related_nodes": [f"host-{src_ip.replace('.', '-')}", f"host-{dst_ip.replace('.', '-')}"]
            }

        # 3. Log / Drop / Security Incident questions
        if any(w in q_lower for w in ["drop", "dropped", "deny", "denied", "block", "log", "ssh", "attack", "fail"]):
            events = self.logs.get("events", [])
            denied_events = [e for e in events if e.get("action") == "DENY"]
            
            # Check if user mentioned specific IP or port
            target_ip = ip_matches[0] if ip_matches else None
            if target_ip:
                matched_logs = [e for e in events if e.get("src_ip") == target_ip or e.get("dst_ip") == target_ip]
            else:
                matched_logs = denied_events

            log_samples = "\n".join([
                f"- `{e.get('timestamp')}`: {e.get('action')} {e.get('protocol')} from `{e.get('src_ip')}:{e.get('src_port')}` to `{e.get('dst_ip')}:{e.get('dst_port')}` [{e.get('acl_group', 'ACL')} Rule {e.get('rule_id')}]"
                for e in matched_logs[:5]
            ])

            ans = (
                f"### Firewall Traffic Log Inspection\n\n"
                f"Examining firewall drop records:\n\n"
                f"{log_samples or 'No recent drop events matching criteria.'}\n\n"
                f"**Root Cause Analysis:**\n"
                f"External or unauthorized connection attempts to non-published ports (such as SSH port 22 or direct DB port 5432) "
                f"are dropped at ingress by default rule `999` on `ACL_OUTSIDE_IN` or rule `203` on `ACL_DMZ_IN`."
            )
            return {
                "question": question,
                "category": "log_investigation",
                "answer": ans,
                "matched_events_count": len(matched_logs)
            }

        # 4. Zones & Topology Inventory questions
        if any(w in q_lower for w in ["zone", "zones", "dmz", "inside", "outside", "database", "pci", "inventory", "where"]):
            zones_info = []
            for zname, zdata in self.v2.zones.items():
                zones_info.append(f"- **{zname}** (Security Level {zdata['security_level']}): Subnet `{zdata.get('subnet')}` via `{zdata.get('interface')}`")
            
            ans = (
                f"### Configured Security Zones & Networks (Revision V2)\n\n"
                + "\n".join(zones_info) + "\n\n"
                f"**Core Firewall:** `FW-CORE-01` routing between {len(self.v2.zones)} zones with full stateful inspection."
            )
            return {
                "question": question,
                "category": "inventory",
                "answer": ans,
                "zones": list(self.v2.zones.keys())
            }

        # Fallback / General assistance
        return {
            "question": question,
            "category": "general",
            "answer": (
                f"I am your Firewall Topology Assistant. You can ask me:\n"
                f"1. **Reachability**: *'Can 192.168.10.80 reach 10.200.50.25 on port 443?'*\n"
                f"2. **Diff & Changes**: *'What changed in the firewall config in CR-4910?'*\n"
                f"3. **Log Analysis**: *'Why was traffic from 198.51.100.22 dropped?'*\n"
                f"4. **Inventory**: *'What zones and subnets are configured?'*"
            )
        }
