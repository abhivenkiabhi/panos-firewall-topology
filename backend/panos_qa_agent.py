"""
Palo Alto Networks (PAN-OS) Customer & SecOps Q&A Agent.
Provides natural language answers on App-ID policies, zone-based routing,
dropped sessions, and commit diffs.
"""

import re
from typing import Any, Dict, List, Optional
from panos_topology_engine import PanOSTopologyEngine
from panos_diff_engine import PanOSDiffEngine
from panos_log_ingestor import PanOSLogIngestor


class PanOSQAAgent:
    def __init__(
        self,
        topo_v1: PanOSTopologyEngine,
        topo_v2: PanOSTopologyEngine,
        diff_engine: PanOSDiffEngine,
        log_ingestor: PanOSLogIngestor
    ):
        self.topo_v1 = topo_v1
        self.topo_v2 = topo_v2
        self.diff_engine = diff_engine
        self.log_ingestor = log_ingestor

    def answer(self, question: str) -> Dict[str, Any]:
        q_lower = question.lower()

        # 1. Diff / Commit changes query
        if any(w in q_lower for w in ["change", "diff", "cr-4910", "commit", "update", "added", "removed", "what's new"]):
            return self._answer_diff()

        # 2. Dropped traffic / Incident query
        if any(w in q_lower for w in ["why was", "drop", "deny", "blocked", "incident", "probe", "attack", "scanner"]):
            return self._answer_drop(question)

        # 3. Reachability / App-ID query
        if any(w in q_lower for w in ["reach", "can", "talk to", "connect", "access", "allowed", "port", "app-id"]):
            return self._answer_reachability(question)

        # 4. Inventory / Zones query
        if any(w in q_lower for w in ["zone", "zones", "interface", "subnet", "virtual router", "inventory"]):
            return self._answer_inventory()

        # Default fallback
        return {
            "question": question,
            "category": "general",
            "answer": (
                f"I am your **Palo Alto Networks Strata Assistant** for firewall `{self.topo_v2.parser.hostname}` ({self.topo_v2.parser.model} PAN-OS {self.topo_v2.parser.panos_version}).\n\n"
                "You can ask me questions such as:\n"
                "• *'What security policies changed in commit CR-4910?'*\n"
                "• *'Can DMZ Web (192.168.10.80) reach Payment Gateway (10.200.50.25) with App-ID ssl?'*\n"
                "• *'Why was traffic from 198.51.100.22 dropped?'*\n"
                "• *'Can DMZ servers access the PostgreSQL database?'*\n"
                "• *'What security zones and virtual routers are configured?'*"
            ),
            "related_nodes": []
        }

    def _answer_diff(self) -> Dict[str, Any]:
        stats = self.diff_engine.stats
        items = self.diff_engine.summary_items

        lines = [
            f"### Palo Alto Networks Commit Summary (Change Request: CR-4910)\n",
            f"Device: **{self.topo_v2.parser.hostname}** (PAN-OS {self.topo_v2.parser.panos_version})\n",
            "The following policy, zone, and network modifications were committed:\n"
        ]

        for it in items:
            lines.append(f"- **[{it['type']}]** {it.get('description', it.get('name', ''))}")

        lines.append(f"\n**Commit Statistics:**")
        lines.append(f"- **+{stats['rules_added']}** PAN-OS Security Policy Rules Added")
        lines.append(f"- **-{stats['rules_removed']}** Legacy Security Policy Rules Revoked")
        lines.append(f"- **+{stats['nodes_added']}** Subnet / Node Added (`PCI-Cardholder` Zone)")
        lines.append(f"- **-{stats['nodes_removed']}** Decommissioned Node (`Legacy-Test` Zone)")
        lines.append(f"\n*Summary: Production PCI-DSS CDE environment activated on interface `ethernet1/5` with App-ID `ssl` and `postgresql` inspection.*")

        return {
            "question": "What changed in the PAN-OS firewall config in CR-4910?",
            "category": "commit_diff",
            "answer": "\n".join(lines),
            "related_nodes": ["subnet-PCI-Cardholder", "subnet-Legacy-Test", "host-10-200-50-25"]
        }

    def _answer_drop(self, question: str) -> Dict[str, Any]:
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", question)
        target_ip = ip_match.group(0) if ip_match else "198.51.100.22"

        matching_drops = [
            e for e in self.log_ingestor.events 
            if e["action"] == "DROP" and (e["src_ip"] == target_ip or e["dst_ip"] == target_ip)
        ]

        if not matching_drops:
            matching_drops = [e for e in self.log_ingestor.events if e["action"] == "DROP"]

        if matching_drops:
            event = matching_drops[0]
            answer = (
                f"### Palo Alto Networks Threat & Drop Analysis\n\n"
                f"Traffic from **`{event['src_ip']}`** to **`{event['dst_ip']}:{event['dst_port']}`** was **DROPPED** by PAN-OS.\n\n"
                f"**Match Details from PAN-OS Syslog:**\n"
                f"- **Firewall Model**: {self.topo_v2.parser.model} (Serial: {event['serial']})\n"
                f"- **Matched Security Rule**: `{event['rule_name']}`\n"
                f"- **Identified App-ID**: `{event['app_id']}`\n"
                f"- **Source Zone**: `{event['src_zone']}` (Ingress: `{event['ingress_interface']}`)\n"
                f"- **Destination Zone**: `{event['dst_zone']}`\n"
                f"- **Action**: `{event['action']}`\n"
                f"- **Session ID**: `{event['session_id']}`\n\n"
                f"**Root Cause**: The session matched PAN-OS security rule `{event['rule_name']}` "
                f"which strictly denies `{event['app_id']}` administrative probe attempts to prevent unauthorized ingress."
            )
            return {
                "question": question,
                "category": "log_drop",
                "answer": answer,
                "related_nodes": ["node-internet-gw", f"host-{event['src_ip'].replace('.', '-')}", f"host-{event['dst_ip'].replace('.', '-')}"]
            }

        return {
            "question": question,
            "category": "log_drop",
            "answer": f"No drop events found for {target_ip} in the current PAN-OS syslog buffer.",
            "related_nodes": []
        }

    def _answer_reachability(self, question: str) -> Dict[str, Any]:
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", question)
        port_match = re.search(r"port\s+(\d+)", question, re.IGNORECASE)
        app_match = re.search(r"(?:app-id|app|application)\s+([a-zA-Z0-9_\-]+)", question, re.IGNORECASE)

        src_ip = "192.168.10.80"
        dst_ip = "10.200.50.25"
        port = int(port_match.group(1)) if port_match else 443
        app_id = app_match.group(1) if app_match else "ssl"

        if len(ips) >= 2:
            src_ip, dst_ip = ips[0], ips[1]
        elif len(ips) == 1:
            if "to" in question:
                dst_ip = ips[0]
            else:
                src_ip = ips[0]

        # Specific check for DMZ to DB
        if ("db" in question.lower() or "database" in question.lower()) and "dmz" in question.lower():
            src_ip = "192.168.10.80"
            dst_ip = "10.100.1.50"
            port = 5432
            app_id = "postgresql"

        sim = self.topo_v2.simulate_panos_packet(src_ip, dst_ip, port=port, app_id=app_id)

        status_text = "**ALLOWED**" if sim["action"] == "ALLOW" else "**BLOCKED / DROPPED**"
        lines = [
            f"### Palo Alto Networks Policy Evaluation\n",
            f"Session request from **`{src_ip}`** (Zone: `{sim['src_zone']}`) to **`{dst_ip}:{port}`** (Zone: `{sim['dst_zone']}`) using App-ID **`{app_id}`** is {status_text}.\n",
            f"**Policy Match Details:**",
            f"- **Enforced Rule**: `{sim['rule_name']}`",
            f"- **Decision**: `{sim['action']}`",
            f"- **Rule Description**: *{sim['rule_description']}*",
            f"\n**PAN-OS Traversal Path:**"
        ]
        for idx, hop in enumerate(sim["path"]):
            lines.append(f"{idx + 1}. {hop}")

        return {
            "question": question,
            "category": "reachability",
            "answer": "\n".join(lines),
            "simulation": sim,
            "related_nodes": [f"host-{src_ip.replace('.', '-')}", f"host-{dst_ip.replace('.', '-')}", f"subnet-{sim['src_zone']}", f"subnet-{sim['dst_zone']}"]
        }

    def _answer_inventory(self) -> Dict[str, Any]:
        zones = list(self.topo_v2.zones.keys())
        lines = [
            f"### Palo Alto Networks Active Inventory ({self.topo_v2.parser.hostname})\n",
            f"- **Hardware Platform**: {self.topo_v2.parser.model} (PAN-OS {self.topo_v2.parser.panos_version})",
            f"- **Virtual Routers**: `default` (Managing {len(self.topo_v2.parser.interfaces)} layer 3 interfaces)",
            f"- **Active Security Zones ({len(zones)})**:"
        ]
        for z in zones:
            ifaces = ", ".join(self.topo_v2.zones[z]["interfaces"])
            lines.append(f"  • **{z}**: Interface(s) `[{ifaces}]`")

        lines.append(f"- **Configured Security Policies**: {len(self.topo_v2.parser.security_rules)} rules with App-ID inspection")
        lines.append(f"- **Address Objects**: {len(self.topo_v2.parser.address_objects)} objects")

        return {
            "question": "What security zones and inventory are active?",
            "category": "inventory",
            "answer": "\n".join(lines),
            "related_nodes": [f"subnet-{z}" for z in zones]
        }
