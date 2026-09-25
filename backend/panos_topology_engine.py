"""
Palo Alto Networks (PAN-OS) Topology Engine & App-ID Policy Simulator.
Constructs network graph from PAN-OS running configuration, zones, virtual routers,
and evaluates layer 7 App-ID policies.
"""

import ipaddress
from typing import Any, Dict, List, Optional
from panos_parser import PanOSConfigParser
from panos_log_ingestor import PanOSLogIngestor


class PanOSTopologyEngine:
    def __init__(self, parser: PanOSConfigParser, ingestor: Optional[PanOSLogIngestor] = None):
        self.parser = parser
        self.ingestor = ingestor
        self.nodes: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, Any]] = []
        self.zones: Dict[str, Any] = {}
        
        self.build_graph()

    def build_graph(self):
        self.nodes = []
        self.edges = []
        self.zones = self.parser.zones

        # 1. Central Palo Alto NGFW Node
        fw_node = {
            "id": f"node-{self.parser.hostname}",
            "label": f"{self.parser.hostname}\n({self.parser.model} PAN-OS {self.parser.panos_version})",
            "type": "firewall",
            "zone": "CORE",
            "metadata": {
                "hostname": self.parser.hostname,
                "model": self.parser.model,
                "panos_version": self.parser.panos_version,
                "interfaces": self.parser.interfaces,
                "virtual_routers": list(self.parser.virtual_routers.keys()),
                "total_security_rules": len(self.parser.security_rules)
            }
        }
        self.nodes.append(fw_node)

        # 2. Virtual Router Node
        vr_node = {
            "id": "node-vr-default",
            "label": "Virtual Router: default\n(FIB / RIB Routing)",
            "type": "virtual_router",
            "zone": "ROUTER",
            "metadata": {
                "vr_name": "default",
                "static_routes": self.parser.virtual_routers.get("default", {}).get("static_routes", [])
            }
        }
        self.nodes.append(vr_node)

        # Connect Firewall to Virtual Router
        self.edges.append({
            "id": "edge-fw-vr",
            "source": fw_node["id"],
            "target": vr_node["id"],
            "label": "RIB/FIB",
            "type": "internal_link"
        })

        # 3. Subnets and Interfaces
        subnet_nodes = {}
        for iface in self.parser.interfaces:
            z_name = iface["zone"] or "Untrust"
            sub_id = f"subnet-{z_name}"
            
            sub_node = {
                "id": sub_id,
                "label": f"{z_name} Subnet\n({iface['subnet']})",
                "type": "subnet",
                "zone": z_name,
                "metadata": {
                    "cidr": iface["subnet"],
                    "gateway_ip": iface["ip"],
                    "interface": iface["name"],
                    "comment": iface["comment"]
                }
            }
            subnet_nodes[sub_id] = sub_node
            self.nodes.append(sub_node)

            # Edge from Firewall/VR to Subnet
            self.edges.append({
                "id": f"edge-fw-{sub_id}",
                "source": fw_node["id"],
                "target": sub_id,
                "label": iface["name"],
                "type": "interface_link"
            })

        # 4. Internet Gateway Node
        gw_node = {
            "id": "node-internet-gw",
            "label": "Public Internet / Transit\n(ISP Gateway 203.0.113.254)",
            "type": "gateway",
            "zone": "Untrust",
            "metadata": {"ip": "203.0.113.254"}
        }
        self.nodes.append(gw_node)
        self.edges.append({
            "id": "edge-untrust-gw",
            "source": gw_node["id"],
            "target": "subnet-Untrust",
            "label": "BGP / Transit",
            "type": "gateway_link"
        })

        # 5. Connected Endpoints (From ARP Table & Address Objects)
        for arp in self.parser.arp_table:
            # Skip the ISP gateway as it's already represented
            if "203.0.113.254" in arp["ip"]:
                continue

            host_id = f"host-{arp['ip'].replace('.', '-')}"
            zone_id = arp["zone"] or "Untrust"
            
            # Find matching address object description
            desc = ""
            for obj_name, obj in self.parser.address_objects.items():
                if arp["ip"] in obj["value"]:
                    desc = obj["description"]
                    break

            host_node = {
                "id": host_id,
                "label": f"{arp['label']}\n({arp['ip']})",
                "type": "endpoint",
                "zone": zone_id,
                "metadata": {
                    "ip": arp["ip"],
                    "mac": arp["mac"],
                    "interface": arp["interface"],
                    "description": desc
                }
            }
            self.nodes.append(host_node)

            # Connect Host to its Subnet
            sub_id = f"subnet-{zone_id}"
            if sub_id in subnet_nodes:
                self.edges.append({
                    "id": f"edge-{host_id}-{sub_id}",
                    "source": sub_id,
                    "target": host_id,
                    "label": arp["mac"],
                    "type": "l2_link"
                })

    def find_zone_for_ip(self, ip_str: str) -> str:
        """Determines the Palo Alto Security Zone for a given IP."""
        try:
            target_ip = ipaddress.IPv4Address(ip_str)
        except Exception:
            return "Untrust"

        # Check explicit ARP table
        for arp in self.parser.arp_table:
            if arp["ip"] == ip_str:
                return arp["zone"] or "Untrust"

        # Check interfaces / subnets
        for iface in self.parser.interfaces:
            try:
                net = ipaddress.IPv4Network(iface["subnet"], strict=False)
                if target_ip in net:
                    return iface["zone"] or "Untrust"
            except Exception:
                continue

        # Check address objects
        for obj in self.parser.address_objects.values():
            try:
                net = ipaddress.IPv4Network(obj["value"], strict=False)
                if target_ip in net:
                    for iface in self.parser.interfaces:
                        if net.overlaps(ipaddress.IPv4Network(iface["subnet"], strict=False)):
                            return iface["zone"] or "Untrust"
            except Exception:
                continue

        return "Untrust"

    def simulate_panos_packet(
        self,
        src_ip: str,
        dst_ip: str,
        port: int = 443,
        protocol: str = "TCP",
        app_id: str = "ssl"
    ) -> Dict[str, Any]:
        """
        Simulates Palo Alto Networks packet processing with App-ID and Zone-Based Policies:
        1. Ingress Zone determination
        2. Egress Zone & Virtual Router FIB lookup
        3. Security Policy evaluation (App-ID aware)
        4. Interzone default drop vs intrazone default allow
        """
        src_zone = self.find_zone_for_ip(src_ip)
        dst_zone = self.find_zone_for_ip(dst_ip)

        path = [
            f"Source Host ({src_ip}) in Zone [{src_zone}]",
            f"Ingress Virtual Router 'default' route lookup to {dst_ip}",
            f"Target Egress Zone determined: [{dst_zone}]"
        ]

        # Intra-zone default check: if src_zone == dst_zone
        is_intrazone = (src_zone == dst_zone)

        # Evaluate PAN-OS security rule base in top-down order
        matched_rule = None
        for rule in self.parser.security_rules:
            # 1. Match from_zone
            if rule["from_zone"] != "any" and rule["from_zone"] != src_zone:
                continue
            
            # 2. Match to_zone
            if rule["to_zone"] != "any" and rule["to_zone"] != dst_zone:
                continue

            # 3. Match Source
            if rule["source"] != "any":
                obj_src = self.parser.address_objects.get(rule["source"])
                if obj_src:
                    src_net = ipaddress.IPv4Network(obj_src["value"], strict=False)
                    if ipaddress.IPv4Address(src_ip) not in src_net:
                        continue
                elif rule["source"] != src_ip:
                    continue

            # 4. Match Destination
            if rule["destination"] != "any":
                obj_dst = self.parser.address_objects.get(rule["destination"])
                if obj_dst:
                    dst_net = ipaddress.IPv4Network(obj_dst["value"], strict=False)
                    if ipaddress.IPv4Address(dst_ip) not in dst_net:
                        continue
                elif rule["destination"] != dst_ip:
                    continue

            # 5. Match Application (App-ID)
            if "any" not in rule["applications"]:
                if app_id.lower() not in [a.lower() for a in rule["applications"]]:
                    continue

            # Rule matches!
            matched_rule = rule
            break

        if matched_rule:
            action = matched_rule["action"]
            rule_name = matched_rule["name"]
            desc = matched_rule["description"] or f"Matched rule '{rule_name}'"
            path.append(f"PAN-OS Policy Engine: Matched Rule \"{rule_name}\" (App-ID: {app_id}) -> {action}")
        else:
            # Fallback to default PAN-OS zone rules
            if is_intrazone:
                action = "ALLOW"
                rule_name = "intrazone-default"
                desc = "PAN-OS Default Intra-zone policy: Traffic within the same security zone is permitted"
                path.append("PAN-OS Policy Engine: Matched built-in 'intrazone-default' -> ALLOW")
            else:
                action = "DROP"
                rule_name = "interzone-default"
                desc = f"PAN-OS Default Inter-zone policy: Cross-zone traffic between {src_zone} and {dst_zone} is dropped"
                path.append("PAN-OS Policy Engine: Matched built-in 'interzone-default' -> DROP")

        if action == "ALLOW":
            path.append(f"Packet delivered to {dst_ip}:{port} ({app_id})")
        else:
            path.append(f"Packet dropped at firewall ingress ({src_zone} -> {dst_zone})")

        return {
            "src_ip": src_ip,
            "src_zone": src_zone,
            "dst_ip": dst_ip,
            "dst_zone": dst_zone,
            "port": port,
            "protocol": protocol,
            "app_id": app_id,
            "action": action,
            "rule_name": rule_name,
            "rule_description": desc,
            "path": path
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": self.nodes,
            "edges": self.edges,
            "zones": self.zones,
            "stats": {
                "nodes_count": len(self.nodes),
                "edges_count": len(self.edges),
                "zones_count": len(self.zones),
                "rules_count": len(self.parser.security_rules)
            }
        }
