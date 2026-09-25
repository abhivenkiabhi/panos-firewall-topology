"""
Topology Engine:
Builds unified graph model from parsed firewall configuration and traffic logs.
Provides packet simulation / reachability checking.
"""

import ipaddress
from typing import Any, Dict, List, Optional


class TopologyEngine:
    def __init__(self, parsed_config: Dict[str, Any], parsed_logs: Optional[Dict[str, Any]] = None):
        self.config = parsed_config
        self.logs = parsed_logs or {"events": [], "discovered_hosts": []}
        self.nodes: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, Any]] = []
        self.zones: Dict[str, Dict[str, Any]] = {}
        self.subnets: List[Dict[str, Any]] = []
        self.hosts: List[Dict[str, Any]] = []
        
        self.build_topology()

    def _ip_in_network(self, ip_str: str, net_str: str) -> bool:
        try:
            ip_obj = ipaddress.IPv4Address(ip_str)
            net_obj = ipaddress.IPv4Network(net_str, strict=False)
            return ip_obj in net_obj
        except Exception:
            return False

    def find_zone_for_ip(self, ip_str: str) -> Optional[str]:
        # First check direct interfaces
        for iface in self.config.get("interfaces", []):
            if iface.get("subnet") and self._ip_in_network(ip_str, iface["subnet"]):
                return iface.get("zone")
            if iface.get("ip") == ip_str:
                return iface.get("zone")
        
        # Check routes
        for r in self.config.get("routes", []):
            dst = r.get("destination")
            if dst and "Default" not in dst:
                if self._ip_in_network(ip_str, dst):
                    return r.get("zone")

        # If not matching internal subnets, check default route or outside
        for r in self.config.get("routes", []):
            if "Default" in r.get("destination", "") or r.get("destination") == "0.0.0.0/0":
                return r.get("zone")
        return "OUTSIDE"

    def build_topology(self):
        hostname = self.config.get("hostname", "FW-CORE-01")
        
        # 1. Firewall Node
        fw_node = {
            "id": f"node-{hostname}",
            "label": hostname,
            "type": "firewall",
            "zone": "CORE",
            "metadata": {
                "interfaces": self.config.get("interfaces", []),
                "routes": self.config.get("routes", []),
                "acl_count": len(self.config.get("acls", [])),
                "status": "active"
            }
        }
        self.nodes.append(fw_node)

        # 2. Extract Zones and Subnets from Interfaces
        zone_color_map = {
            "OUTSIDE": "#ef4444",    # Red
            "DMZ": "#f59e0b",        # Amber
            "INSIDE": "#10b981",     # Emerald / Green
            "PCI_ZONE": "#8b5cf6",   # Purple
            "LEGACY_TEST": "#64748b",# Slate
            "MANAGEMENT": "#3b82f6", # Blue
        }

        for iface in self.config.get("interfaces", []):
            z_name = iface.get("zone")
            if not z_name:
                continue
            
            if z_name not in self.zones:
                self.zones[z_name] = {
                    "id": z_name,
                    "name": z_name,
                    "security_level": iface.get("security_level", 0),
                    "color": zone_color_map.get(z_name, "#6366f1"),
                    "interface": iface.get("name"),
                    "ip": iface.get("ip"),
                    "cidr": iface.get("cidr"),
                    "subnet": iface.get("subnet")
                }

            # Create Subnet Node if subnet exists
            sub_cidr = iface.get("subnet")
            if sub_cidr:
                sub_id = f"subnet-{z_name}"
                subnet_node = {
                    "id": sub_id,
                    "label": f"{z_name} Subnet\n({sub_cidr})",
                    "type": "subnet",
                    "zone": z_name,
                    "metadata": {
                        "cidr": sub_cidr,
                        "gateway_ip": iface.get("ip"),
                        "interface": iface.get("name"),
                        "description": iface.get("description", "")
                    }
                }
                self.nodes.append(subnet_node)
                self.subnets.append(subnet_node)

                # Edge: Firewall <-> Subnet
                self.edges.append({
                    "id": f"edge-{fw_node['id']}-{sub_id}",
                    "source": fw_node["id"],
                    "target": sub_id,
                    "type": "interface_link",
                    "label": iface.get("name"),
                    "metadata": {
                        "ip": iface.get("ip"),
                        "speed": "1 Gbps",
                        "direction": "bidirectional"
                    }
                })

        # 3. Add External Internet / Gateway Node for OUTSIDE
        outside_node_id = "node-internet-gw"
        self.nodes.append({
            "id": outside_node_id,
            "label": "Internet / Upstream ISP\n(203.0.113.254)",
            "type": "gateway",
            "zone": "OUTSIDE",
            "metadata": {
                "ip": "203.0.113.254",
                "role": "Default Gateway"
            }
        })
        self.edges.append({
            "id": f"edge-outside-{outside_node_id}",
            "source": outside_node_id,
            "target": "subnet-OUTSIDE",
            "type": "uplink",
            "label": "BGP / Static Default",
            "metadata": {"carrier": "Tier 1 Transit"}
        })

        # 4. Host Nodes from ARP and Objects
        known_hosts = {}
        for arp in self.config.get("arp_table", []):
            ip_val = arp["ip"]
            if ip_val == "203.0.113.254":
                continue # Already represented as Internet Gateway
            known_hosts[ip_val] = {
                "ip": ip_val,
                "mac": arp.get("mac", ""),
                "zone": arp.get("interface_zone", self.find_zone_for_ip(ip_val)),
                "label": arp.get("label", ip_val)
            }

        # Add objects metadata if available
        for obj_name, obj_data in self.config.get("objects", {}).items():
            if obj_data.get("type") == "host":
                hip = obj_data["value"]
                if hip in known_hosts:
                    known_hosts[hip]["label"] = f"{obj_name}\n({hip})"
                    known_hosts[hip]["description"] = obj_data.get("description", "")
                else:
                    known_hosts[hip] = {
                        "ip": hip,
                        "mac": "unknown",
                        "zone": self.find_zone_for_ip(hip),
                        "label": f"{obj_name}\n({hip})",
                        "description": obj_data.get("description", "")
                    }

        # Create host nodes and connect to their respective subnets
        for hip, hinfo in known_hosts.items():
            hzone = hinfo.get("zone")
            host_node_id = f"host-{hip.replace('.', '-')}"
            h_node = {
                "id": host_node_id,
                "label": hinfo.get("label", hip),
                "type": "endpoint",
                "zone": hzone,
                "metadata": {
                    "ip": hip,
                    "mac": hinfo.get("mac"),
                    "description": hinfo.get("description", "")
                }
            }
            self.nodes.append(h_node)
            self.hosts.append(h_node)

            # Connect Host to Subnet
            sub_id = f"subnet-{hzone}"
            self.edges.append({
                "id": f"edge-{sub_id}-{host_node_id}",
                "source": sub_id,
                "target": host_node_id,
                "type": "host_membership",
                "label": hip,
                "metadata": {"mac": hinfo.get("mac")}
            })

        # 5. Policy Edges from ACLs
        # Group ACL rules by zone
        for acl in self.config.get("acls", []):
            acl_name = acl.get("acl_name", "")
            action = acl.get("action", "PERMIT")
            rule_id = acl.get("rule_id")
            
            # Identify source zone from ACL binding
            src_zone = "ANY"
            for z, binding in self.config.get("access_groups", {}).items():
                if binding.get("acl") == acl_name:
                    src_zone = z
                    break
            
            acl["source_zone"] = src_zone

        # 6. Live Traffic Flows from Logs
        for ev in self.logs.get("events", []):
            if ev.get("action") == "PERMIT" and ev.get("type") == "CONNECTION_BUILT":
                s_ip = ev["src_ip"]
                d_ip = ev["dst_ip"]
                self.edges.append({
                    "id": f"flow-{ev.get('connection_id', s_ip + '-' + d_ip)}",
                    "source": f"host-{s_ip.replace('.', '-')}" if self._find_node_by_ip(s_ip) else "node-internet-gw",
                    "target": f"host-{d_ip.replace('.', '-')}" if self._find_node_by_ip(d_ip) else f"subnet-{ev['dst_zone']}",
                    "type": "active_traffic",
                    "label": f"{ev['protocol']}/{ev['dst_port']} [Rule {ev.get('rule_id')}]",
                    "metadata": {
                        "status": "permitted",
                        "protocol": ev["protocol"],
                        "port": ev["dst_port"],
                        "rule_id": ev.get("rule_id")
                    }
                })

    def _find_node_by_ip(self, ip_str: str) -> Optional[Dict[str, Any]]:
        for n in self.nodes:
            if n.get("metadata", {}).get("ip") == ip_str:
                return n
        return None

    def simulate_packet(self, src_ip: str, dst_ip: str, port: int, protocol: str = "TCP") -> Dict[str, Any]:
        """
        Simulate traffic flow through firewall:
        Identifies source zone, destination zone, matching ACL, and rule outcome.
        """
        src_zone = self.find_zone_for_ip(src_ip)
        dst_zone = self.find_zone_for_ip(dst_ip)
        
        # Find which ACL guards src_zone ingress
        acl_binding = self.config.get("access_groups", {}).get(src_zone, {})
        acl_name = acl_binding.get("acl")
        
        relevant_rules = [r for r in self.config.get("acls", []) if r.get("acl_name") == acl_name]
        
        match_rule = None
        for rule in relevant_rules:
            # Check protocol
            r_proto = rule.get("protocol", "IP")
            if r_proto != "IP" and r_proto != protocol.upper():
                continue
            
            # Check source
            r_src = rule.get("src", "any")
            src_matches = False
            if r_src == "any" or r_src == src_ip:
                src_matches = True
            elif "/" in r_src and self._ip_in_network(src_ip, r_src):
                src_matches = True
            if not src_matches:
                continue

            # Check destination
            r_dst = rule.get("dst", "any")
            dst_matches = False
            if r_dst == "any" or r_dst == dst_ip:
                dst_matches = True
            elif "/" in r_dst and self._ip_in_network(dst_ip, r_dst):
                dst_matches = True
            if not dst_matches:
                continue

            # Check port
            r_port = rule.get("port", "any")
            if r_port != "any" and str(port) != str(r_port):
                continue

            match_rule = rule
            break

        action = match_rule.get("action", "DENY") if match_rule else "DENY"
        rule_desc = match_rule.get("description", "Implicit Deny All") if match_rule else "Implicit Deny All (No matching permit rule)"
        rule_id = match_rule.get("rule_id", "999") if match_rule else "999"

        path_hops = [
            f"Source ({src_ip} in {src_zone})",
            f"Ingress Interface on FW-CORE-01 ({src_zone})",
            f"ACL Evaluation [{acl_name or 'Default'}] -> {action} (Rule ID: {rule_id})",
        ]
        if action == "PERMIT":
            path_hops.append(f"Routing Lookup -> Egress Interface ({dst_zone})")
            path_hops.append(f"Destination ({dst_ip} in {dst_zone})")
        else:
            path_hops.append(f"PACKET DROPPED at Firewall Interface {src_zone}")

        return {
            "src_ip": src_ip,
            "src_zone": src_zone,
            "dst_ip": dst_ip,
            "dst_zone": dst_zone,
            "port": port,
            "protocol": protocol.upper(),
            "action": action,
            "rule_id": rule_id,
            "rule_description": rule_desc,
            "acl_name": acl_name or "implicit",
            "path": path_hops
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": self.nodes,
            "edges": self.edges,
            "zones": self.zones,
            "summary": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "total_zones": len(self.zones),
                "total_acls": len(self.config.get("acls", [])),
                "total_hosts": len(self.hosts)
            }
        }
