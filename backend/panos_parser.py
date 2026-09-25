"""
Palo Alto Networks (PAN-OS) 'set' Command Configuration Parser.
Parses PAN-OS interfaces, zones, virtual routers, address objects, security policies (App-ID),
NAT rules, and operational ARP tables.
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional


class PanOSConfigParser:
    def __init__(self, raw_config: str):
        self.raw_config = raw_config
        self.hostname: str = "PA-NGFW-CORE-01"
        self.model: str = "PA-3410"
        self.panos_version: str = "11.1"
        self.interfaces: List[Dict[str, Any]] = []
        self.zones: Dict[str, Dict[str, Any]] = {}
        self.virtual_routers: Dict[str, Dict[str, Any]] = {}
        self.address_objects: Dict[str, Dict[str, Any]] = {}
        self.security_rules: List[Dict[str, Any]] = []
        self.nat_rules: List[Dict[str, Any]] = []
        self.arp_table: List[Dict[str, str]] = []
        
        self.parse()

    def parse(self):
        lines = [line.strip() for line in self.raw_config.splitlines()]

        # 1. System Hostname & Model
        for line in lines:
            if "set deviceconfig system hostname" in line:
                self.hostname = line.split()[-1]

        # 2. Interfaces
        # Example: set network interface ethernet ethernet1/1 layer3 ip 203.0.113.1/24
        iface_dict = {}
        for line in lines:
            m = re.match(r"^set\s+network\s+interface\s+ethernet\s+(ethernet\S+)\s+layer3\s+ip\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
            if m:
                if_name, cidr = m.groups()
                ip_addr = cidr.split('/')[0]
                try:
                    net = ipaddress.IPv4Network(cidr, strict=False)
                    subnet_str = str(net)
                except Exception:
                    subnet_str = cidr
                if_entry = {
                    "id": if_name,
                    "name": if_name,
                    "ip": ip_addr,
                    "cidr": cidr,
                    "subnet": subnet_str,
                    "zone": None,
                    "comment": ""
                }
                iface_dict[if_name] = if_entry
            
            # Interface comment
            m_c = re.match(r"^set\s+network\s+interface\s+ethernet\s+(ethernet\S+)\s+layer3\s+comment\s+\"([^\"]+)\"", line)
            if m_c:
                if_name, comment = m_c.groups()
                if if_name in iface_dict:
                    iface_dict[if_name]["comment"] = comment

        # 3. Security Zones
        # Example: set zone Untrust network layer3 ethernet1/1
        # Example with multiple: set zone Untrust network layer3 [ ethernet1/1 ethernet1/2 ]
        for line in lines:
            m = re.match(r"^set\s+zone\s+(\S+)\s+network\s+layer3\s+(\S+)", line)
            if m:
                z_name, if_target = m.groups()
                if z_name not in self.zones:
                    self.zones[z_name] = {"name": z_name, "interfaces": []}
                clean_if = if_target.strip("[]")
                self.zones[z_name]["interfaces"].append(clean_if)
                if clean_if in iface_dict:
                    iface_dict[clean_if]["zone"] = z_name

        self.interfaces = list(iface_dict.values())

        # 4. Virtual Routers
        # Example: set network virtual-router default routing-table ip static-route "Default-Internet-Gateway" nexthop ip-address 203.0.113.254 interface ethernet1/1 metric 10 destination 0.0.0.0/0
        vr_default = {"name": "default", "interfaces": [], "static_routes": []}
        for line in lines:
            if "set network virtual-router default interface" in line:
                ifs = re.findall(r"ethernet\S+", line)
                vr_default["interfaces"].extend(ifs)
            
            m_route = re.match(
                r"^set\s+network\s+virtual-router\s+(\S+)\s+routing-table\s+ip\s+static-route\s+\"([^\"]+)\"\s+(.+)",
                line
            )
            if m_route:
                vr_name, route_name, params = m_route.groups()
                dst_m = re.search(r"destination\s+(\d+\.\d+\.\d+\.\d+/\d+)", params)
                gw_m = re.search(r"nexthop\s+ip-address\s+(\d+\.\d+\.\d+\.\d+)", params)
                if_m = re.search(r"interface\s+(ethernet\S+)", params)
                vr_default["static_routes"].append({
                    "name": route_name,
                    "destination": dst_m.group(1) if dst_m else "0.0.0.0/0",
                    "nexthop": gw_m.group(1) if gw_m else "direct",
                    "interface": if_m.group(1) if if_m else None
                })
        self.virtual_routers["default"] = vr_default

        # 5. Address Objects
        # Example: set address OBJ_NET_DMZ ip-netmask 192.168.10.0/24 description "DMZ Web Subnet"
        for line in lines:
            m = re.match(r"^set\s+address\s+(\S+)\s+ip-netmask\s+(\d+\.\d+\.\d+\.\d+(?:/\d+)?)(?:\s+description\s+\"([^\"]+)\")?", line)
            if m:
                obj_name, cidr, desc = m.groups()
                self.address_objects[obj_name] = {
                    "name": obj_name,
                    "value": cidr,
                    "description": desc or ""
                }

        # 6. Security Policy Rules (App-ID)
        # Example: set rulebase security rules "Allow-Inbound-Web" from Untrust to DMZ source any destination OBJ_HOST_WEB_SRV01 application [ web-browsing ssl ] service application-default action allow description "..."
        sec_pattern = re.compile(
            r"^set\s+rulebase\s+security\s+rules\s+\"([^\"]+)\"\s+(.+)$"
        )
        for line in lines:
            m = sec_pattern.match(line)
            if m:
                rule_name, params = m.groups()
                
                from_m = re.search(r"from\s+(\S+)", params)
                to_m = re.search(r"to\s+(\S+)", params)
                src_m = re.search(r"source\s+(\S+)", params)
                dst_m = re.search(r"destination\s+(\S+)", params)
                act_m = re.search(r"action\s+(allow|drop|deny|reset-client)", params)
                desc_m = re.search(r"description\s+\"([^\"]+)\"", params)

                # Extract applications (can be single or [ app1 app2 ])
                apps = []
                app_bracket = re.search(r"application\s+\[([^\]]+)\]", params)
                if app_bracket:
                    apps = app_bracket.group(1).split()
                else:
                    app_single = re.search(r"application\s+(\S+)", params)
                    if app_single:
                        apps = [app_single.group(1)]

                # Extract service
                svc_m = re.search(r"service\s+(\S+)", params)

                self.security_rules.append({
                    "name": rule_name,
                    "from_zone": from_m.group(1) if from_m else "any",
                    "to_zone": to_m.group(1) if to_m else "any",
                    "source": src_m.group(1) if src_m else "any",
                    "destination": dst_m.group(1) if dst_m else "any",
                    "applications": apps or ["any"],
                    "service": svc_m.group(1) if svc_m else "application-default",
                    "action": act_m.group(1).upper() if act_m else "ALLOW",
                    "description": desc_m.group(1) if desc_m else "",
                    "raw": line
                })

        # 7. NAT Rules
        for line in lines:
            if "set rulebase nat rules" in line:
                self.nat_rules.append({"raw": line})

        # 8. Operational ARP Table from comment block
        in_arp = False
        for line in lines:
            if "# interface" in line and "hw address" in line:
                in_arp = True
                continue
            if in_arp:
                if line.startswith("#") and not line.strip() == "#":
                    clean = line.lstrip("# ").strip()
                    m = re.match(r"^(ethernet\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]+)\s+\S+\s+\d+(?:\s+\((.+)\))?", clean)
                    if m:
                        if_val, ip_val, mac_val, label = m.groups()
                        # resolve zone for this interface
                        z_match = next((i["zone"] for i in self.interfaces if i["name"] == if_val), "Untrust")
                        self.arp_table.append({
                            "interface": if_val,
                            "ip": ip_val,
                            "mac": mac_val,
                            "zone": z_match,
                            "label": label or ip_val
                        })
                elif not line.startswith("#"):
                    in_arp = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "model": self.model,
            "panos_version": self.panos_version,
            "interfaces": self.interfaces,
            "zones": self.zones,
            "virtual_routers": self.virtual_routers,
            "address_objects": self.address_objects,
            "security_rules": self.security_rules,
            "nat_rules": self.nat_rules,
            "arp_table": self.arp_table
        }
