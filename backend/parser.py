"""
CLI Running Configuration Parser for Cisco ASA / Firewall Configs.
Extracts interfaces, zones, subnets, ACL rules, NAT, routes, and ARP entries.
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional


class FirewallConfigParser:
    def __init__(self, raw_config: str):
        self.raw_config = raw_config
        self.hostname: str = "FIREWALL"
        self.interfaces: List[Dict[str, Any]] = []
        self.objects: Dict[str, Dict[str, Any]] = {}
        self.acls: List[Dict[str, Any]] = []
        self.access_groups: Dict[str, str] = {}
        self.routes: List[Dict[str, Any]] = []
        self.nat_rules: List[Dict[str, Any]] = []
        self.arp_table: List[Dict[str, str]] = []
        
        self.parse()

    def parse(self):
        lines = [line.strip() for line in self.raw_config.splitlines()]
        
        # 1. Hostname
        for line in lines:
            m = re.match(r"^hostname\s+(\S+)", line)
            if m:
                self.hostname = m.group(1)
                break

        # 2. Interfaces
        current_iface = None
        for line in lines:
            if line.startswith("interface "):
                if current_iface:
                    self.interfaces.append(current_iface)
                if_name = line.split()[1]
                current_iface = {
                    "id": if_name,
                    "name": if_name,
                    "zone": None,
                    "security_level": 0,
                    "ip": None,
                    "netmask": None,
                    "cidr": None,
                    "subnet": None,
                    "description": "",
                    "enabled": True,
                }
            elif current_iface:
                if line.startswith("nameif "):
                    current_iface["zone"] = line.split()[1]
                elif line.startswith("security-level "):
                    current_iface["security_level"] = int(line.split()[1])
                elif line.startswith("ip address "):
                    parts = line.split()
                    ip_addr = parts[2]
                    netmask = parts[3]
                    current_iface["ip"] = ip_addr
                    current_iface["netmask"] = netmask
                    try:
                        net = ipaddress.IPv4Network(f"{ip_addr}/{netmask}", strict=False)
                        current_iface["cidr"] = f"{ip_addr}/{net.prefixlen}"
                        current_iface["subnet"] = str(net)
                    except Exception:
                        pass
                elif line.startswith("description "):
                    current_iface["description"] = line.replace("description ", "")
                elif line == "shutdown":
                    current_iface["enabled"] = False
                elif line == "!":
                    self.interfaces.append(current_iface)
                    current_iface = None
        if current_iface:
            self.interfaces.append(current_iface)

        # 3. Object definitions (hosts & subnets)
        current_obj = None
        for line in lines:
            if line.startswith("object network "):
                obj_name = line.split()[2]
                current_obj = {"name": obj_name, "type": "unknown", "value": None, "description": ""}
                self.objects[obj_name] = current_obj
            elif current_obj:
                if line.startswith("subnet "):
                    parts = line.split()
                    current_obj["type"] = "subnet"
                    try:
                        net = ipaddress.IPv4Network(f"{parts[1]}/{parts[2]}", strict=False)
                        current_obj["value"] = str(net)
                    except Exception:
                        current_obj["value"] = f"{parts[1]} {parts[2]}"
                elif line.startswith("host "):
                    current_obj["type"] = "host"
                    current_obj["value"] = line.split()[1]
                elif line.startswith("description "):
                    current_obj["description"] = line.replace("description ", "")
                elif line == "!":
                    current_obj = None

        # 4. Access Groups (ACL binding to interfaces)
        for line in lines:
            m = re.match(r"^access-group\s+(\S+)\s+(in|out)\s+interface\s+(\S+)", line)
            if m:
                acl_name, direction, zone_name = m.groups()
                self.access_groups[zone_name] = {"acl": acl_name, "direction": direction}

        # 5. Access Lists (ACL rules)
        # Example: access-list ACL_OUTSIDE_IN extended permit tcp any host 192.168.10.80 eq 443 rule-id 101 description ...
        acl_pattern = re.compile(
            r"^access-list\s+(\S+)\s+extended\s+(permit|deny)\s+(\S+)\s+(.+?)(?:\s+rule-id\s+(\d+))?(?:\s+description\s+(.+))?$"
        )
        for line in lines:
            m = acl_pattern.match(line)
            if m:
                acl_name, action, proto, rest, rule_id, desc = m.groups()
                rule = {
                    "acl_name": acl_name,
                    "action": action.upper(),
                    "protocol": proto.upper(),
                    "rule_id": rule_id or "default",
                    "description": desc or "",
                    "raw": line,
                    "src": "any",
                    "dst": "any",
                    "port": "any"
                }
                
                # Parse endpoints and ports from `rest`
                # e.g.: any host 192.168.10.80 eq 443
                # e.g.: 192.168.10.0 255.255.255.0 host 10.100.1.20 eq 8080
                tokens = rest.split()
                idx = 0
                
                # Parse source
                if idx < len(tokens):
                    if tokens[idx] == "any":
                        rule["src"] = "any"
                        idx += 1
                    elif tokens[idx] == "host" and idx + 1 < len(tokens):
                        rule["src"] = tokens[idx + 1]
                        idx += 2
                    elif idx + 1 < len(tokens) and re.match(r"^\d+\.\d+\.\d+\.\d+$", tokens[idx]) and re.match(r"^\d+\.\d+\.\d+\.\d+$", tokens[idx + 1]):
                        try:
                            net = ipaddress.IPv4Network(f"{tokens[idx]}/{tokens[idx+1]}", strict=False)
                            rule["src"] = str(net)
                        except Exception:
                            rule["src"] = f"{tokens[idx]}/{tokens[idx+1]}"
                        idx += 2
                    else:
                        rule["src"] = tokens[idx]
                        idx += 1

                # Parse destination
                if idx < len(tokens):
                    if tokens[idx] == "any":
                        rule["dst"] = "any"
                        idx += 1
                    elif tokens[idx] == "host" and idx + 1 < len(tokens):
                        rule["dst"] = tokens[idx + 1]
                        idx += 2
                    elif idx + 1 < len(tokens) and re.match(r"^\d+\.\d+\.\d+\.\d+$", tokens[idx]) and re.match(r"^\d+\.\d+\.\d+\.\d+$", tokens[idx + 1]):
                        try:
                            net = ipaddress.IPv4Network(f"{tokens[idx]}/{tokens[idx+1]}", strict=False)
                            rule["dst"] = str(net)
                        except Exception:
                            rule["dst"] = f"{tokens[idx]}/{tokens[idx+1]}"
                        idx += 2
                    else:
                        rule["dst"] = tokens[idx]
                        idx += 1

                # Parse port
                if idx < len(tokens) and tokens[idx] == "eq" and idx + 1 < len(tokens):
                    rule["port"] = tokens[idx + 1]
                
                self.acls.append(rule)

        # 6. Static Routes
        for line in lines:
            m = re.match(r"^route\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+))?", line)
            if m:
                zone, dest_ip, mask, gateway, metric = m.groups()
                dest_str = "0.0.0.0/0 (Default)" if dest_ip == "0.0.0.0" and mask == "0.0.0.0" else f"{dest_ip}/{mask}"
                self.routes.append({
                    "zone": zone,
                    "destination": dest_str,
                    "gateway": gateway,
                    "metric": int(metric) if metric else 1
                })

        # 7. NAT Rules
        for line in lines:
            if " nat (" in line:
                self.nat_rules.append({"raw": line})

        # 8. ARP Table from CLI output comment block
        in_arp = False
        for line in lines:
            if "! IP Address" in line and "MAC Address" in line:
                in_arp = True
                continue
            if in_arp:
                if line.startswith("!") and not line.strip() == "!":
                    clean = line.lstrip("! ").strip()
                    m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\.]+)\s+(\S+)(?:\s+\((.+)\))?", clean)
                    if m:
                        ip_val, mac_val, iface_val, label = m.groups()
                        self.arp_table.append({
                            "ip": ip_val,
                            "mac": mac_val,
                            "interface_zone": iface_val,
                            "label": label or ip_val
                        })
                elif not line.startswith("!"):
                    in_arp = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "interfaces": self.interfaces,
            "objects": self.objects,
            "acls": self.acls,
            "access_groups": self.access_groups,
            "routes": self.routes,
            "nat_rules": self.nat_rules,
            "arp_table": self.arp_table
        }
