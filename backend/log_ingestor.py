"""
Firewall Traffic and Syslog Ingestor.
Parses session builds, teardowns, and access-list deny drops.
"""

import re
from typing import Any, Dict, List


class FirewallLogIngestor:
    def __init__(self, raw_logs: str):
        self.raw_logs = raw_logs
        self.events: List[Dict[str, Any]] = []
        self.discovered_hosts: Dict[str, Dict[str, Any]] = {}
        self.stats = {
            "total_events": 0,
            "permitted_flows": 0,
            "denied_flows": 0,
            "teardown_flows": 0,
            "total_bytes": 0,
        }
        self.parse()

    def parse(self):
        # Patterns for Cisco ASA log lines:
        # 1. Built connection:
        # Sep 25 14:02:10 FW-CORE-01 %ASA-6-302013: Built inbound TCP connection 901244 for OUTSIDE:198.51.100.45/49210 (203.0.113.80/443) to DMZ:192.168.10.80/443 rule-id 101
        # or without NAT:
        # Sep 25 14:02:22 FW-CORE-01 %ASA-6-302013: Built inbound TCP connection 901248 for DMZ:192.168.10.80/54120 to INSIDE:10.100.1.20/8080 rule-id 201
        built_pattern = re.compile(
            r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+%ASA-6-302013:\s+Built\s+(\S+)\s+(\S+)\s+connection\s+(\d+)\s+for\s+(\S+?):(\d+\.\d+\.\d+\.\d+)/(\d+)(?:\s+\([^)]+\))?\s+to\s+(\S+?):(\d+\.\d+\.\d+\.\d+)/(\d+)(?:\s+rule-id\s+(\d+))?"
        )

        # 2. Deny packet:
        # Sep 25 14:02:14 FW-CORE-01 %ASA-4-106023: Deny tcp src OUTSIDE:198.51.100.22/58122 dst OUTSIDE:203.0.113.1/22 by access-group "ACL_OUTSIDE_IN" [rule-id 999]
        deny_pattern = re.compile(
            r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+%ASA-4-106023:\s+Deny\s+(\S+)\s+src\s+(\S+?):(\d+\.\d+\.\d+\.\d+)/(\d+)\s+dst\s+(\S+?):(\d+\.\d+\.\d+\.\d+)/(\d+)\s+by\s+access-group\s+\"([^\"]+)\"(?:\s+\[rule-id\s+(\d+)\])?"
        )

        # 3. Teardown connection:
        # Sep 25 14:02:40 FW-CORE-01 %ASA-6-302014: Teardown TCP connection 901244 for OUTSIDE:198.51.100.45/49210 to DMZ:192.168.10.80/443 duration 0:00:30 bytes 14520 TCP FINs
        teardown_pattern = re.compile(
            r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+%ASA-6-302014:\s+Teardown\s+(\S+)\s+connection\s+(\d+)\s+for\s+(\S+?):(\d+\.\d+\.\d+\.\d+)/(\d+)\s+to\s+(\S+?):(\d+\.\d+\.\d+\.\d+)/(\d+)\s+duration\s+(\S+)\s+bytes\s+(\d+)"
        )

        for line in self.raw_logs.splitlines():
            line = line.strip()
            if not line:
                continue

            # Try Built
            m = built_pattern.match(line)
            if m:
                ts, device, direction, proto, conn_id, s_zone, s_ip, s_port, d_zone, d_ip, d_port, rule_id = m.groups()
                event = {
                    "raw": line,
                    "timestamp": ts,
                    "device": device,
                    "action": "PERMIT",
                    "type": "CONNECTION_BUILT",
                    "protocol": proto.upper(),
                    "direction": direction,
                    "connection_id": conn_id,
                    "src_zone": s_zone,
                    "src_ip": s_ip,
                    "src_port": int(s_port),
                    "dst_zone": d_zone,
                    "dst_ip": d_ip,
                    "dst_port": int(d_port),
                    "rule_id": rule_id or "auto",
                }
                self.events.append(event)
                self.stats["permitted_flows"] += 1
                self._record_host(s_ip, s_zone)
                self._record_host(d_ip, d_zone)
                continue

            # Try Deny
            m = deny_pattern.match(line)
            if m:
                ts, device, proto, s_zone, s_ip, s_port, d_zone, d_ip, d_port, acl_group, rule_id = m.groups()
                event = {
                    "raw": line,
                    "timestamp": ts,
                    "device": device,
                    "action": "DENY",
                    "type": "ACCESS_DENIED",
                    "protocol": proto.upper(),
                    "src_zone": s_zone,
                    "src_ip": s_ip,
                    "src_port": int(s_port),
                    "dst_zone": d_zone,
                    "dst_ip": d_ip,
                    "dst_port": int(d_port),
                    "acl_group": acl_group,
                    "rule_id": rule_id or "implicit-deny",
                }
                self.events.append(event)
                self.stats["denied_flows"] += 1
                self._record_host(s_ip, s_zone)
                self._record_host(d_ip, d_zone)
                continue

            # Try Teardown
            m = teardown_pattern.match(line)
            if m:
                ts, device, proto, conn_id, s_zone, s_ip, s_port, d_zone, d_ip, d_port, duration, bytes_transferred = m.groups()
                b_int = int(bytes_transferred)
                event = {
                    "raw": line,
                    "timestamp": ts,
                    "device": device,
                    "action": "TEARDOWN",
                    "type": "CONNECTION_TEARDOWN",
                    "protocol": proto.upper(),
                    "connection_id": conn_id,
                    "src_zone": s_zone,
                    "src_ip": s_ip,
                    "src_port": int(s_port),
                    "dst_zone": d_zone,
                    "dst_ip": d_ip,
                    "dst_port": int(d_port),
                    "duration": duration,
                    "bytes": b_int,
                }
                self.events.append(event)
                self.stats["teardown_flows"] += 1
                self.stats["total_bytes"] += b_int
                continue

        self.stats["total_events"] = len(self.events)

    def _record_host(self, ip: str, zone: str):
        if ip not in self.discovered_hosts:
            self.discovered_hosts[ip] = {
                "ip": ip,
                "zone": zone,
                "hits": 1
            }
        else:
            self.discovered_hosts[ip]["hits"] += 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stats": self.stats,
            "events": self.events,
            "discovered_hosts": list(self.discovered_hosts.values())
        }
