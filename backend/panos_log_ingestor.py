"""
Palo Alto Networks (PAN-OS) 32-Field CSV Syslog Ingestor.
Extracts App-ID, security rule names, zones, session actions, and traffic telemetry.
"""

from typing import Any, Dict, List


class PanOSLogIngestor:
    def __init__(self, raw_logs: str):
        self.raw_logs = raw_logs
        self.events: List[Dict[str, Any]] = []
        self.discovered_hosts: Dict[str, Dict[str, Any]] = {}
        self.app_stats: Dict[str, int] = {}
        self.stats = {
            "total_events": 0,
            "permitted_flows": 0,
            "denied_flows": 0,
            "total_bytes": 0,
            "unique_apps": 0
        }
        self.parse()

    def parse(self):
        for line in self.raw_logs.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 25:
                continue

            # Standard PAN-OS CSV Syslog field mapping:
            # 0: Future use
            # 1: Receive Time
            # 2: Serial Number
            # 3: Type (TRAFFIC, THREAT, etc)
            # 4: Subtype (start, end, drop, deny)
            # 7: Source IP
            # 8: Destination IP
            # 11: Rule Name
            # 14: Application (App-ID)
            # 16: Source Zone
            # 17: Destination Zone
            # 18: Ingress Interface
            # 19: Egress Interface
            # 21: Session ID
            # 23: Source Port
            # 24: Destination Port
            # 28: Protocol
            # 29: Action (allow, drop, deny)
            # 30: Total Bytes
            try:
                rec_time = parts[1]
                serial = parts[2]
                log_type = parts[3]
                src_ip = parts[7]
                dst_ip = parts[8]
                rule_name = parts[11] or "intrazone-default"
                app_id = parts[14] or "unknown"
                src_zone = parts[16]
                dst_zone = parts[17]
                ingress_if = parts[18]
                egress_if = parts[19] if len(parts) > 19 else ""
                session_id = parts[21] if len(parts) > 21 else "0"
                src_port = int(parts[23]) if len(parts) > 23 and parts[23].isdigit() else 0
                dst_port = int(parts[24]) if len(parts) > 24 and parts[24].isdigit() else 0
                protocol = parts[28].upper() if len(parts) > 28 else "TCP"
                action_raw = parts[29].lower() if len(parts) > 29 else "allow"
                total_bytes = int(parts[30]) if len(parts) > 30 and parts[30].isdigit() else 0

                is_allow = action_raw in ["allow", "permit"]
                action_clean = "ALLOW" if is_allow else "DROP"

                event = {
                    "raw": line,
                    "timestamp": rec_time,
                    "serial": serial,
                    "log_type": log_type,
                    "action": action_clean,
                    "rule_name": rule_name,
                    "app_id": app_id,
                    "src_zone": src_zone,
                    "dst_zone": dst_zone,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "ingress_interface": ingress_if,
                    "egress_interface": egress_if,
                    "protocol": protocol,
                    "session_id": session_id,
                    "bytes": total_bytes
                }
                self.events.append(event)

                if is_allow:
                    self.stats["permitted_flows"] += 1
                else:
                    self.stats["denied_flows"] += 1
                
                self.stats["total_bytes"] += total_bytes

                # Track App-ID counts
                self.app_stats[app_id] = self.app_stats.get(app_id, 0) + 1

                # Discovered hosts
                self._record_host(src_ip, src_zone)
                self._record_host(dst_ip, dst_zone)

            except Exception as e:
                # Malformed line or unexpected field offset
                continue

        self.stats["total_events"] = len(self.events)
        self.stats["unique_apps"] = len(self.app_stats)

    def _record_host(self, ip: str, zone: str):
        if not ip or ip == "0.0.0.0":
            return
        if ip not in self.discovered_hosts:
            self.discovered_hosts[ip] = {"ip": ip, "zone": zone, "hits": 1}
        else:
            self.discovered_hosts[ip]["hits"] += 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stats": self.stats,
            "app_stats": self.app_stats,
            "events": self.events,
            "discovered_hosts": list(self.discovered_hosts.values())
        }
