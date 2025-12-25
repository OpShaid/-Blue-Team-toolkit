"""
Intrusion Detection System - Rule-based network intrusion detection.
"""

import re
import struct
import socket
import threading
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Pattern
from enum import Enum

from blueteam.core.logger import get_logger
from blueteam.core.database import Database, Alert

logger = get_logger(__name__)


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(Enum):
    ALERT = "alert"
    LOG = "log"
    DROP = "drop"
    BLOCK = "block"


@dataclass
class Rule:
    """IDS Detection Rule."""
    id: str
    name: str
    description: str
    severity: Severity
    action: Action
    protocol: str = "any"
    src_ip: str = "any"
    src_port: str = "any"
    dst_ip: str = "any"
    dst_port: str = "any"
    content: Optional[str] = None
    content_regex: Optional[Pattern] = None
    pcre: Optional[str] = None
    flags: Optional[str] = None
    threshold: Optional[int] = None
    window: int = 60  # seconds
    enabled: bool = True
    tags: List[str] = field(default_factory=list)


@dataclass
class Detection:
    """Represents a detection event."""
    rule_id: str
    rule_name: str
    timestamp: datetime
    severity: Severity
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str
    payload_excerpt: str
    raw_packet: bytes = b""
    metadata: Dict[str, Any] = field(default_factory=dict)


class IntrusionDetector:
    """
    Network Intrusion Detection System.

    Features:
    - Signature-based detection (Snort-like rules)
    - Protocol anomaly detection
    - Rate-based detection (DoS, port scans)
    - Custom rule support
    - Real-time alerting
    """

    def __init__(self, db: Database = None, rule_file: str = None):
        self.db = db or Database()
        self.rules: Dict[str, Rule] = {}
        self.detections: List[Detection] = []
        self.alert_callback: Optional[Callable] = None

        self._running = False
        self._monitor_thread = None

        # Rate limiting tracking
        self._rate_counters: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._last_rate_reset = datetime.now()

        # Load default rules
        self._load_default_rules()

        # Load custom rules if provided
        if rule_file:
            self.load_rules(rule_file)

    def _load_default_rules(self):
        """Load built-in detection rules."""
        default_rules = [
            # Port Scan Detection
            Rule(
                id="SCAN-001",
                name="TCP Port Scan Detected",
                description="Multiple TCP connection attempts to different ports",
                severity=Severity.MEDIUM,
                action=Action.ALERT,
                protocol="tcp",
                threshold=20,
                window=60,
                tags=["reconnaissance", "port_scan"]
            ),

            # Brute Force Detection
            Rule(
                id="BRUTE-001",
                name="SSH Brute Force Attempt",
                description="Multiple SSH connection attempts from same source",
                severity=Severity.HIGH,
                action=Action.ALERT,
                protocol="tcp",
                dst_port="22",
                threshold=10,
                window=60,
                tags=["brute_force", "ssh"]
            ),
            Rule(
                id="BRUTE-002",
                name="RDP Brute Force Attempt",
                description="Multiple RDP connection attempts from same source",
                severity=Severity.HIGH,
                action=Action.ALERT,
                protocol="tcp",
                dst_port="3389",
                threshold=10,
                window=60,
                tags=["brute_force", "rdp"]
            ),

            # Malware/C2 Signatures
            Rule(
                id="MALWARE-001",
                name="Cobalt Strike Beacon Traffic",
                description="Possible Cobalt Strike C2 beacon detected",
                severity=Severity.CRITICAL,
                action=Action.ALERT,
                content="beacon",
                tags=["malware", "c2", "cobalt_strike"]
            ),
            Rule(
                id="MALWARE-002",
                name="Meterpreter Reverse Shell",
                description="Possible Meterpreter reverse shell traffic",
                severity=Severity.CRITICAL,
                action=Action.ALERT,
                dst_port="4444",
                tags=["malware", "c2", "metasploit"]
            ),
            Rule(
                id="MALWARE-003",
                name="PowerShell Download Cradle",
                description="PowerShell download/execute pattern detected",
                severity=Severity.HIGH,
                action=Action.ALERT,
                pcre=r"powershell.*-e[ncodema]*\s+[A-Za-z0-9+/=]{50,}",
                tags=["malware", "powershell", "download"]
            ),

            # Command Injection
            Rule(
                id="INJECT-001",
                name="Command Injection Attempt",
                description="Possible command injection in HTTP traffic",
                severity=Severity.HIGH,
                action=Action.ALERT,
                protocol="tcp",
                dst_port="80,443,8080",
                pcre=r"[;&|`$].*(?:cat|ls|pwd|id|whoami|uname|wget|curl)",
                tags=["injection", "command_injection"]
            ),

            # SQL Injection
            Rule(
                id="SQLI-001",
                name="SQL Injection Attempt",
                description="Possible SQL injection attempt detected",
                severity=Severity.HIGH,
                action=Action.ALERT,
                protocol="tcp",
                pcre=r"(?:union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table|--\s*$|'\s*or\s*'1'\s*=\s*'1)",
                tags=["injection", "sqli"]
            ),

            # XSS
            Rule(
                id="XSS-001",
                name="Cross-Site Scripting Attempt",
                description="Possible XSS attack detected",
                severity=Severity.MEDIUM,
                action=Action.ALERT,
                protocol="tcp",
                pcre=r"<script[^>]*>|javascript:|on\w+\s*=",
                tags=["injection", "xss"]
            ),

            # Data Exfiltration
            Rule(
                id="EXFIL-001",
                name="Large Outbound Transfer",
                description="Unusually large outbound data transfer",
                severity=Severity.MEDIUM,
                action=Action.ALERT,
                tags=["exfiltration"]
            ),
            Rule(
                id="EXFIL-002",
                name="DNS Tunneling Suspected",
                description="Suspiciously long DNS queries (possible tunneling)",
                severity=Severity.HIGH,
                action=Action.ALERT,
                protocol="udp",
                dst_port="53",
                tags=["exfiltration", "dns_tunnel"]
            ),

            # Suspicious Protocols
            Rule(
                id="PROTO-001",
                name="Tor Traffic Detected",
                description="Possible Tor network traffic",
                severity=Severity.MEDIUM,
                action=Action.ALERT,
                dst_port="9001,9030,9050,9051",
                tags=["tor", "anonymizer"]
            ),
            Rule(
                id="PROTO-002",
                name="IRC Traffic Detected",
                description="IRC traffic detected (potential C2)",
                severity=Severity.MEDIUM,
                action=Action.ALERT,
                dst_port="6667,6668,6669",
                tags=["irc", "c2"]
            ),

            # Network Attacks
            Rule(
                id="ATTACK-001",
                name="SYN Flood Detected",
                description="Possible SYN flood attack",
                severity=Severity.CRITICAL,
                action=Action.ALERT,
                protocol="tcp",
                flags="S",
                threshold=100,
                window=10,
                tags=["dos", "syn_flood"]
            ),
            Rule(
                id="ATTACK-002",
                name="ICMP Flood Detected",
                description="Possible ICMP flood attack",
                severity=Severity.HIGH,
                action=Action.ALERT,
                protocol="icmp",
                threshold=100,
                window=10,
                tags=["dos", "icmp_flood"]
            ),

            # Reconnaissance
            Rule(
                id="RECON-001",
                name="NMAP Scan Detected",
                description="NMAP fingerprinting detected",
                severity=Severity.MEDIUM,
                action=Action.ALERT,
                protocol="tcp",
                flags="SFUP",
                tags=["reconnaissance", "nmap"]
            ),
        ]

        for rule in default_rules:
            self.rules[rule.id] = rule

    def load_rules(self, rule_file: str):
        """Load rules from JSON file."""
        path = Path(rule_file)
        if not path.exists():
            logger.warning(f"Rule file not found: {rule_file}")
            return

        try:
            with open(path) as f:
                rules_data = json.load(f)

            for rule_dict in rules_data.get("rules", []):
                rule = Rule(
                    id=rule_dict["id"],
                    name=rule_dict["name"],
                    description=rule_dict.get("description", ""),
                    severity=Severity(rule_dict.get("severity", "medium")),
                    action=Action(rule_dict.get("action", "alert")),
                    protocol=rule_dict.get("protocol", "any"),
                    src_ip=rule_dict.get("src_ip", "any"),
                    src_port=rule_dict.get("src_port", "any"),
                    dst_ip=rule_dict.get("dst_ip", "any"),
                    dst_port=rule_dict.get("dst_port", "any"),
                    content=rule_dict.get("content"),
                    pcre=rule_dict.get("pcre"),
                    flags=rule_dict.get("flags"),
                    threshold=rule_dict.get("threshold"),
                    window=rule_dict.get("window", 60),
                    enabled=rule_dict.get("enabled", True),
                    tags=rule_dict.get("tags", [])
                )

                if rule.pcre:
                    try:
                        rule.content_regex = re.compile(rule.pcre, re.IGNORECASE)
                    except re.error as e:
                        logger.error(f"Invalid regex in rule {rule.id}: {e}")
                        continue

                self.rules[rule.id] = rule
                logger.info(f"Loaded rule: {rule.id} - {rule.name}")

        except Exception as e:
            logger.error(f"Failed to load rules: {e}")

    def add_rule(self, rule: Rule):
        """Add a custom rule."""
        if rule.pcre:
            try:
                rule.content_regex = re.compile(rule.pcre, re.IGNORECASE)
            except re.error as e:
                logger.error(f"Invalid regex in rule {rule.id}: {e}")
                return

        self.rules[rule.id] = rule
        logger.info(f"Added rule: {rule.id} - {rule.name}")

    def remove_rule(self, rule_id: str):
        """Remove a rule."""
        if rule_id in self.rules:
            del self.rules[rule_id]
            logger.info(f"Removed rule: {rule_id}")

    def enable_rule(self, rule_id: str, enabled: bool = True):
        """Enable or disable a rule."""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = enabled

    def start_detection(self, interface: str = None):
        """Start intrusion detection."""
        if self._running:
            logger.warning("Detection already running")
            return

        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._detection_loop,
            args=(interface,),
            daemon=True
        )
        self._monitor_thread.start()
        logger.info(f"Started IDS with {len(self.rules)} rules")

    def stop_detection(self):
        """Stop intrusion detection."""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2)
        logger.info("Stopped IDS")

    def _detection_loop(self, interface: str):
        """Main detection loop."""
        try:
            if hasattr(socket, 'AF_PACKET'):
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                if interface:
                    sock.bind((interface, 0))
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            sock.settimeout(1)

            while self._running:
                try:
                    raw_data, _ = sock.recvfrom(65536)
                    self._analyze_packet(raw_data)
                except socket.timeout:
                    self._check_rate_limits()
                except Exception as e:
                    logger.debug(f"Packet analysis error: {e}")

            if not hasattr(socket, 'AF_PACKET'):
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()

        except PermissionError:
            logger.error("IDS requires administrator/root privileges")
        except Exception as e:
            logger.error(f"IDS error: {e}")

    def _analyze_packet(self, raw_data: bytes):
        """Analyze a packet against all rules."""
        packet_info = self._parse_packet(raw_data)
        if not packet_info:
            return

        # Update rate counters
        src_key = f"{packet_info['src_ip']}:{packet_info['dst_port']}"
        self._rate_counters[src_key]["count"] += 1
        self._rate_counters[src_key]["last_seen"] = datetime.now().timestamp()

        # Check each enabled rule
        for rule in self.rules.values():
            if not rule.enabled:
                continue

            if self._matches_rule(rule, packet_info, raw_data):
                self._trigger_detection(rule, packet_info, raw_data)

    def _parse_packet(self, raw_data: bytes) -> Optional[Dict[str, Any]]:
        """Parse packet into structured format."""
        if len(raw_data) < 20:
            return None

        offset = 14 if raw_data[12:14] == b'\x08\x00' else 0

        ip_header = raw_data[offset:offset + 20]
        if len(ip_header) < 20:
            return None

        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        ihl = (iph[0] & 0xF) * 4
        protocol = iph[6]

        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])

        proto_name = {1: "icmp", 6: "tcp", 17: "udp"}.get(protocol, "other")

        src_port = 0
        dst_port = 0
        flags = ""
        payload = b""

        transport_offset = offset + ihl

        if protocol == 6:  # TCP
            if len(raw_data) >= transport_offset + 20:
                tcp_header = struct.unpack('!HHLLBBHHH', raw_data[transport_offset:transport_offset + 20])
                src_port = tcp_header[0]
                dst_port = tcp_header[1]
                flags = self._get_tcp_flags(tcp_header[5])
                data_offset = ((tcp_header[4] >> 4) * 4)
                payload = raw_data[transport_offset + data_offset:]

        elif protocol == 17:  # UDP
            if len(raw_data) >= transport_offset + 8:
                udp_header = struct.unpack('!HHHH', raw_data[transport_offset:transport_offset + 8])
                src_port = udp_header[0]
                dst_port = udp_header[1]
                payload = raw_data[transport_offset + 8:]

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto_name,
            "flags": flags,
            "payload": payload,
            "length": len(raw_data),
        }

    def _get_tcp_flags(self, flag_byte: int) -> str:
        """Convert TCP flags byte to string."""
        flags = []
        if flag_byte & 0x01:
            flags.append("F")
        if flag_byte & 0x02:
            flags.append("S")
        if flag_byte & 0x04:
            flags.append("R")
        if flag_byte & 0x08:
            flags.append("P")
        if flag_byte & 0x10:
            flags.append("A")
        if flag_byte & 0x20:
            flags.append("U")
        return "".join(flags)

    def _matches_rule(self, rule: Rule, packet: Dict[str, Any], raw_data: bytes) -> bool:
        """Check if packet matches rule criteria."""
        # Protocol check
        if rule.protocol != "any" and rule.protocol != packet["protocol"]:
            return False

        # Port checks
        if rule.dst_port != "any":
            ports = [int(p) for p in rule.dst_port.split(",")]
            if packet["dst_port"] not in ports:
                return False

        if rule.src_port != "any":
            ports = [int(p) for p in rule.src_port.split(",")]
            if packet["src_port"] not in ports:
                return False

        # Flags check
        if rule.flags and rule.flags not in packet["flags"]:
            return False

        # Content check
        if rule.content:
            content_bytes = rule.content.encode() if isinstance(rule.content, str) else rule.content
            if content_bytes not in packet["payload"]:
                return False

        # Regex check
        if rule.content_regex:
            try:
                payload_str = packet["payload"].decode(errors='ignore')
                if not rule.content_regex.search(payload_str):
                    return False
            except Exception:
                return False

        # Threshold check
        if rule.threshold:
            src_key = f"{packet['src_ip']}:{packet['dst_port']}"
            count = self._rate_counters[src_key]["count"]
            if count < rule.threshold:
                return False

        return True

    def _trigger_detection(self, rule: Rule, packet: Dict[str, Any], raw_data: bytes):
        """Create detection event."""
        detection = Detection(
            rule_id=rule.id,
            rule_name=rule.name,
            timestamp=datetime.now(),
            severity=rule.severity,
            source_ip=packet["src_ip"],
            source_port=packet["src_port"],
            dest_ip=packet["dst_ip"],
            dest_port=packet["dst_port"],
            protocol=packet["protocol"],
            payload_excerpt=packet["payload"][:100].decode(errors='ignore'),
            raw_packet=raw_data,
            metadata={"tags": rule.tags}
        )

        self.detections.append(detection)

        # Log alert
        logger.warning(
            f"[{rule.severity.value.upper()}] {rule.name} | "
            f"{packet['src_ip']}:{packet['src_port']} -> "
            f"{packet['dst_ip']}:{packet['dst_port']}"
        )

        # Store in database
        try:
            self.db.add_alert(Alert(
                rule_name=rule.id,
                severity=rule.severity.value,
                title=rule.name,
                description=rule.description,
                source_ip=packet["src_ip"],
                dest_ip=packet["dst_ip"],
            ))
        except Exception as e:
            logger.debug(f"Failed to store alert: {e}")

        # Callback
        if self.alert_callback:
            self.alert_callback(detection)

    def _check_rate_limits(self):
        """Periodic rate limit check."""
        now = datetime.now()
        if (now - self._last_rate_reset).seconds >= 60:
            self._rate_counters.clear()
            self._last_rate_reset = now

    def analyze_packet(self, raw_data: bytes) -> List[Detection]:
        """Analyze a single packet (for PCAP analysis)."""
        detections = []
        packet_info = self._parse_packet(raw_data)

        if packet_info:
            for rule in self.rules.values():
                if rule.enabled and self._matches_rule(rule, packet_info, raw_data):
                    detection = Detection(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        timestamp=datetime.now(),
                        severity=rule.severity,
                        source_ip=packet_info["src_ip"],
                        source_port=packet_info["src_port"],
                        dest_ip=packet_info["dst_ip"],
                        dest_port=packet_info["dst_port"],
                        protocol=packet_info["protocol"],
                        payload_excerpt=packet_info["payload"][:100].decode(errors='ignore'),
                    )
                    detections.append(detection)

        return detections

    def get_statistics(self) -> Dict[str, Any]:
        """Get IDS statistics."""
        severity_counts = defaultdict(int)
        rule_counts = defaultdict(int)

        for detection in self.detections:
            severity_counts[detection.severity.value] += 1
            rule_counts[detection.rule_id] += 1

        return {
            "total_detections": len(self.detections),
            "by_severity": dict(severity_counts),
            "top_rules": dict(sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "rules_loaded": len(self.rules),
            "rules_enabled": sum(1 for r in self.rules.values() if r.enabled),
        }

    def export_detections(self, output_file: str):
        """Export detections to JSON."""
        from blueteam.core.utils import export_to_json

        data = [
            {
                "rule_id": d.rule_id,
                "rule_name": d.rule_name,
                "timestamp": d.timestamp.isoformat(),
                "severity": d.severity.value,
                "source": f"{d.source_ip}:{d.source_port}",
                "dest": f"{d.dest_ip}:{d.dest_port}",
                "protocol": d.protocol,
                "payload_excerpt": d.payload_excerpt,
            }
            for d in self.detections
        ]

        export_to_json(data, output_file)
        logger.info(f"Exported {len(data)} detections to {output_file}")
