"""
Network Traffic Analyzer - Real-time packet capture and analysis.
"""

import socket
import struct
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set
from queue import Queue

from blueteam.core.logger import get_logger
from blueteam.core.database import Database
from blueteam.core.utils import is_private_ip, get_ip_info

logger = get_logger(__name__)


@dataclass
class Packet:
    """Represents a captured network packet."""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    length: int
    flags: str = ""
    payload: bytes = b""
    raw: bytes = b""


@dataclass
class ConnectionStats:
    """Statistics for a network connection."""
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    packets: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    flags: Set[str] = field(default_factory=set)


class NetworkAnalyzer:
    """
    Real-time network traffic analyzer with threat detection capabilities.

    Features:
    - Live packet capture (requires admin/root)
    - Protocol analysis (TCP, UDP, ICMP, DNS)
    - Connection tracking
    - Anomaly detection
    - Suspicious pattern matching
    - Export to PCAP format
    """

    # Suspicious ports commonly used by malware
    SUSPICIOUS_PORTS = {
        4444, 5555, 6666, 7777,  # Common backdoor ports
        1337, 31337,  # "Elite" hacker ports
        3389,  # RDP
        5900, 5901,  # VNC
        6667, 6668, 6669,  # IRC (C2)
        8080, 8443,  # Common proxy/C2
        9001, 9030,  # Tor
        12345, 54321,  # Common trojans
    }

    # Known malicious patterns
    SUSPICIOUS_PATTERNS = [
        b"cmd.exe",
        b"/bin/sh",
        b"/bin/bash",
        b"powershell",
        b"wget ",
        b"curl ",
        b"nc -e",
        b"netcat",
        b"whoami",
        b"uname -a",
        b"POST /gate",  # Common C2 pattern
        b"beacon",
    ]

    def __init__(
        self,
        interface: str = None,
        db: Database = None,
        packet_callback: Callable[[Packet], None] = None
    ):
        self.interface = interface
        self.db = db or Database()
        self.packet_callback = packet_callback

        self._running = False
        self._capture_thread = None
        self._packet_queue = Queue()

        # Statistics
        self.connections: Dict[tuple, ConnectionStats] = {}
        self.protocol_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.ip_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})
        self.alerts: List[Dict[str, Any]] = []

        # Detection rules
        self.port_scan_threshold = 20  # Ports per minute
        self.connection_threshold = 100  # Connections per minute
        self._port_scan_tracker: Dict[str, Set[int]] = defaultdict(set)
        self._connection_tracker: Dict[str, int] = defaultdict(int)

    def start_capture(self, filter_expr: str = None, promiscuous: bool = True):
        """Start capturing network traffic."""
        if self._running:
            logger.warning("Capture already running")
            return

        self._running = True
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(filter_expr, promiscuous),
            daemon=True
        )
        self._capture_thread.start()
        logger.info(f"Started network capture on {self.interface or 'default interface'}")

    def stop_capture(self):
        """Stop capturing network traffic."""
        self._running = False
        if self._capture_thread:
            self._capture_thread.join(timeout=2)
        logger.info("Stopped network capture")

    def _capture_loop(self, filter_expr: str, promiscuous: bool):
        """Main capture loop using raw sockets."""
        try:
            # Create raw socket (requires admin/root)
            if hasattr(socket, 'AF_PACKET'):
                # Linux
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                if self.interface:
                    sock.bind((self.interface, 0))
            else:
                # Windows
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                if promiscuous:
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            sock.settimeout(1)

            while self._running:
                try:
                    raw_data, addr = sock.recvfrom(65536)
                    self._process_packet(raw_data)
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.debug(f"Packet capture error: {e}")

            # Cleanup
            if not hasattr(socket, 'AF_PACKET') and promiscuous:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()

        except PermissionError:
            logger.error("Permission denied. Run with administrator/root privileges.")
        except Exception as e:
            logger.error(f"Capture error: {e}")

    def _process_packet(self, raw_data: bytes):
        """Process a captured packet."""
        try:
            packet = self._parse_packet(raw_data)
            if packet:
                self._update_stats(packet)
                self._detect_threats(packet)

                if self.packet_callback:
                    self.packet_callback(packet)

        except Exception as e:
            logger.debug(f"Packet processing error: {e}")

    def _parse_packet(self, raw_data: bytes) -> Optional[Packet]:
        """Parse raw packet data."""
        if len(raw_data) < 20:
            return None

        # Check for Ethernet header (Linux) or start with IP (Windows)
        offset = 0
        if raw_data[12:14] == b'\x08\x00':  # Ethernet with IPv4
            offset = 14

        # Parse IP header
        ip_header = raw_data[offset:offset + 20]
        if len(ip_header) < 20:
            return None

        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        ihl = (version_ihl & 0xF) * 4
        protocol = iph[6]
        source_ip = socket.inet_ntoa(iph[8])
        dest_ip = socket.inet_ntoa(iph[9])

        source_port = 0
        dest_port = 0
        flags = ""
        protocol_name = "OTHER"

        # Parse transport layer
        transport_offset = offset + ihl

        if protocol == 6:  # TCP
            protocol_name = "TCP"
            if len(raw_data) >= transport_offset + 20:
                tcp_header = struct.unpack('!HHLLBBHHH', raw_data[transport_offset:transport_offset + 20])
                source_port = tcp_header[0]
                dest_port = tcp_header[1]
                flag_byte = tcp_header[5]
                flags = self._parse_tcp_flags(flag_byte)

        elif protocol == 17:  # UDP
            protocol_name = "UDP"
            if len(raw_data) >= transport_offset + 8:
                udp_header = struct.unpack('!HHHH', raw_data[transport_offset:transport_offset + 8])
                source_port = udp_header[0]
                dest_port = udp_header[1]

        elif protocol == 1:  # ICMP
            protocol_name = "ICMP"

        return Packet(
            timestamp=datetime.now(),
            source_ip=source_ip,
            dest_ip=dest_ip,
            source_port=source_port,
            dest_port=dest_port,
            protocol=protocol_name,
            length=len(raw_data),
            flags=flags,
            payload=raw_data[transport_offset + 20:] if protocol == 6 else raw_data[transport_offset + 8:],
            raw=raw_data
        )

    def _parse_tcp_flags(self, flag_byte: int) -> str:
        """Parse TCP flags byte."""
        flags = []
        if flag_byte & 0x01:
            flags.append("FIN")
        if flag_byte & 0x02:
            flags.append("SYN")
        if flag_byte & 0x04:
            flags.append("RST")
        if flag_byte & 0x08:
            flags.append("PSH")
        if flag_byte & 0x10:
            flags.append("ACK")
        if flag_byte & 0x20:
            flags.append("URG")
        return ",".join(flags)

    def _update_stats(self, packet: Packet):
        """Update statistics with packet info."""
        # Protocol stats
        self.protocol_stats[packet.protocol] += 1

        # Port stats
        if packet.dest_port:
            self.port_stats[packet.dest_port] += 1

        # IP stats
        self.ip_stats[packet.source_ip]["packets"] += 1
        self.ip_stats[packet.source_ip]["bytes"] += packet.length

        # Connection tracking
        conn_key = (
            packet.source_ip, packet.dest_ip,
            packet.source_port, packet.dest_port,
            packet.protocol
        )

        if conn_key not in self.connections:
            self.connections[conn_key] = ConnectionStats(
                source_ip=packet.source_ip,
                dest_ip=packet.dest_ip,
                source_port=packet.source_port,
                dest_port=packet.dest_port,
                protocol=packet.protocol,
                first_seen=packet.timestamp
            )

        conn = self.connections[conn_key]
        conn.packets += 1
        conn.bytes_sent += packet.length
        conn.last_seen = packet.timestamp
        if packet.flags:
            conn.flags.update(packet.flags.split(","))

    def _detect_threats(self, packet: Packet):
        """Detect potential threats in packet."""
        alerts = []

        # Check suspicious ports
        if packet.dest_port in self.SUSPICIOUS_PORTS:
            alerts.append({
                "type": "suspicious_port",
                "severity": "medium",
                "message": f"Connection to suspicious port {packet.dest_port}",
                "source_ip": packet.source_ip,
                "dest_ip": packet.dest_ip,
                "dest_port": packet.dest_port,
            })

        # Check payload for suspicious patterns
        if packet.payload:
            for pattern in self.SUSPICIOUS_PATTERNS:
                if pattern in packet.payload:
                    alerts.append({
                        "type": "suspicious_payload",
                        "severity": "high",
                        "message": f"Suspicious pattern detected: {pattern.decode(errors='ignore')}",
                        "source_ip": packet.source_ip,
                        "dest_ip": packet.dest_ip,
                    })
                    break

        # Port scan detection
        self._port_scan_tracker[packet.source_ip].add(packet.dest_port)
        if len(self._port_scan_tracker[packet.source_ip]) > self.port_scan_threshold:
            alerts.append({
                "type": "port_scan",
                "severity": "high",
                "message": f"Possible port scan from {packet.source_ip}",
                "source_ip": packet.source_ip,
                "ports_scanned": len(self._port_scan_tracker[packet.source_ip]),
            })
            self._port_scan_tracker[packet.source_ip].clear()

        # Connection flood detection
        self._connection_tracker[packet.source_ip] += 1
        if self._connection_tracker[packet.source_ip] > self.connection_threshold:
            if "SYN" in packet.flags and "ACK" not in packet.flags:
                alerts.append({
                    "type": "syn_flood",
                    "severity": "critical",
                    "message": f"Possible SYN flood from {packet.source_ip}",
                    "source_ip": packet.source_ip,
                })

        # External to internal connection (potential intrusion)
        if not is_private_ip(packet.source_ip) and is_private_ip(packet.dest_ip):
            if packet.dest_port in [22, 23, 3389, 5900]:
                alerts.append({
                    "type": "external_access",
                    "severity": "medium",
                    "message": f"External access attempt to {packet.dest_ip}:{packet.dest_port}",
                    "source_ip": packet.source_ip,
                    "dest_ip": packet.dest_ip,
                    "dest_port": packet.dest_port,
                })

        # Store alerts
        for alert in alerts:
            alert["timestamp"] = packet.timestamp.isoformat()
            self.alerts.append(alert)
            logger.warning(f"ALERT: {alert['message']}")

    def get_stats(self) -> Dict[str, Any]:
        """Get current capture statistics."""
        return {
            "total_connections": len(self.connections),
            "protocol_stats": dict(self.protocol_stats),
            "top_ports": sorted(
                self.port_stats.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10],
            "top_talkers": sorted(
                [(ip, stats["bytes"]) for ip, stats in self.ip_stats.items()],
                key=lambda x: x[1],
                reverse=True
            )[:10],
            "alerts": len(self.alerts),
        }

    def get_connections(self, active_only: bool = False) -> List[Dict[str, Any]]:
        """Get list of connections."""
        connections = []
        now = datetime.now()

        for conn in self.connections.values():
            if active_only and conn.last_seen:
                age = (now - conn.last_seen).total_seconds()
                if age > 300:  # 5 minutes timeout
                    continue

            connections.append({
                "source": f"{conn.source_ip}:{conn.source_port}",
                "dest": f"{conn.dest_ip}:{conn.dest_port}",
                "protocol": conn.protocol,
                "packets": conn.packets,
                "bytes": conn.bytes_sent,
                "flags": list(conn.flags),
                "first_seen": conn.first_seen.isoformat() if conn.first_seen else None,
                "last_seen": conn.last_seen.isoformat() if conn.last_seen else None,
            })

        return connections

    def analyze_pcap(self, pcap_file: str) -> Dict[str, Any]:
        """Analyze a PCAP file."""
        from blueteam.network.pcap_parser import PcapParser

        parser = PcapParser(pcap_file)
        results = {
            "file": pcap_file,
            "packets": 0,
            "connections": [],
            "alerts": [],
            "dns_queries": [],
            "http_requests": [],
        }

        for packet in parser.parse():
            results["packets"] += 1
            self._update_stats(packet)
            self._detect_threats(packet)

        results["connections"] = self.get_connections()
        results["alerts"] = self.alerts
        results["stats"] = self.get_stats()

        return results

    def export_connections(self, output_file: str):
        """Export connections to CSV."""
        from blueteam.core.utils import export_to_csv

        connections = self.get_connections()
        export_to_csv(connections, output_file)
        logger.info(f"Exported {len(connections)} connections to {output_file}")
