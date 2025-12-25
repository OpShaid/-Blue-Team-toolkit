"""
PCAP File Parser - Parse and analyze PCAP/PCAPNG files.
"""

import struct
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional, Dict, Any, List
from dataclasses import dataclass

from blueteam.core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class PcapPacket:
    """Represents a packet from a PCAP file."""
    timestamp: datetime
    captured_len: int
    original_len: int
    data: bytes


class PcapParser:
    """
    Parse PCAP and PCAPNG files for analysis.

    Supports:
    - PCAP format (libpcap)
    - PCAPNG format
    - Both little and big endian
    """

    # PCAP magic numbers
    PCAP_MAGIC_LE = 0xa1b2c3d4  # Little endian microseconds
    PCAP_MAGIC_BE = 0xd4c3b2a1  # Big endian microseconds
    PCAP_MAGIC_NS_LE = 0xa1b23c4d  # Little endian nanoseconds
    PCAP_MAGIC_NS_BE = 0x4d3cb2a1  # Big endian nanoseconds
    PCAPNG_MAGIC = 0x0a0d0d0a  # PCAPNG Section Header Block

    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.is_pcapng = False
        self.is_nanoseconds = False
        self.byte_order = "<"  # Little endian default
        self.link_type = 1  # Ethernet default

        if not self.file_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {file_path}")

    def parse(self) -> Generator[PcapPacket, None, None]:
        """Parse PCAP file and yield packets."""
        with open(self.file_path, "rb") as f:
            # Read magic number
            magic = struct.unpack("<I", f.read(4))[0]

            if magic == self.PCAPNG_MAGIC:
                self.is_pcapng = True
                f.seek(0)
                yield from self._parse_pcapng(f)
            elif magic in (self.PCAP_MAGIC_LE, self.PCAP_MAGIC_NS_LE):
                self.byte_order = "<"
                self.is_nanoseconds = magic == self.PCAP_MAGIC_NS_LE
                yield from self._parse_pcap(f)
            elif magic in (self.PCAP_MAGIC_BE, self.PCAP_MAGIC_NS_BE):
                self.byte_order = ">"
                self.is_nanoseconds = magic == self.PCAP_MAGIC_NS_BE
                yield from self._parse_pcap(f)
            else:
                raise ValueError(f"Unknown PCAP format: {hex(magic)}")

    def _parse_pcap(self, f) -> Generator[PcapPacket, None, None]:
        """Parse standard PCAP file."""
        # Read global header (already read magic)
        header = f.read(20)
        if len(header) < 20:
            return

        version_major, version_minor, thiszone, sigfigs, snaplen, network = struct.unpack(
            f"{self.byte_order}HHIIII", header
        )
        self.link_type = network

        logger.debug(f"PCAP version {version_major}.{version_minor}, snaplen={snaplen}")

        # Read packets
        while True:
            packet_header = f.read(16)
            if len(packet_header) < 16:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                f"{self.byte_order}IIII", packet_header
            )

            # Convert timestamp
            if self.is_nanoseconds:
                timestamp = datetime.fromtimestamp(ts_sec + ts_usec / 1e9)
            else:
                timestamp = datetime.fromtimestamp(ts_sec + ts_usec / 1e6)

            # Read packet data
            data = f.read(incl_len)
            if len(data) < incl_len:
                break

            yield PcapPacket(
                timestamp=timestamp,
                captured_len=incl_len,
                original_len=orig_len,
                data=data
            )

    def _parse_pcapng(self, f) -> Generator[PcapPacket, None, None]:
        """Parse PCAPNG file."""
        while True:
            block_header = f.read(8)
            if len(block_header) < 8:
                break

            block_type, block_len = struct.unpack("<II", block_header)

            if block_len < 12:
                break

            block_data = f.read(block_len - 12)
            f.read(4)  # Block length trailer

            if block_type == 0x00000006:  # Enhanced Packet Block
                if len(block_data) >= 20:
                    interface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(
                        "<IIIII", block_data[:20]
                    )

                    # Calculate timestamp (microseconds since epoch)
                    timestamp_us = (ts_high << 32) | ts_low
                    timestamp = datetime.fromtimestamp(timestamp_us / 1e6)

                    packet_data = block_data[20:20 + cap_len]

                    yield PcapPacket(
                        timestamp=timestamp,
                        captured_len=cap_len,
                        original_len=orig_len,
                        data=packet_data
                    )

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics from PCAP file."""
        stats = {
            "file": str(self.file_path),
            "file_size": self.file_path.stat().st_size,
            "total_packets": 0,
            "total_bytes": 0,
            "start_time": None,
            "end_time": None,
            "duration": 0,
            "protocols": {},
            "src_ips": {},
            "dst_ips": {},
            "ports": {},
        }

        for packet in self.parse():
            stats["total_packets"] += 1
            stats["total_bytes"] += packet.original_len

            if stats["start_time"] is None:
                stats["start_time"] = packet.timestamp
            stats["end_time"] = packet.timestamp

            # Parse Ethernet + IP if present
            if len(packet.data) > 34 and packet.data[12:14] == b'\x08\x00':
                ip_data = packet.data[14:]
                protocol = ip_data[9]

                # Track protocols
                proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(protocol, str(protocol))
                stats["protocols"][proto_name] = stats["protocols"].get(proto_name, 0) + 1

                # Track IPs
                import socket
                src_ip = socket.inet_ntoa(ip_data[12:16])
                dst_ip = socket.inet_ntoa(ip_data[16:20])
                stats["src_ips"][src_ip] = stats["src_ips"].get(src_ip, 0) + 1
                stats["dst_ips"][dst_ip] = stats["dst_ips"].get(dst_ip, 0) + 1

                # Track ports for TCP/UDP
                if protocol in (6, 17):
                    ihl = (ip_data[0] & 0x0F) * 4
                    if len(ip_data) > ihl + 4:
                        src_port, dst_port = struct.unpack("!HH", ip_data[ihl:ihl + 4])
                        stats["ports"][dst_port] = stats["ports"].get(dst_port, 0) + 1

        if stats["start_time"] and stats["end_time"]:
            stats["duration"] = (stats["end_time"] - stats["start_time"]).total_seconds()
            stats["start_time"] = stats["start_time"].isoformat()
            stats["end_time"] = stats["end_time"].isoformat()

        # Sort and limit
        stats["src_ips"] = dict(sorted(stats["src_ips"].items(), key=lambda x: x[1], reverse=True)[:20])
        stats["dst_ips"] = dict(sorted(stats["dst_ips"].items(), key=lambda x: x[1], reverse=True)[:20])
        stats["ports"] = dict(sorted(stats["ports"].items(), key=lambda x: x[1], reverse=True)[:20])

        return stats

    def extract_streams(self) -> Dict[tuple, List[bytes]]:
        """Extract TCP streams from PCAP."""
        streams = {}

        for packet in self.parse():
            if len(packet.data) < 54:  # Minimum Ethernet + IP + TCP
                continue

            # Check for IPv4
            if packet.data[12:14] != b'\x08\x00':
                continue

            ip_data = packet.data[14:]
            protocol = ip_data[9]

            if protocol != 6:  # TCP only
                continue

            import socket
            src_ip = socket.inet_ntoa(ip_data[12:16])
            dst_ip = socket.inet_ntoa(ip_data[16:20])

            ihl = (ip_data[0] & 0x0F) * 4
            tcp_data = ip_data[ihl:]

            if len(tcp_data) < 20:
                continue

            src_port, dst_port = struct.unpack("!HH", tcp_data[:4])
            data_offset = ((tcp_data[12] >> 4) * 4)
            payload = tcp_data[data_offset:]

            if payload:
                stream_key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
                if stream_key not in streams:
                    streams[stream_key] = []
                streams[stream_key].append(payload)

        return streams

    def find_http_requests(self) -> List[Dict[str, Any]]:
        """Extract HTTP requests from PCAP."""
        requests = []
        http_methods = [b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH"]

        for packet in self.parse():
            if len(packet.data) < 54:
                continue

            # Find HTTP in payload
            payload_start = 54
            payload = packet.data[payload_start:]

            for method in http_methods:
                if payload.startswith(method + b" "):
                    try:
                        lines = payload.split(b"\r\n")
                        request_line = lines[0].decode('utf-8', errors='ignore')
                        headers = {}

                        for line in lines[1:]:
                            if b": " in line:
                                key, value = line.split(b": ", 1)
                                headers[key.decode()] = value.decode(errors='ignore')
                            elif line == b"":
                                break

                        requests.append({
                            "timestamp": packet.timestamp.isoformat(),
                            "method": method.decode(),
                            "request_line": request_line,
                            "host": headers.get("Host", ""),
                            "user_agent": headers.get("User-Agent", ""),
                            "headers": headers,
                        })
                    except Exception:
                        pass
                    break

        return requests

    def find_dns_queries(self) -> List[Dict[str, Any]]:
        """Extract DNS queries from PCAP."""
        queries = []

        for packet in self.parse():
            if len(packet.data) < 42:
                continue

            # Check for IPv4
            if packet.data[12:14] != b'\x08\x00':
                continue

            ip_data = packet.data[14:]
            protocol = ip_data[9]

            if protocol != 17:  # UDP only
                continue

            ihl = (ip_data[0] & 0x0F) * 4
            udp_data = ip_data[ihl:]

            if len(udp_data) < 8:
                continue

            src_port, dst_port = struct.unpack("!HH", udp_data[:4])

            if dst_port != 53 and src_port != 53:
                continue

            dns_data = udp_data[8:]
            if len(dns_data) < 12:
                continue

            # Parse DNS header
            flags = struct.unpack("!H", dns_data[2:4])[0]
            is_response = (flags >> 15) & 1
            qdcount = struct.unpack("!H", dns_data[4:6])[0]

            if qdcount == 0:
                continue

            # Parse question section
            offset = 12
            name_parts = []

            while offset < len(dns_data):
                length = dns_data[offset]
                if length == 0:
                    offset += 1
                    break
                if length >= 192:  # Compression pointer
                    offset += 2
                    break
                name_parts.append(dns_data[offset + 1:offset + 1 + length].decode(errors='ignore'))
                offset += length + 1

            if offset + 4 <= len(dns_data):
                qtype, qclass = struct.unpack("!HH", dns_data[offset:offset + 4])
                type_names = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA"}

                queries.append({
                    "timestamp": packet.timestamp.isoformat(),
                    "is_response": is_response,
                    "query": ".".join(name_parts),
                    "type": type_names.get(qtype, str(qtype)),
                })

        return queries
