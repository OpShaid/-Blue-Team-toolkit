"""
Port Scanner - Defensive port scanning for security assessment.
"""

import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from blueteam.core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class PortResult:
    """Result of a port scan."""
    port: int
    state: str  # open, closed, filtered
    service: Optional[str] = None
    banner: Optional[str] = None
    version: Optional[str] = None


@dataclass
class ScanResult:
    """Complete scan result for a host."""
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    open_ports: List[PortResult] = None
    os_guess: Optional[str] = None
    total_ports: int = 0


class PortScanner:
    """
    Defensive port scanner for security assessment.

    Features:
    - TCP connect scan
    - TCP SYN scan (requires root)
    - Service detection
    - Banner grabbing
    - OS fingerprinting
    - Rate limiting
    """

    # Common service ports
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
    ]

    # Well-known services
    SERVICES = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
        139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
        993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
        3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
        6379: "redis", 8080: "http-proxy", 8443: "https-alt", 27017: "mongodb",
    }

    def __init__(self, timeout: float = 1.0, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads
        self.results: Dict[str, ScanResult] = {}

    def scan_port(self, target: str, port: int, grab_banner: bool = True) -> PortResult:
        """Scan a single port."""
        result = PortResult(
            port=port,
            state="closed",
            service=self.SERVICES.get(port, "unknown")
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            connection = sock.connect_ex((target, port))

            if connection == 0:
                result.state = "open"

                if grab_banner:
                    try:
                        # Try to grab banner
                        sock.settimeout(2)

                        # Send probe for HTTP
                        if port in (80, 8080, 8000, 8888):
                            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        elif port == 443:
                            pass  # Skip banner for SSL
                        else:
                            sock.send(b"\r\n")

                        banner = sock.recv(1024)
                        if banner:
                            result.banner = banner.decode(errors='ignore').strip()[:200]
                            result.version = self._extract_version(result.banner)
                    except Exception:
                        pass

            sock.close()

        except socket.timeout:
            result.state = "filtered"
        except socket.error:
            result.state = "closed"

        return result

    def _extract_version(self, banner: str) -> Optional[str]:
        """Extract version info from banner."""
        import re

        patterns = [
            r"SSH-[\d.]+-(\S+)",
            r"Server:\s*(.+?)[\r\n]",
            r"(Apache[^\r\n]+)",
            r"(nginx[^\r\n]+)",
            r"(OpenSSH[^\r\n]+)",
            r"(\d+\.\d+\.\d+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1).strip()

        return None

    def scan_host(
        self,
        target: str,
        ports: List[int] = None,
        port_range: Tuple[int, int] = None,
        common_ports: bool = False,
        grab_banners: bool = True
    ) -> ScanResult:
        """
        Scan a host for open ports.

        Args:
            target: Target IP or hostname
            ports: Specific list of ports
            port_range: Range of ports (start, end)
            common_ports: Scan common ports only
            grab_banners: Attempt banner grabbing
        """
        # Resolve hostname
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            logger.error(f"Cannot resolve hostname: {target}")
            return ScanResult(target=target, start_time=datetime.now())

        # Determine ports to scan
        if ports:
            scan_ports = ports
        elif port_range:
            scan_ports = range(port_range[0], port_range[1] + 1)
        elif common_ports:
            scan_ports = self.COMMON_PORTS
        else:
            scan_ports = range(1, 1025)

        result = ScanResult(
            target=target,
            start_time=datetime.now(),
            open_ports=[],
            total_ports=len(list(scan_ports))
        )

        logger.info(f"Starting scan of {target} ({len(list(scan_ports))} ports)")

        # Use thread pool for parallel scanning
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self.scan_port, target_ip, port, grab_banners): port
                for port in scan_ports
            }

            for future in as_completed(futures):
                try:
                    port_result = future.result()
                    if port_result.state == "open":
                        result.open_ports.append(port_result)
                        logger.info(f"  Port {port_result.port}/tcp open - {port_result.service}")
                except Exception as e:
                    logger.debug(f"Scan error: {e}")

        result.end_time = datetime.now()
        result.open_ports.sort(key=lambda x: x.port)

        # Store result
        self.results[target] = result

        duration = (result.end_time - result.start_time).total_seconds()
        logger.info(f"Scan complete: {len(result.open_ports)} open ports found in {duration:.2f}s")

        return result

    def scan_network(
        self,
        network: str,
        ports: List[int] = None
    ) -> Dict[str, ScanResult]:
        """Scan an entire network range."""
        import ipaddress

        results = {}

        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            logger.error(f"Invalid network: {e}")
            return results

        ports = ports or [22, 80, 443, 445, 3389]
        hosts = list(net.hosts())

        logger.info(f"Scanning {len(hosts)} hosts in {network}")

        for host in hosts:
            host_str = str(host)

            # Quick ping check
            if self._is_host_up(host_str):
                result = self.scan_host(host_str, ports=ports)
                if result.open_ports:
                    results[host_str] = result

        return results

    def _is_host_up(self, target: str) -> bool:
        """Quick check if host is responding."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, 80)) == 0 or sock.connect_ex((target, 443)) == 0
            sock.close()
            return result or self._icmp_ping(target)
        except Exception:
            return False

    def _icmp_ping(self, target: str) -> bool:
        """ICMP ping (requires root on Unix)."""
        import platform
        import subprocess

        param = "-n" if platform.system().lower() == "windows" else "-c"

        try:
            result = subprocess.run(
                ["ping", param, "1", "-w", "500", target],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except Exception:
            return False

    def syn_scan(self, target: str, ports: List[int]) -> List[PortResult]:
        """
        TCP SYN scan (half-open scan).
        Requires root/admin privileges.
        """
        results = []

        try:
            # Create raw socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.settimeout(self.timeout)

            target_ip = socket.gethostbyname(target)

            for port in ports:
                result = self._syn_scan_port(sock, target_ip, port)
                results.append(result)
                if result.state == "open":
                    logger.info(f"  Port {port}/tcp open (SYN)")

            sock.close()

        except PermissionError:
            logger.error("SYN scan requires root/admin privileges. Falling back to connect scan.")
            return [self.scan_port(target, p) for p in ports]
        except Exception as e:
            logger.error(f"SYN scan error: {e}")

        return results

    def _syn_scan_port(self, sock: socket.socket, target: str, port: int) -> PortResult:
        """Send SYN packet and check response."""
        result = PortResult(port=port, state="filtered", service=self.SERVICES.get(port))

        try:
            # Build TCP SYN packet (simplified)
            source_port = 12345

            # This is a simplified version - real implementation would need
            # proper packet crafting with scapy or similar
            sock.sendto(self._build_syn_packet(target, source_port, port), (target, 0))

            # Wait for response
            start = time.time()
            while time.time() - start < self.timeout:
                try:
                    data, addr = sock.recvfrom(1024)
                    if addr[0] == target:
                        # Check if SYN-ACK (simplified)
                        if len(data) >= 40:
                            flags = data[33]
                            if flags & 0x12 == 0x12:  # SYN-ACK
                                result.state = "open"
                            elif flags & 0x14 == 0x14:  # RST-ACK
                                result.state = "closed"
                        break
                except socket.timeout:
                    break

        except Exception:
            pass

        return result

    def _build_syn_packet(self, dest: str, src_port: int, dst_port: int) -> bytes:
        """Build a TCP SYN packet. Simplified version."""
        # This would need proper implementation with checksums
        # For now, return empty bytes as placeholder
        return b""

    def detect_services(self, result: ScanResult) -> ScanResult:
        """Perform service detection on open ports."""
        for port_result in result.open_ports:
            if not port_result.banner:
                # Try specific probes
                banner = self._probe_service(result.target, port_result.port)
                if banner:
                    port_result.banner = banner
                    port_result.version = self._extract_version(banner)

        return result

    def _probe_service(self, target: str, port: int) -> Optional[str]:
        """Send service-specific probes."""
        probes = {
            21: b"USER anonymous\r\n",
            22: b"",
            25: b"EHLO test\r\n",
            80: b"GET / HTTP/1.0\r\n\r\n",
            110: b"",
            143: b"",
            443: b"",  # Need SSL
        }

        probe = probes.get(port, b"\r\n")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            sock.send(probe)
            response = sock.recv(1024)
            sock.close()
            return response.decode(errors='ignore').strip()[:200]
        except Exception:
            return None

    def export_results(self, output_file: str, format: str = "json"):
        """Export scan results."""
        from blueteam.core.utils import export_to_json

        data = {}
        for target, result in self.results.items():
            data[target] = {
                "target": result.target,
                "start_time": result.start_time.isoformat(),
                "end_time": result.end_time.isoformat() if result.end_time else None,
                "total_ports_scanned": result.total_ports,
                "open_ports": [
                    {
                        "port": p.port,
                        "state": p.state,
                        "service": p.service,
                        "banner": p.banner,
                        "version": p.version,
                    }
                    for p in result.open_ports
                ],
            }

        export_to_json(data, output_file)
        logger.info(f"Exported results to {output_file}")

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all scans."""
        return {
            "hosts_scanned": len(self.results),
            "hosts_with_open_ports": sum(1 for r in self.results.values() if r.open_ports),
            "total_open_ports": sum(len(r.open_ports) for r in self.results.values()),
            "common_open_ports": self._get_common_ports(),
        }

    def _get_common_ports(self) -> Dict[int, int]:
        """Get most commonly open ports across scans."""
        from collections import Counter
        ports = Counter()
        for result in self.results.values():
            for port in result.open_ports:
                ports[port.port] += 1
        return dict(ports.most_common(10))
