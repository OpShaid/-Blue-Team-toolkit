"""
Connection Tracker - Track and analyze network connections.
"""

import socket
import subprocess
import platform
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from pathlib import Path

from blueteam.core.logger import get_logger
from blueteam.core.utils import is_private_ip, get_ip_info

logger = get_logger(__name__)


@dataclass
class Connection:
    """Represents a network connection."""
    protocol: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str
    pid: Optional[int] = None
    process_name: Optional[str] = None
    timestamp: Optional[datetime] = None


class ConnectionTracker:
    """
    Track active network connections on the system.

    Features:
    - Live connection monitoring
    - Process correlation
    - Suspicious connection detection
    - Connection history
    - Baseline comparison
    """

    # Suspicious indicators
    SUSPICIOUS_PORTS = {
        4444, 5555, 6666, 7777, 1337, 31337,  # Backdoors
        6667, 6668, 6669,  # IRC C2
        9001, 9030,  # Tor
        8545, 30303,  # Crypto mining
    }

    SUSPICIOUS_COUNTRIES = {"KP", "IR", "RU", "CN", "BY"}  # Example high-risk countries

    def __init__(self):
        self.connections: List[Connection] = []
        self.baseline: Set[tuple] = set()
        self.history: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []

    def get_connections(self) -> List[Connection]:
        """Get current network connections."""
        self.connections = []

        system = platform.system()

        if system == "Windows":
            self._get_windows_connections()
        else:
            self._get_unix_connections()

        return self.connections

    def _get_windows_connections(self):
        """Get connections on Windows using netstat."""
        try:
            result = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True,
                text=True,
                timeout=30
            )

            for line in result.stdout.split("\n")[4:]:
                parts = line.split()
                if len(parts) >= 5:
                    protocol = parts[0]
                    local = parts[1]
                    remote = parts[2]
                    state = parts[3] if len(parts) > 4 else ""
                    pid = int(parts[-1]) if parts[-1].isdigit() else None

                    local_addr, local_port = self._parse_address(local)
                    remote_addr, remote_port = self._parse_address(remote)

                    if local_addr and remote_addr:
                        conn = Connection(
                            protocol=protocol,
                            local_address=local_addr,
                            local_port=local_port,
                            remote_address=remote_addr,
                            remote_port=remote_port,
                            state=state,
                            pid=pid,
                            process_name=self._get_process_name(pid) if pid else None,
                            timestamp=datetime.now()
                        )
                        self.connections.append(conn)

        except Exception as e:
            logger.error(f"Error getting Windows connections: {e}")

    def _get_unix_connections(self):
        """Get connections on Unix-like systems."""
        try:
            # Try ss first (faster), fall back to netstat
            try:
                result = subprocess.run(
                    ["ss", "-tunap"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                self._parse_ss_output(result.stdout)
            except FileNotFoundError:
                result = subprocess.run(
                    ["netstat", "-tunap"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                self._parse_netstat_output(result.stdout)

        except Exception as e:
            logger.error(f"Error getting Unix connections: {e}")

    def _parse_ss_output(self, output: str):
        """Parse ss command output."""
        for line in output.split("\n")[1:]:
            parts = line.split()
            if len(parts) >= 5:
                protocol = parts[0]
                state = parts[1]
                local = parts[4]
                remote = parts[5] if len(parts) > 5 else ""

                local_addr, local_port = self._parse_address(local)
                remote_addr, remote_port = self._parse_address(remote)

                pid = None
                process_name = None
                if len(parts) > 6:
                    match = re.search(r'pid=(\d+)', parts[6])
                    if match:
                        pid = int(match.group(1))
                    match = re.search(r'"([^"]+)"', parts[6])
                    if match:
                        process_name = match.group(1)

                if local_addr:
                    self.connections.append(Connection(
                        protocol=protocol,
                        local_address=local_addr,
                        local_port=local_port,
                        remote_address=remote_addr or "0.0.0.0",
                        remote_port=remote_port,
                        state=state,
                        pid=pid,
                        process_name=process_name,
                        timestamp=datetime.now()
                    ))

    def _parse_netstat_output(self, output: str):
        """Parse netstat command output."""
        for line in output.split("\n")[2:]:
            parts = line.split()
            if len(parts) >= 4:
                protocol = parts[0]
                local = parts[3]
                remote = parts[4] if len(parts) > 4 else ""
                state = parts[5] if len(parts) > 5 else ""

                local_addr, local_port = self._parse_address(local)
                remote_addr, remote_port = self._parse_address(remote)

                pid = None
                process_name = None
                if len(parts) > 6:
                    pid_prog = parts[6]
                    if "/" in pid_prog:
                        pid_str, process_name = pid_prog.split("/", 1)
                        pid = int(pid_str) if pid_str.isdigit() else None

                if local_addr:
                    self.connections.append(Connection(
                        protocol=protocol,
                        local_address=local_addr,
                        local_port=local_port,
                        remote_address=remote_addr or "0.0.0.0",
                        remote_port=remote_port,
                        state=state,
                        pid=pid,
                        process_name=process_name,
                        timestamp=datetime.now()
                    ))

    def _parse_address(self, addr: str) -> tuple:
        """Parse address:port string."""
        if not addr or addr in ("*:*", "0.0.0.0:*", "[::]:*"):
            return None, 0

        # Handle IPv6
        if addr.startswith("["):
            match = re.match(r'\[([^\]]+)\]:(\d+)', addr)
            if match:
                return match.group(1), int(match.group(2))
            return None, 0

        # Handle IPv4
        if ":" in addr:
            parts = addr.rsplit(":", 1)
            try:
                return parts[0], int(parts[1])
            except (ValueError, IndexError):
                return None, 0

        return addr, 0

    def _get_process_name(self, pid: int) -> Optional[str]:
        """Get process name from PID."""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.stdout.strip():
                    parts = result.stdout.strip().split(",")
                    if parts:
                        return parts[0].strip('"')
            else:
                proc_path = Path(f"/proc/{pid}/comm")
                if proc_path.exists():
                    return proc_path.read_text().strip()
        except Exception:
            pass
        return None

    def set_baseline(self):
        """Set current connections as baseline."""
        self.get_connections()
        self.baseline = set()

        for conn in self.connections:
            self.baseline.add((
                conn.remote_address,
                conn.remote_port,
                conn.local_port,
                conn.protocol
            ))

        logger.info(f"Baseline set with {len(self.baseline)} connection patterns")

    def find_new_connections(self) -> List[Connection]:
        """Find connections not in baseline."""
        self.get_connections()
        new_connections = []

        for conn in self.connections:
            key = (
                conn.remote_address,
                conn.remote_port,
                conn.local_port,
                conn.protocol
            )
            if key not in self.baseline:
                new_connections.append(conn)

        return new_connections

    def analyze_connections(self) -> Dict[str, Any]:
        """Analyze current connections for threats."""
        self.get_connections()
        self.alerts = []

        analysis = {
            "total_connections": len(self.connections),
            "established": 0,
            "listening": 0,
            "external": 0,
            "internal": 0,
            "by_process": defaultdict(int),
            "by_port": defaultdict(int),
            "suspicious": [],
        }

        for conn in self.connections:
            # Count states
            if conn.state == "ESTABLISHED":
                analysis["established"] += 1
            elif conn.state in ("LISTEN", "LISTENING"):
                analysis["listening"] += 1

            # Count internal/external
            if is_private_ip(conn.remote_address):
                analysis["internal"] += 1
            else:
                analysis["external"] += 1

            # Count by process
            if conn.process_name:
                analysis["by_process"][conn.process_name] += 1

            # Count by port
            analysis["by_port"][conn.remote_port] += 1

            # Check for suspicious connections
            suspicious = self._check_suspicious(conn)
            if suspicious:
                analysis["suspicious"].append(suspicious)
                self.alerts.append(suspicious)

        # Convert defaultdicts
        analysis["by_process"] = dict(analysis["by_process"])
        analysis["by_port"] = dict(sorted(
            analysis["by_port"].items(),
            key=lambda x: x[1],
            reverse=True
        )[:20])

        return analysis

    def _check_suspicious(self, conn: Connection) -> Optional[Dict[str, Any]]:
        """Check if connection is suspicious."""
        reasons = []

        # Suspicious port
        if conn.remote_port in self.SUSPICIOUS_PORTS:
            reasons.append(f"Connection to suspicious port {conn.remote_port}")

        # Connection to external IP on unusual port
        if not is_private_ip(conn.remote_address):
            if conn.remote_port not in {80, 443, 53, 22, 21, 25, 587, 993, 995}:
                if conn.state == "ESTABLISHED":
                    reasons.append(f"Established connection to external IP on port {conn.remote_port}")

        # Unknown process with external connection
        if not conn.process_name and not is_private_ip(conn.remote_address):
            reasons.append("External connection from unknown process")

        # Reverse shell indicators
        if conn.local_port > 1024 and conn.remote_port in {4444, 5555, 6666, 1337}:
            reasons.append("Possible reverse shell connection")

        if reasons:
            return {
                "connection": {
                    "local": f"{conn.local_address}:{conn.local_port}",
                    "remote": f"{conn.remote_address}:{conn.remote_port}",
                    "protocol": conn.protocol,
                    "state": conn.state,
                    "process": conn.process_name,
                    "pid": conn.pid,
                },
                "reasons": reasons,
                "severity": "high" if len(reasons) > 1 else "medium",
                "timestamp": datetime.now().isoformat(),
            }

        return None

    def get_listening_ports(self) -> List[Dict[str, Any]]:
        """Get all listening ports."""
        self.get_connections()
        listening = []

        for conn in self.connections:
            if conn.state in ("LISTEN", "LISTENING"):
                listening.append({
                    "port": conn.local_port,
                    "protocol": conn.protocol,
                    "address": conn.local_address,
                    "process": conn.process_name,
                    "pid": conn.pid,
                })

        return sorted(listening, key=lambda x: x["port"])

    def find_process_connections(self, process_name: str) -> List[Connection]:
        """Find all connections for a specific process."""
        self.get_connections()
        return [
            conn for conn in self.connections
            if conn.process_name and process_name.lower() in conn.process_name.lower()
        ]

    def export_connections(self, output_file: str):
        """Export connections to file."""
        from blueteam.core.utils import export_to_json

        self.get_connections()
        data = []

        for conn in self.connections:
            data.append({
                "timestamp": conn.timestamp.isoformat() if conn.timestamp else None,
                "protocol": conn.protocol,
                "local_address": conn.local_address,
                "local_port": conn.local_port,
                "remote_address": conn.remote_address,
                "remote_port": conn.remote_port,
                "state": conn.state,
                "pid": conn.pid,
                "process": conn.process_name,
            })

        export_to_json(data, output_file)
        logger.info(f"Exported {len(data)} connections to {output_file}")
