"""
Syslog Parser - Parse and analyze syslog messages.
"""

import re
import socket
from datetime import datetime
from typing import Any, Dict, Generator, List, Optional
from dataclasses import dataclass, field
from pathlib import Path

from blueteam.core.logger import get_logger
from blueteam.logs.parser import LogEntry

logger = get_logger(__name__)


@dataclass
class SyslogMessage:
    """Represents a parsed syslog message."""
    timestamp: Optional[datetime]
    hostname: str
    facility: int
    severity: int
    app_name: str
    proc_id: Optional[str]
    msg_id: Optional[str]
    structured_data: Dict[str, Dict[str, str]]
    message: str
    raw: str


class SyslogParser:
    """
    Parse syslog messages (RFC 3164 and RFC 5424).

    Features:
    - BSD syslog (RFC 3164)
    - Modern syslog (RFC 5424)
    - Structured data parsing
    - Facility/severity decoding
    - Common log format detection
    """

    # Syslog facilities
    FACILITIES = {
        0: "kern", 1: "user", 2: "mail", 3: "daemon",
        4: "auth", 5: "syslog", 6: "lpr", 7: "news",
        8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
        12: "ntp", 13: "audit", 14: "alert", 15: "clock",
        16: "local0", 17: "local1", 18: "local2", 19: "local3",
        20: "local4", 21: "local5", 22: "local6", 23: "local7",
    }

    # Syslog severities
    SEVERITIES = {
        0: "emerg", 1: "alert", 2: "crit", 3: "err",
        4: "warning", 5: "notice", 6: "info", 7: "debug",
    }

    # RFC 5424 regex
    RFC5424_PATTERN = re.compile(
        r'^<(?P<priority>\d+)>(?P<version>\d+)\s+'
        r'(?P<timestamp>\S+)\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<appname>\S+)\s+'
        r'(?P<procid>\S+)\s+'
        r'(?P<msgid>\S+)\s+'
        r'(?P<sd>(?:\[.*?\])+|-)\s*'
        r'(?P<message>.*)?$'
    )

    # RFC 3164 regex
    RFC3164_PATTERN = re.compile(
        r'^(?:<(?P<priority>\d+)>)?'
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<tag>[\w\-]+)(?:\[(?P<pid>\d+)\])?:\s*'
        r'(?P<message>.*)$'
    )

    # Structured data regex
    SD_PATTERN = re.compile(r'\[([^\]]+)\]')
    SD_PARAM_PATTERN = re.compile(r'(\S+)="([^"]*)"')

    def __init__(self):
        self.messages: List[SyslogMessage] = []
        self.stats = {
            "total": 0,
            "rfc5424": 0,
            "rfc3164": 0,
            "by_facility": {},
            "by_severity": {},
            "by_host": {},
        }

    def parse_line(self, line: str) -> Optional[SyslogMessage]:
        """Parse a single syslog line."""
        line = line.strip()
        if not line:
            return None

        self.stats["total"] += 1

        # Try RFC 5424 first
        match = self.RFC5424_PATTERN.match(line)
        if match:
            self.stats["rfc5424"] += 1
            return self._parse_rfc5424(match, line)

        # Try RFC 3164
        match = self.RFC3164_PATTERN.match(line)
        if match:
            self.stats["rfc3164"] += 1
            return self._parse_rfc3164(match, line)

        # Fallback - basic parsing
        return self._parse_basic(line)

    def _parse_rfc5424(self, match: re.Match, raw: str) -> SyslogMessage:
        """Parse RFC 5424 format."""
        groups = match.groupdict()

        priority = int(groups["priority"])
        facility = priority >> 3
        severity = priority & 0x07

        # Parse timestamp
        timestamp = self._parse_timestamp(groups["timestamp"])

        # Parse structured data
        sd = {}
        sd_raw = groups["sd"]
        if sd_raw != "-":
            for sd_match in self.SD_PATTERN.finditer(sd_raw):
                sd_content = sd_match.group(1)
                parts = sd_content.split(" ", 1)
                sd_id = parts[0]
                sd[sd_id] = {}
                if len(parts) > 1:
                    for param_match in self.SD_PARAM_PATTERN.finditer(parts[1]):
                        sd[sd_id][param_match.group(1)] = param_match.group(2)

        msg = SyslogMessage(
            timestamp=timestamp,
            hostname=groups["hostname"] if groups["hostname"] != "-" else "",
            facility=facility,
            severity=severity,
            app_name=groups["appname"] if groups["appname"] != "-" else "",
            proc_id=groups["procid"] if groups["procid"] != "-" else None,
            msg_id=groups["msgid"] if groups["msgid"] != "-" else None,
            structured_data=sd,
            message=groups["message"] or "",
            raw=raw
        )

        self._update_stats(msg)
        return msg

    def _parse_rfc3164(self, match: re.Match, raw: str) -> SyslogMessage:
        """Parse RFC 3164 (BSD) format."""
        groups = match.groupdict()

        priority = int(groups.get("priority", "13"))  # Default to user.notice
        facility = priority >> 3
        severity = priority & 0x07

        timestamp = self._parse_bsd_timestamp(groups["timestamp"])

        msg = SyslogMessage(
            timestamp=timestamp,
            hostname=groups["hostname"],
            facility=facility,
            severity=severity,
            app_name=groups["tag"],
            proc_id=groups.get("pid"),
            msg_id=None,
            structured_data={},
            message=groups["message"],
            raw=raw
        )

        self._update_stats(msg)
        return msg

    def _parse_basic(self, line: str) -> SyslogMessage:
        """Basic parsing for non-standard formats."""
        # Try to extract priority
        priority = 13  # Default: user.notice
        if line.startswith("<"):
            try:
                end = line.index(">")
                priority = int(line[1:end])
                line = line[end + 1:]
            except (ValueError, IndexError):
                pass

        return SyslogMessage(
            timestamp=None,
            hostname="unknown",
            facility=priority >> 3,
            severity=priority & 0x07,
            app_name="unknown",
            proc_id=None,
            msg_id=None,
            structured_data={},
            message=line,
            raw=line
        )

    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse RFC 5424 timestamp."""
        if ts_str == "-":
            return None

        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(ts_str[:26], fmt[:len(ts_str) + 2])
            except ValueError:
                continue

        return None

    def _parse_bsd_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse BSD syslog timestamp."""
        try:
            # BSD format doesn't include year
            parsed = datetime.strptime(ts_str, "%b %d %H:%M:%S")
            return parsed.replace(year=datetime.now().year)
        except ValueError:
            return None

    def _update_stats(self, msg: SyslogMessage):
        """Update parsing statistics."""
        facility_name = self.FACILITIES.get(msg.facility, str(msg.facility))
        severity_name = self.SEVERITIES.get(msg.severity, str(msg.severity))

        self.stats["by_facility"][facility_name] = self.stats["by_facility"].get(facility_name, 0) + 1
        self.stats["by_severity"][severity_name] = self.stats["by_severity"].get(severity_name, 0) + 1
        self.stats["by_host"][msg.hostname] = self.stats["by_host"].get(msg.hostname, 0) + 1

    def parse_file(self, file_path: str) -> Generator[SyslogMessage, None, None]:
        """Parse syslog file."""
        path = Path(file_path)

        if not path.exists():
            logger.error(f"File not found: {file_path}")
            return

        import gzip

        opener = gzip.open if path.suffix == ".gz" else open

        with opener(path, "rt", errors="ignore") as f:
            for line in f:
                msg = self.parse_line(line)
                if msg:
                    self.messages.append(msg)
                    yield msg

    def analyze_auth(self) -> Dict[str, Any]:
        """Analyze authentication-related messages."""
        auth_facilities = {4, 10}  # auth, authpriv
        auth_messages = [m for m in self.messages if m.facility in auth_facilities]

        failed_logins = []
        successful_logins = []
        sudo_commands = []

        for msg in auth_messages:
            message_lower = msg.message.lower()

            if "failed" in message_lower or "invalid" in message_lower:
                failed_logins.append(msg)
            elif "accepted" in message_lower or "successful" in message_lower:
                successful_logins.append(msg)
            elif "sudo" in message_lower:
                sudo_commands.append(msg)

        # Extract IPs from failed logins
        ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        failed_by_ip: Dict[str, int] = {}

        for msg in failed_logins:
            match = ip_pattern.search(msg.message)
            if match:
                ip = match.group(1)
                failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1

        return {
            "total_auth_messages": len(auth_messages),
            "failed_logins": len(failed_logins),
            "successful_logins": len(successful_logins),
            "sudo_commands": len(sudo_commands),
            "failed_by_ip": dict(sorted(failed_by_ip.items(), key=lambda x: x[1], reverse=True)[:10]),
            "potential_brute_force": [ip for ip, count in failed_by_ip.items() if count >= 10],
        }

    def analyze_services(self) -> Dict[str, Any]:
        """Analyze service-related messages."""
        services: Dict[str, Dict[str, int]] = {}

        for msg in self.messages:
            if msg.app_name not in services:
                services[msg.app_name] = {"total": 0, "errors": 0, "warnings": 0}

            services[msg.app_name]["total"] += 1

            if msg.severity <= 3:  # error or worse
                services[msg.app_name]["errors"] += 1
            elif msg.severity == 4:  # warning
                services[msg.app_name]["warnings"] += 1

        # Sort by errors
        sorted_services = dict(sorted(
            services.items(),
            key=lambda x: x[1]["errors"],
            reverse=True
        )[:20])

        return {
            "total_services": len(services),
            "services": sorted_services,
            "problematic": [s for s, stats in services.items() if stats["errors"] > 10],
        }

    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """Detect anomalies in syslog data."""
        anomalies = []

        # High severity message burst
        high_severity = [m for m in self.messages if m.severity <= 2]
        if len(high_severity) > 50:
            anomalies.append({
                "type": "high_severity_burst",
                "severity": "high",
                "description": f"Detected {len(high_severity)} critical/alert/emergency messages",
                "count": len(high_severity),
            })

        # Unknown hosts
        known_hosts = set()
        for msg in self.messages:
            if msg.hostname and msg.hostname != "unknown":
                known_hosts.add(msg.hostname)

        if len(known_hosts) > 100:
            anomalies.append({
                "type": "many_hosts",
                "severity": "medium",
                "description": f"Messages from {len(known_hosts)} different hosts",
                "count": len(known_hosts),
            })

        # Kernel messages with errors
        kernel_errors = [m for m in self.messages if m.facility == 0 and m.severity <= 3]
        if kernel_errors:
            anomalies.append({
                "type": "kernel_errors",
                "severity": "high",
                "description": f"Detected {len(kernel_errors)} kernel error messages",
                "count": len(kernel_errors),
                "samples": [m.message[:100] for m in kernel_errors[:5]],
            })

        return anomalies

    def to_log_entries(self) -> List[LogEntry]:
        """Convert to generic LogEntry format."""
        severity_map = {
            0: "CRITICAL", 1: "CRITICAL", 2: "CRITICAL", 3: "ERROR",
            4: "WARNING", 5: "INFO", 6: "INFO", 7: "DEBUG"
        }

        return [
            LogEntry(
                timestamp=msg.timestamp,
                source=f"syslog:{msg.hostname}:{msg.app_name}",
                level=severity_map.get(msg.severity, "INFO"),
                message=msg.message,
                raw=msg.raw,
                parsed={
                    "facility": self.FACILITIES.get(msg.facility, str(msg.facility)),
                    "severity": self.SEVERITIES.get(msg.severity, str(msg.severity)),
                    "structured_data": msg.structured_data,
                },
                tags=[f"facility:{msg.facility}", f"host:{msg.hostname}"]
            )
            for msg in self.messages
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Get parsing statistics."""
        return {
            **self.stats,
            "total_messages": len(self.messages),
        }
