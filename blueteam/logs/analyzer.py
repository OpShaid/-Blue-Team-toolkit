"""
Log Analyzer - Security-focused log analysis and anomaly detection.
"""

import re
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from blueteam.core.logger import get_logger
from blueteam.logs.parser import LogEntry

logger = get_logger(__name__)


@dataclass
class SecurityFinding:
    """Represents a security finding from log analysis."""
    timestamp: datetime
    category: str
    severity: str
    title: str
    description: str
    source_entries: List[LogEntry] = field(default_factory=list)
    indicators: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


class LogAnalyzer:
    """
    Security-focused log analyzer with threat detection.

    Features:
    - Authentication failure analysis
    - Privilege escalation detection
    - Anomaly detection
    - Attack pattern recognition
    - User behavior analysis
    - Timeline reconstruction
    """

    # Suspicious patterns
    ATTACK_PATTERNS = {
        "sql_injection": [
            r"(?:union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from)",
            r"(?:--\s*$|'\s*or\s*'1'\s*=\s*'1|'\s*--)",
            r"(?:exec\s*\(|execute\s*\(|xp_cmdshell)",
        ],
        "xss": [
            r"<script[^>]*>",
            r"javascript\s*:",
            r"on\w+\s*=\s*['\"]",
        ],
        "path_traversal": [
            r"\.\./\.\./",
            r"\.\.\\\.\.\\",
            r"%2e%2e[/\\]",
            r"etc/passwd",
            r"windows/system32",
        ],
        "command_injection": [
            r"[;&|`].*(?:cat|ls|pwd|id|whoami|uname)",
            r"\$\(.*\)",
            r"`.*`",
        ],
        "credential_stuffing": [
            r"failed.*password.*for.*(\S+).*from",
            r"invalid.*user.*(\S+).*from",
            r"authentication.*failure.*user=(\S+)",
        ],
        "privilege_escalation": [
            r"su\s*:\s*.*FAILED",
            r"sudo.*COMMAND",
            r"wheel.*group",
            r"root.*login",
        ],
    }

    # Critical events
    CRITICAL_PATTERNS = {
        "root_login": r"(?:root|administrator)\s+(?:logged\s+in|accepted)",
        "service_stopped": r"(?:stopped|shutdown|terminated).*(?:sshd|apache|nginx|mysql)",
        "config_change": r"(?:configuration|config)\s+(?:changed|modified|updated)",
        "user_created": r"(?:new\s+user|useradd|adduser|created\s+account)",
        "firewall_change": r"(?:firewall|iptables|ufw)\s+(?:modified|added|deleted)",
    }

    def __init__(self):
        self.entries: List[LogEntry] = []
        self.findings: List[SecurityFinding] = []
        self.stats = {
            "total_analyzed": 0,
            "errors": 0,
            "warnings": 0,
            "auth_failures": 0,
            "by_source": Counter(),
            "by_hour": Counter(),
        }

        # Compile patterns
        self._attack_patterns = {
            name: [re.compile(p, re.IGNORECASE) for p in patterns]
            for name, patterns in self.ATTACK_PATTERNS.items()
        }
        self._critical_patterns = {
            name: re.compile(p, re.IGNORECASE)
            for name, p in self.CRITICAL_PATTERNS.items()
        }

    def analyze(self, entries: List[LogEntry]) -> List[SecurityFinding]:
        """Analyze log entries for security issues."""
        self.entries = entries
        self.findings = []

        for entry in entries:
            self.stats["total_analyzed"] += 1

            if entry.level == "ERROR":
                self.stats["errors"] += 1
            elif entry.level == "WARNING":
                self.stats["warnings"] += 1

            self.stats["by_source"][entry.source] += 1

            if entry.timestamp:
                self.stats["by_hour"][entry.timestamp.hour] += 1

            # Run detections
            self._detect_attack_patterns(entry)
            self._detect_critical_events(entry)
            self._detect_auth_failures(entry)

        # Run aggregate analysis
        self._analyze_brute_force()
        self._analyze_anomalies()
        self._analyze_user_behavior()

        return self.findings

    def _detect_attack_patterns(self, entry: LogEntry):
        """Detect attack patterns in log entry."""
        for attack_type, patterns in self._attack_patterns.items():
            for pattern in patterns:
                if pattern.search(entry.message) or pattern.search(entry.raw):
                    self.findings.append(SecurityFinding(
                        timestamp=entry.timestamp or datetime.now(),
                        category="attack_pattern",
                        severity="high",
                        title=f"{attack_type.replace('_', ' ').title()} Detected",
                        description=f"Potential {attack_type} attack detected in logs",
                        source_entries=[entry],
                        indicators={"attack_type": attack_type, "pattern": pattern.pattern},
                        recommendations=[
                            f"Review the source of this request",
                            f"Check for successful exploitation",
                            f"Consider blocking the source IP if applicable",
                        ]
                    ))
                    break

    def _detect_critical_events(self, entry: LogEntry):
        """Detect critical security events."""
        for event_type, pattern in self._critical_patterns.items():
            if pattern.search(entry.message) or pattern.search(entry.raw):
                severity = "critical" if event_type in ("root_login", "firewall_change") else "high"
                self.findings.append(SecurityFinding(
                    timestamp=entry.timestamp or datetime.now(),
                    category="critical_event",
                    severity=severity,
                    title=f"Critical Event: {event_type.replace('_', ' ').title()}",
                    description=f"Critical security event detected: {entry.message[:200]}",
                    source_entries=[entry],
                    indicators={"event_type": event_type},
                ))

    def _detect_auth_failures(self, entry: LogEntry):
        """Track authentication failures."""
        auth_patterns = [
            r"authentication\s+fail",
            r"failed\s+password",
            r"invalid\s+user",
            r"access\s+denied",
            r"login\s+fail",
            r"permission\s+denied",
        ]

        for pattern in auth_patterns:
            if re.search(pattern, entry.message, re.IGNORECASE):
                self.stats["auth_failures"] += 1
                break

    def _analyze_brute_force(self):
        """Detect brute force attacks."""
        # Group auth failures by source IP
        ip_failures: Dict[str, List[LogEntry]] = defaultdict(list)
        ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

        for entry in self.entries:
            if any(p in entry.message.lower() for p in ["fail", "invalid", "denied"]):
                match = ip_pattern.search(entry.message)
                if match:
                    ip = match.group(1)
                    ip_failures[ip].append(entry)

        # Detect high failure rates
        for ip, failures in ip_failures.items():
            if len(failures) >= 5:
                # Check time window
                if failures[0].timestamp and failures[-1].timestamp:
                    duration = (failures[-1].timestamp - failures[0].timestamp).total_seconds()
                    if duration > 0 and len(failures) / duration > 0.1:  # More than 1 per 10 seconds
                        self.findings.append(SecurityFinding(
                            timestamp=failures[-1].timestamp,
                            category="brute_force",
                            severity="high",
                            title=f"Brute Force Attack from {ip}",
                            description=f"Detected {len(failures)} failed attempts from {ip}",
                            source_entries=failures[:10],
                            indicators={
                                "source_ip": ip,
                                "failure_count": len(failures),
                                "duration_seconds": duration,
                            },
                            recommendations=[
                                f"Consider blocking IP {ip}",
                                "Review affected accounts for compromise",
                                "Enable account lockout policies",
                            ]
                        ))

    def _analyze_anomalies(self):
        """Detect anomalous patterns."""
        # Unusual hour activity
        if self.stats["by_hour"]:
            avg_hourly = sum(self.stats["by_hour"].values()) / 24
            for hour, count in self.stats["by_hour"].items():
                if count > avg_hourly * 5 and hour in range(0, 6):  # 5x average during night
                    self.findings.append(SecurityFinding(
                        timestamp=datetime.now(),
                        category="anomaly",
                        severity="medium",
                        title=f"Unusual Night Activity at {hour}:00",
                        description=f"Detected {count} events at {hour}:00 (avg: {avg_hourly:.1f})",
                        indicators={"hour": hour, "count": count, "average": avg_hourly},
                    ))

        # Error spike detection
        total = self.stats["total_analyzed"]
        if total > 100:
            error_rate = self.stats["errors"] / total
            if error_rate > 0.3:
                self.findings.append(SecurityFinding(
                    timestamp=datetime.now(),
                    category="anomaly",
                    severity="high",
                    title="High Error Rate Detected",
                    description=f"Error rate of {error_rate:.1%} detected ({self.stats['errors']} errors)",
                    indicators={"error_count": self.stats["errors"], "error_rate": error_rate},
                ))

    def _analyze_user_behavior(self):
        """Analyze user behavior patterns."""
        user_activity: Dict[str, List[LogEntry]] = defaultdict(list)
        user_pattern = re.compile(r'user[=:\s]+(\S+)', re.IGNORECASE)

        for entry in self.entries:
            match = user_pattern.search(entry.message)
            if match:
                user = match.group(1)
                user_activity[user].append(entry)

        # Detect users with high activity
        for user, activities in user_activity.items():
            # Check for privilege escalation attempts
            priv_patterns = ["sudo", "su ", "admin", "root", "wheel"]
            priv_attempts = [e for e in activities if any(p in e.message.lower() for p in priv_patterns)]

            if len(priv_attempts) >= 3:
                self.findings.append(SecurityFinding(
                    timestamp=priv_attempts[-1].timestamp or datetime.now(),
                    category="user_behavior",
                    severity="medium",
                    title=f"Privilege Escalation Attempts by {user}",
                    description=f"User {user} attempted privilege escalation {len(priv_attempts)} times",
                    source_entries=priv_attempts[:5],
                    indicators={"user": user, "attempts": len(priv_attempts)},
                ))

    def get_timeline(
        self,
        start_time: datetime = None,
        end_time: datetime = None,
        severity: str = None
    ) -> List[Dict[str, Any]]:
        """Get security events timeline."""
        events = []

        for finding in self.findings:
            if start_time and finding.timestamp < start_time:
                continue
            if end_time and finding.timestamp > end_time:
                continue
            if severity and finding.severity != severity:
                continue

            events.append({
                "timestamp": finding.timestamp.isoformat(),
                "category": finding.category,
                "severity": finding.severity,
                "title": finding.title,
                "description": finding.description[:200],
            })

        return sorted(events, key=lambda x: x["timestamp"])

    def get_summary(self) -> Dict[str, Any]:
        """Get analysis summary."""
        severity_counts = Counter(f.severity for f in self.findings)
        category_counts = Counter(f.category for f in self.findings)

        return {
            "total_entries_analyzed": self.stats["total_analyzed"],
            "total_findings": len(self.findings),
            "by_severity": dict(severity_counts),
            "by_category": dict(category_counts),
            "auth_failures": self.stats["auth_failures"],
            "error_count": self.stats["errors"],
            "warning_count": self.stats["warnings"],
            "top_sources": self.stats["by_source"].most_common(10),
        }

    def export_findings(self, output_file: str):
        """Export findings to JSON."""
        from blueteam.core.utils import export_to_json

        data = [
            {
                "timestamp": f.timestamp.isoformat(),
                "category": f.category,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "indicators": f.indicators,
                "recommendations": f.recommendations,
            }
            for f in self.findings
        ]

        export_to_json(data, output_file)
        logger.info(f"Exported {len(data)} findings to {output_file}")
