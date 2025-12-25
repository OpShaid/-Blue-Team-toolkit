"""
Event Correlator - Correlate events across multiple sources.
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from blueteam.core.logger import get_logger
from blueteam.logs.parser import LogEntry

logger = get_logger(__name__)


class CorrelationType(Enum):
    SEQUENCE = "sequence"  # Events in order
    THRESHOLD = "threshold"  # Count threshold
    TIME_WINDOW = "time_window"  # Events within time
    AGGREGATION = "aggregation"  # Group by field


@dataclass
class CorrelationRule:
    """Defines a correlation rule."""
    id: str
    name: str
    description: str
    rule_type: CorrelationType
    conditions: List[Dict[str, Any]]
    time_window: int = 300  # seconds
    threshold: int = 1
    group_by: Optional[str] = None
    severity: str = "medium"
    enabled: bool = True


@dataclass
class CorrelatedEvent:
    """Represents a correlated event from multiple sources."""
    rule_id: str
    rule_name: str
    timestamp: datetime
    severity: str
    description: str
    source_events: List[LogEntry] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)


class EventCorrelator:
    """
    Correlate security events across multiple log sources.

    Features:
    - Rule-based correlation
    - Sequence detection
    - Threshold-based alerting
    - Time-window analysis
    - Attack chain detection
    """

    def __init__(self):
        self.rules: Dict[str, CorrelationRule] = {}
        self.events: List[CorrelatedEvent] = []
        self._event_buffer: List[LogEntry] = []
        self._buffer_size = 10000

        # Load default rules
        self._load_default_rules()

    def _load_default_rules(self):
        """Load built-in correlation rules."""
        default_rules = [
            # Lateral movement detection
            CorrelationRule(
                id="CORR-001",
                name="Lateral Movement Detected",
                description="Multiple hosts accessed from same source within short period",
                rule_type=CorrelationType.THRESHOLD,
                conditions=[
                    {"field": "message", "pattern": r"(?:login|logon|authenticated|connected)"}
                ],
                time_window=300,
                threshold=5,
                group_by="source_ip",
                severity="high"
            ),

            # Attack chain: recon -> exploitation -> post-exploitation
            CorrelationRule(
                id="CORR-002",
                name="Attack Chain Detected",
                description="Reconnaissance followed by exploitation attempt",
                rule_type=CorrelationType.SEQUENCE,
                conditions=[
                    {"field": "message", "pattern": r"(?:scan|probe|enumerate)"},
                    {"field": "message", "pattern": r"(?:exploit|inject|overflow)"},
                    {"field": "message", "pattern": r"(?:shell|reverse|connect)"},
                ],
                time_window=3600,
                severity="critical"
            ),

            # Credential theft chain
            CorrelationRule(
                id="CORR-003",
                name="Credential Theft Chain",
                description="Failed auth followed by successful auth (credential stuffing success)",
                rule_type=CorrelationType.SEQUENCE,
                conditions=[
                    {"field": "message", "pattern": r"(?:failed|invalid).*(?:password|auth)"},
                    {"field": "message", "pattern": r"(?:accepted|success).*(?:password|auth)"},
                ],
                time_window=60,
                group_by="source_ip",
                severity="critical"
            ),

            # Data exfiltration indicators
            CorrelationRule(
                id="CORR-004",
                name="Possible Data Exfiltration",
                description="Large data transfer after reconnaissance activity",
                rule_type=CorrelationType.SEQUENCE,
                conditions=[
                    {"field": "message", "pattern": r"(?:list|find|search|dir)"},
                    {"field": "message", "pattern": r"(?:upload|transfer|send|post).*(?:bytes|mb|gb)"},
                ],
                time_window=1800,
                severity="high"
            ),

            # Privilege escalation chain
            CorrelationRule(
                id="CORR-005",
                name="Privilege Escalation Chain",
                description="User gained elevated privileges after initial access",
                rule_type=CorrelationType.SEQUENCE,
                conditions=[
                    {"field": "message", "pattern": r"(?:login|logon|session started)"},
                    {"field": "message", "pattern": r"(?:sudo|su|runas|privilege)"},
                    {"field": "message", "pattern": r"(?:root|administrator|admin|SYSTEM)"},
                ],
                time_window=300,
                severity="critical"
            ),

            # Brute force with success
            CorrelationRule(
                id="CORR-006",
                name="Brute Force Success",
                description="Multiple failed attempts followed by success",
                rule_type=CorrelationType.THRESHOLD,
                conditions=[
                    {"field": "message", "pattern": r"failed.*(?:password|auth|login)"}
                ],
                time_window=300,
                threshold=10,
                group_by="source_ip",
                severity="critical"
            ),

            # Service disruption
            CorrelationRule(
                id="CORR-007",
                name="Service Disruption Pattern",
                description="Multiple services affected in short period",
                rule_type=CorrelationType.THRESHOLD,
                conditions=[
                    {"field": "message", "pattern": r"(?:stopped|crashed|terminated|down)"}
                ],
                time_window=60,
                threshold=3,
                severity="high"
            ),

            # Malware activity
            CorrelationRule(
                id="CORR-008",
                name="Malware Activity Chain",
                description="File download followed by execution",
                rule_type=CorrelationType.SEQUENCE,
                conditions=[
                    {"field": "message", "pattern": r"(?:download|wget|curl|fetch)"},
                    {"field": "message", "pattern": r"(?:chmod|execute|run|spawn)"},
                    {"field": "message", "pattern": r"(?:connect|beacon|callback)"},
                ],
                time_window=300,
                severity="critical"
            ),
        ]

        for rule in default_rules:
            self.rules[rule.id] = rule

    def add_rule(self, rule: CorrelationRule):
        """Add a correlation rule."""
        self.rules[rule.id] = rule
        logger.info(f"Added correlation rule: {rule.id} - {rule.name}")

    def remove_rule(self, rule_id: str):
        """Remove a correlation rule."""
        if rule_id in self.rules:
            del self.rules[rule_id]

    def process_event(self, entry: LogEntry) -> List[CorrelatedEvent]:
        """Process a single event and check for correlations."""
        self._event_buffer.append(entry)

        # Trim buffer
        if len(self._event_buffer) > self._buffer_size:
            self._event_buffer = self._event_buffer[-self._buffer_size:]

        correlations = []

        for rule in self.rules.values():
            if not rule.enabled:
                continue

            if rule.rule_type == CorrelationType.SEQUENCE:
                result = self._check_sequence(rule, entry)
            elif rule.rule_type == CorrelationType.THRESHOLD:
                result = self._check_threshold(rule, entry)
            else:
                continue

            if result:
                correlations.append(result)
                self.events.append(result)

        return correlations

    def correlate_batch(self, entries: List[LogEntry]) -> List[CorrelatedEvent]:
        """Correlate a batch of events."""
        all_correlations = []

        for entry in entries:
            correlations = self.process_event(entry)
            all_correlations.extend(correlations)

        return all_correlations

    def _check_sequence(self, rule: CorrelationRule, latest: LogEntry) -> Optional[CorrelatedEvent]:
        """Check for sequence pattern match."""
        if not latest.timestamp:
            return None

        window_start = latest.timestamp - timedelta(seconds=rule.time_window)

        # Get relevant events in window
        window_events = [
            e for e in self._event_buffer
            if e.timestamp and e.timestamp >= window_start
        ]

        # Check if sequence conditions are met
        matched_events = []
        conditions = rule.conditions.copy()

        for event in window_events:
            if not conditions:
                break

            condition = conditions[0]
            pattern = condition.get("pattern", "")

            if re.search(pattern, event.message, re.IGNORECASE):
                matched_events.append(event)
                conditions.pop(0)

        # All conditions matched = sequence detected
        if not conditions and len(matched_events) >= len(rule.conditions):
            # Check group_by if specified
            if rule.group_by:
                grouped = self._extract_field(matched_events, rule.group_by)
                if len(set(grouped)) > 1:
                    return None

            return CorrelatedEvent(
                rule_id=rule.id,
                rule_name=rule.name,
                timestamp=latest.timestamp,
                severity=rule.severity,
                description=f"Sequence detected: {rule.description}",
                source_events=matched_events,
                context={
                    "sequence_length": len(matched_events),
                    "time_span": (matched_events[-1].timestamp - matched_events[0].timestamp).seconds
                    if matched_events[0].timestamp else 0
                }
            )

        return None

    def _check_threshold(self, rule: CorrelationRule, latest: LogEntry) -> Optional[CorrelatedEvent]:
        """Check for threshold-based correlation."""
        if not latest.timestamp:
            return None

        window_start = latest.timestamp - timedelta(seconds=rule.time_window)

        # Get events matching conditions in window
        matching_events = []

        for event in self._event_buffer:
            if not event.timestamp or event.timestamp < window_start:
                continue

            for condition in rule.conditions:
                pattern = condition.get("pattern", "")
                if re.search(pattern, event.message, re.IGNORECASE):
                    matching_events.append(event)
                    break

        # Group if specified
        if rule.group_by:
            groups = defaultdict(list)
            for event in matching_events:
                key = self._extract_field([event], rule.group_by)
                if key:
                    groups[key[0]].append(event)

            # Check each group against threshold
            for group_key, group_events in groups.items():
                if len(group_events) >= rule.threshold:
                    return CorrelatedEvent(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        timestamp=latest.timestamp,
                        severity=rule.severity,
                        description=f"Threshold exceeded: {rule.description} ({group_key})",
                        source_events=group_events[:20],
                        context={
                            "group_key": group_key,
                            "count": len(group_events),
                            "threshold": rule.threshold,
                        }
                    )
        else:
            if len(matching_events) >= rule.threshold:
                return CorrelatedEvent(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    timestamp=latest.timestamp,
                    severity=rule.severity,
                    description=f"Threshold exceeded: {rule.description}",
                    source_events=matching_events[:20],
                    context={
                        "count": len(matching_events),
                        "threshold": rule.threshold,
                    }
                )

        return None

    def _extract_field(self, events: List[LogEntry], field_name: str) -> List[str]:
        """Extract field values from events."""
        values = []

        patterns = {
            "source_ip": r"(?:from|src|source)[:\s=]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            "dest_ip": r"(?:to|dst|dest)[:\s=]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            "user": r"(?:user|username|account)[:\s=]*(\S+)",
            "host": r"(?:host|hostname|server)[:\s=]*(\S+)",
        }

        pattern = patterns.get(field_name)
        if pattern:
            for event in events:
                match = re.search(pattern, event.message, re.IGNORECASE)
                if match:
                    values.append(match.group(1))

        return values

    def get_statistics(self) -> Dict[str, Any]:
        """Get correlation statistics."""
        severity_counts = defaultdict(int)
        rule_counts = defaultdict(int)

        for event in self.events:
            severity_counts[event.severity] += 1
            rule_counts[event.rule_id] += 1

        return {
            "total_correlations": len(self.events),
            "by_severity": dict(severity_counts),
            "by_rule": dict(sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)),
            "rules_enabled": sum(1 for r in self.rules.values() if r.enabled),
            "buffer_size": len(self._event_buffer),
        }

    def get_recent_correlations(self, count: int = 10) -> List[CorrelatedEvent]:
        """Get most recent correlations."""
        return sorted(self.events, key=lambda x: x.timestamp, reverse=True)[:count]

    def export_correlations(self, output_file: str):
        """Export correlations to JSON."""
        from blueteam.core.utils import export_to_json

        data = [
            {
                "rule_id": e.rule_id,
                "rule_name": e.rule_name,
                "timestamp": e.timestamp.isoformat(),
                "severity": e.severity,
                "description": e.description,
                "context": e.context,
                "source_event_count": len(e.source_events),
            }
            for e in self.events
        ]

        export_to_json(data, output_file)
        logger.info(f"Exported {len(data)} correlations to {output_file}")
