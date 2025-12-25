"""
Timeline Builder - Reconstruct incident timelines from multiple sources.
"""

import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict
from pathlib import Path

from blueteam.core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class TimelineEvent:
    """A single event in the timeline."""
    timestamp: datetime
    source: str
    event_type: str
    description: str
    severity: str = "info"  # info, warning, alert, critical
    actor: Optional[str] = None
    target: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None
    related_events: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    id: str = ""


@dataclass
class TimelinePhase:
    """A phase of the attack/incident."""
    name: str
    start_time: datetime
    end_time: Optional[datetime]
    description: str
    mitre_tactics: List[str] = field(default_factory=list)
    events: List[TimelineEvent] = field(default_factory=list)


class TimelineBuilder:
    """
    Build comprehensive incident timelines.

    Features:
    - Multi-source event aggregation
    - Automatic event correlation
    - MITRE ATT&CK mapping
    - Timeline visualization export
    - Attack phase identification
    """

    # MITRE ATT&CK tactics
    MITRE_TACTICS = {
        "reconnaissance": ["scan", "probe", "enumerate", "discover"],
        "initial_access": ["phish", "exploit", "drive-by", "supply chain"],
        "execution": ["powershell", "script", "command", "cmd.exe", "wscript"],
        "persistence": ["scheduled task", "registry", "service", "startup"],
        "privilege_escalation": ["sudo", "admin", "system", "root", "elevation"],
        "defense_evasion": ["disable", "clear log", "masquerade", "obfuscate"],
        "credential_access": ["dump", "credential", "password", "hash", "keylog"],
        "discovery": ["whoami", "ipconfig", "net user", "systeminfo"],
        "lateral_movement": ["psexec", "wmi", "rdp", "ssh", "remote"],
        "collection": ["archive", "compress", "stage", "clipboard"],
        "exfiltration": ["upload", "transfer", "send", "exfil"],
        "impact": ["encrypt", "destroy", "ransom", "wipe"],
    }

    def __init__(self):
        self.events: List[TimelineEvent] = []
        self.phases: List[TimelinePhase] = []
        self._event_counter = 0

    def add_event(
        self,
        timestamp: datetime,
        source: str,
        event_type: str,
        description: str,
        severity: str = "info",
        actor: str = None,
        target: str = None,
        raw_data: Dict[str, Any] = None,
        tags: List[str] = None
    ) -> TimelineEvent:
        """Add an event to the timeline."""
        self._event_counter += 1

        event = TimelineEvent(
            id=f"evt-{self._event_counter:06d}",
            timestamp=timestamp,
            source=source,
            event_type=event_type,
            description=description,
            severity=severity,
            actor=actor,
            target=target,
            raw_data=raw_data or {},
            tags=tags or [],
        )

        # Auto-tag with MITRE tactics
        event.tags.extend(self._identify_mitre_tactics(description))

        self.events.append(event)
        return event

    def add_events_from_logs(self, log_entries: List[Dict[str, Any]], source: str = "logs"):
        """Add events from parsed log entries."""
        for entry in log_entries:
            timestamp = entry.get("timestamp")
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp)
                except ValueError:
                    timestamp = datetime.now()

            self.add_event(
                timestamp=timestamp or datetime.now(),
                source=source,
                event_type=entry.get("event_type", "log"),
                description=entry.get("message", str(entry)),
                severity=self._map_severity(entry.get("level", "info")),
                actor=entry.get("user") or entry.get("source_ip"),
                target=entry.get("target") or entry.get("dest_ip"),
                raw_data=entry,
            )

    def add_events_from_alerts(self, alerts: List[Dict[str, Any]], source: str = "alerts"):
        """Add events from security alerts."""
        for alert in alerts:
            self.add_event(
                timestamp=datetime.fromisoformat(alert.get("timestamp", datetime.now().isoformat())),
                source=source,
                event_type=alert.get("type", "alert"),
                description=alert.get("title", alert.get("description", "")),
                severity=alert.get("severity", "warning"),
                actor=alert.get("source_ip"),
                target=alert.get("dest_ip"),
                raw_data=alert,
                tags=alert.get("tags", []),
            )

    def _map_severity(self, level: str) -> str:
        """Map log level to timeline severity."""
        level = level.lower()
        if level in ("critical", "emergency", "fatal"):
            return "critical"
        elif level in ("error", "err", "high"):
            return "alert"
        elif level in ("warning", "warn", "medium"):
            return "warning"
        return "info"

    def _identify_mitre_tactics(self, text: str) -> List[str]:
        """Identify MITRE ATT&CK tactics from text."""
        text_lower = text.lower()
        tactics = []

        for tactic, keywords in self.MITRE_TACTICS.items():
            if any(keyword in text_lower for keyword in keywords):
                tactics.append(f"mitre:{tactic}")

        return tactics

    def correlate_events(self, time_window: int = 300) -> None:
        """Correlate related events based on time and actors."""
        # Sort events by timestamp
        self.events.sort(key=lambda x: x.timestamp)

        # Correlate events within time window
        for i, event in enumerate(self.events):
            for j in range(i + 1, len(self.events)):
                other = self.events[j]

                # Stop if outside time window
                time_diff = (other.timestamp - event.timestamp).total_seconds()
                if time_diff > time_window:
                    break

                # Correlate by actor
                if event.actor and event.actor == other.actor:
                    if other.id not in event.related_events:
                        event.related_events.append(other.id)
                    if event.id not in other.related_events:
                        other.related_events.append(event.id)

                # Correlate by target
                if event.target and event.target == other.target:
                    if other.id not in event.related_events:
                        event.related_events.append(other.id)

    def identify_phases(self) -> List[TimelinePhase]:
        """Identify attack phases from events."""
        self.phases = []

        # Group events by MITRE tactics
        tactic_events: Dict[str, List[TimelineEvent]] = defaultdict(list)

        for event in self.events:
            for tag in event.tags:
                if tag.startswith("mitre:"):
                    tactic = tag.replace("mitre:", "")
                    tactic_events[tactic].append(event)

        # Create phases for each tactic with events
        tactic_order = [
            "reconnaissance", "initial_access", "execution", "persistence",
            "privilege_escalation", "defense_evasion", "credential_access",
            "discovery", "lateral_movement", "collection", "exfiltration", "impact"
        ]

        for tactic in tactic_order:
            if tactic in tactic_events:
                events = sorted(tactic_events[tactic], key=lambda x: x.timestamp)
                phase = TimelinePhase(
                    name=tactic.replace("_", " ").title(),
                    start_time=events[0].timestamp,
                    end_time=events[-1].timestamp if len(events) > 1 else None,
                    description=f"Attack phase: {tactic}",
                    mitre_tactics=[tactic],
                    events=events,
                )
                self.phases.append(phase)

        return self.phases

    def get_timeline(
        self,
        start_time: datetime = None,
        end_time: datetime = None,
        severity: str = None,
        actor: str = None,
        source: str = None
    ) -> List[TimelineEvent]:
        """Get filtered and sorted timeline."""
        events = self.events.copy()

        if start_time:
            events = [e for e in events if e.timestamp >= start_time]
        if end_time:
            events = [e for e in events if e.timestamp <= end_time]
        if severity:
            events = [e for e in events if e.severity == severity]
        if actor:
            events = [e for e in events if e.actor == actor]
        if source:
            events = [e for e in events if e.source == source]

        return sorted(events, key=lambda x: x.timestamp)

    def get_actor_timeline(self, actor: str) -> List[TimelineEvent]:
        """Get timeline for a specific actor."""
        return self.get_timeline(actor=actor)

    def get_statistics(self) -> Dict[str, Any]:
        """Get timeline statistics."""
        if not self.events:
            return {"total_events": 0}

        events_by_severity = defaultdict(int)
        events_by_source = defaultdict(int)
        events_by_type = defaultdict(int)
        actors = set()
        targets = set()

        for event in self.events:
            events_by_severity[event.severity] += 1
            events_by_source[event.source] += 1
            events_by_type[event.event_type] += 1
            if event.actor:
                actors.add(event.actor)
            if event.target:
                targets.add(event.target)

        return {
            "total_events": len(self.events),
            "time_range": {
                "start": min(e.timestamp for e in self.events).isoformat(),
                "end": max(e.timestamp for e in self.events).isoformat(),
            },
            "by_severity": dict(events_by_severity),
            "by_source": dict(events_by_source),
            "by_type": dict(sorted(events_by_type.items(), key=lambda x: x[1], reverse=True)[:10]),
            "unique_actors": len(actors),
            "unique_targets": len(targets),
            "phases_identified": len(self.phases),
        }

    def export_timeline(self, output_file: str, format: str = "json"):
        """Export timeline to file."""
        if format == "json":
            self._export_json(output_file)
        elif format == "csv":
            self._export_csv(output_file)
        elif format == "markdown":
            self._export_markdown(output_file)
        elif format == "html":
            self._export_html(output_file)

    def _export_json(self, output_file: str):
        """Export as JSON."""
        data = {
            "generated_at": datetime.now().isoformat(),
            "statistics": self.get_statistics(),
            "phases": [
                {
                    "name": p.name,
                    "start": p.start_time.isoformat(),
                    "end": p.end_time.isoformat() if p.end_time else None,
                    "tactics": p.mitre_tactics,
                    "event_count": len(p.events),
                }
                for p in self.phases
            ],
            "events": [
                {
                    "id": e.id,
                    "timestamp": e.timestamp.isoformat(),
                    "source": e.source,
                    "type": e.event_type,
                    "severity": e.severity,
                    "description": e.description,
                    "actor": e.actor,
                    "target": e.target,
                    "tags": e.tags,
                    "related": e.related_events,
                }
                for e in sorted(self.events, key=lambda x: x.timestamp)
            ],
        }

        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Exported timeline to {output_file}")

    def _export_csv(self, output_file: str):
        """Export as CSV."""
        import csv

        with open(output_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Timestamp", "Source", "Type", "Severity",
                "Description", "Actor", "Target", "Tags"
            ])

            for event in sorted(self.events, key=lambda x: x.timestamp):
                writer.writerow([
                    event.timestamp.isoformat(),
                    event.source,
                    event.event_type,
                    event.severity,
                    event.description,
                    event.actor or "",
                    event.target or "",
                    ", ".join(event.tags),
                ])

    def _export_markdown(self, output_file: str) -> str:
        """Export as Markdown."""
        md = "# Incident Timeline\n\n"
        md += f"Generated: {datetime.now().isoformat()}\n\n"

        # Statistics
        stats = self.get_statistics()
        md += "## Summary\n\n"
        md += f"- Total Events: {stats['total_events']}\n"
        if stats.get('time_range'):
            md += f"- Time Range: {stats['time_range']['start']} to {stats['time_range']['end']}\n"
        md += f"- Unique Actors: {stats.get('unique_actors', 0)}\n"
        md += f"- Unique Targets: {stats.get('unique_targets', 0)}\n\n"

        # Phases
        if self.phases:
            md += "## Attack Phases\n\n"
            for phase in self.phases:
                md += f"### {phase.name}\n"
                md += f"- Start: {phase.start_time.isoformat()}\n"
                md += f"- Events: {len(phase.events)}\n"
                md += f"- MITRE Tactics: {', '.join(phase.mitre_tactics)}\n\n"

        # Events
        md += "## Events\n\n"
        md += "| Time | Source | Type | Severity | Description |\n"
        md += "|------|--------|------|----------|-------------|\n"

        for event in sorted(self.events, key=lambda x: x.timestamp):
            time_str = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            desc = event.description[:50] + "..." if len(event.description) > 50 else event.description
            md += f"| {time_str} | {event.source} | {event.event_type} | {event.severity} | {desc} |\n"

        with open(output_file, "w") as f:
            f.write(md)

        return md

    def _export_html(self, output_file: str):
        """Export as interactive HTML."""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Incident Timeline</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .timeline { position: relative; max-width: 1200px; margin: 0 auto; }
        .event { padding: 10px 20px; background: white; border-radius: 5px;
                 margin: 10px 0; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .event-critical { border-left: 4px solid #ff4444; }
        .event-alert { border-left: 4px solid #ff8800; }
        .event-warning { border-left: 4px solid #ffcc00; }
        .event-info { border-left: 4px solid #4488ff; }
        .timestamp { font-size: 0.9em; color: #666; }
        .description { margin: 5px 0; }
        .meta { font-size: 0.85em; color: #888; }
        .tag { display: inline-block; padding: 2px 8px; margin: 2px;
               background: #e0e0e0; border-radius: 3px; font-size: 0.8em; }
        .mitre { background: #ffebee; color: #c62828; }
        h1 { color: #333; }
        .stats { display: flex; gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 15px; border-radius: 5px;
                     box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .stat-value { font-size: 2em; font-weight: bold; color: #1976d2; }
    </style>
</head>
<body>
    <h1>Incident Timeline</h1>
"""
        stats = self.get_statistics()

        html += f"""
    <div class="stats">
        <div class="stat-card">
            <div class="stat-value">{stats['total_events']}</div>
            <div>Total Events</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{stats.get('unique_actors', 0)}</div>
            <div>Unique Actors</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{len(self.phases)}</div>
            <div>Attack Phases</div>
        </div>
    </div>

    <div class="timeline">
"""
        for event in sorted(self.events, key=lambda x: x.timestamp, reverse=True):
            tags_html = ""
            for tag in event.tags:
                css_class = "tag mitre" if tag.startswith("mitre:") else "tag"
                tags_html += f'<span class="{css_class}">{tag}</span>'

            html += f"""
        <div class="event event-{event.severity}">
            <div class="timestamp">{event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</div>
            <div class="description"><strong>{event.event_type}:</strong> {event.description}</div>
            <div class="meta">
                Source: {event.source}
                {f' | Actor: {event.actor}' if event.actor else ''}
                {f' | Target: {event.target}' if event.target else ''}
            </div>
            <div>{tags_html}</div>
        </div>
"""

        html += """
    </div>
</body>
</html>
"""
        with open(output_file, "w") as f:
            f.write(html)

        logger.info(f"Exported HTML timeline to {output_file}")
