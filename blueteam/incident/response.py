"""
Incident Responder - Core incident response coordination.
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from blueteam.core.logger import get_logger
from blueteam.core.database import Database

logger = get_logger(__name__)


class IncidentStatus(Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"


class IncidentSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentCategory(Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    INTRUSION = "intrusion"
    DATA_BREACH = "data_breach"
    DOS = "denial_of_service"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    INSIDER_THREAT = "insider_threat"
    RANSOMWARE = "ransomware"
    APT = "advanced_persistent_threat"
    OTHER = "other"


@dataclass
class IncidentNote:
    """Note attached to an incident."""
    id: str
    timestamp: datetime
    author: str
    content: str
    attachments: List[str] = field(default_factory=list)


@dataclass
class IncidentAction:
    """Action taken during incident response."""
    id: str
    timestamp: datetime
    action_type: str
    description: str
    performer: str
    status: str  # pending, completed, failed
    result: Optional[str] = None


@dataclass
class Incident:
    """Represents a security incident."""
    id: str
    title: str
    description: str
    category: IncidentCategory
    severity: IncidentSeverity
    status: IncidentStatus
    created_at: datetime
    updated_at: datetime
    created_by: str
    assigned_to: Optional[str] = None
    iocs: List[str] = field(default_factory=list)
    affected_assets: List[str] = field(default_factory=list)
    notes: List[IncidentNote] = field(default_factory=list)
    actions: List[IncidentAction] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    related_incidents: List[str] = field(default_factory=list)
    closed_at: Optional[datetime] = None
    resolution: Optional[str] = None


class IncidentResponder:
    """
    Coordinate incident response activities.

    Features:
    - Incident creation and tracking
    - Response action management
    - Evidence collection
    - Timeline reconstruction
    - Reporting
    """

    def __init__(self, db: Database = None, data_dir: str = "data/incidents"):
        self.db = db or Database()
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.incidents: Dict[str, Incident] = {}
        self.callbacks: Dict[str, List[Callable]] = {
            "on_create": [],
            "on_update": [],
            "on_escalate": [],
            "on_close": [],
        }

        # Load existing incidents
        self._load_incidents()

    def _load_incidents(self):
        """Load incidents from disk."""
        for file in self.data_dir.glob("*.json"):
            try:
                with open(file) as f:
                    data = json.load(f)
                    incident = self._dict_to_incident(data)
                    self.incidents[incident.id] = incident
            except Exception as e:
                logger.error(f"Failed to load incident {file}: {e}")

    def _save_incident(self, incident: Incident):
        """Save incident to disk."""
        file_path = self.data_dir / f"{incident.id}.json"
        with open(file_path, "w") as f:
            json.dump(self._incident_to_dict(incident), f, indent=2, default=str)

    def _incident_to_dict(self, incident: Incident) -> Dict[str, Any]:
        """Convert incident to dictionary."""
        return {
            "id": incident.id,
            "title": incident.title,
            "description": incident.description,
            "category": incident.category.value,
            "severity": incident.severity.value,
            "status": incident.status.value,
            "created_at": incident.created_at.isoformat(),
            "updated_at": incident.updated_at.isoformat(),
            "created_by": incident.created_by,
            "assigned_to": incident.assigned_to,
            "iocs": incident.iocs,
            "affected_assets": incident.affected_assets,
            "notes": [
                {
                    "id": n.id,
                    "timestamp": n.timestamp.isoformat(),
                    "author": n.author,
                    "content": n.content,
                    "attachments": n.attachments,
                }
                for n in incident.notes
            ],
            "actions": [
                {
                    "id": a.id,
                    "timestamp": a.timestamp.isoformat(),
                    "action_type": a.action_type,
                    "description": a.description,
                    "performer": a.performer,
                    "status": a.status,
                    "result": a.result,
                }
                for a in incident.actions
            ],
            "timeline": incident.timeline,
            "tags": incident.tags,
            "related_incidents": incident.related_incidents,
            "closed_at": incident.closed_at.isoformat() if incident.closed_at else None,
            "resolution": incident.resolution,
        }

    def _dict_to_incident(self, data: Dict[str, Any]) -> Incident:
        """Convert dictionary to incident."""
        return Incident(
            id=data["id"],
            title=data["title"],
            description=data["description"],
            category=IncidentCategory(data["category"]),
            severity=IncidentSeverity(data["severity"]),
            status=IncidentStatus(data["status"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            created_by=data["created_by"],
            assigned_to=data.get("assigned_to"),
            iocs=data.get("iocs", []),
            affected_assets=data.get("affected_assets", []),
            notes=[
                IncidentNote(
                    id=n["id"],
                    timestamp=datetime.fromisoformat(n["timestamp"]),
                    author=n["author"],
                    content=n["content"],
                    attachments=n.get("attachments", []),
                )
                for n in data.get("notes", [])
            ],
            actions=[
                IncidentAction(
                    id=a["id"],
                    timestamp=datetime.fromisoformat(a["timestamp"]),
                    action_type=a["action_type"],
                    description=a["description"],
                    performer=a["performer"],
                    status=a["status"],
                    result=a.get("result"),
                )
                for a in data.get("actions", [])
            ],
            timeline=data.get("timeline", []),
            tags=data.get("tags", []),
            related_incidents=data.get("related_incidents", []),
            closed_at=datetime.fromisoformat(data["closed_at"]) if data.get("closed_at") else None,
            resolution=data.get("resolution"),
        )

    def create_incident(
        self,
        title: str,
        description: str,
        category: IncidentCategory,
        severity: IncidentSeverity,
        created_by: str = "system",
        iocs: List[str] = None,
        affected_assets: List[str] = None,
        tags: List[str] = None,
    ) -> Incident:
        """Create a new incident."""
        incident = Incident(
            id=f"INC-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}",
            title=title,
            description=description,
            category=category,
            severity=severity,
            status=IncidentStatus.NEW,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            created_by=created_by,
            iocs=iocs or [],
            affected_assets=affected_assets or [],
            tags=tags or [],
        )

        # Add creation to timeline
        incident.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "event": "incident_created",
            "description": f"Incident created by {created_by}",
        })

        self.incidents[incident.id] = incident
        self._save_incident(incident)

        # Notify callbacks
        for callback in self.callbacks["on_create"]:
            try:
                callback(incident)
            except Exception as e:
                logger.error(f"Callback error: {e}")

        logger.info(f"Created incident: {incident.id} - {title}")
        return incident

    def update_status(
        self,
        incident_id: str,
        status: IncidentStatus,
        updated_by: str = "system",
        notes: str = None
    ) -> Optional[Incident]:
        """Update incident status."""
        incident = self.incidents.get(incident_id)
        if not incident:
            logger.warning(f"Incident not found: {incident_id}")
            return None

        old_status = incident.status
        incident.status = status
        incident.updated_at = datetime.now()

        # Add to timeline
        incident.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "event": "status_change",
            "old_status": old_status.value,
            "new_status": status.value,
            "updated_by": updated_by,
            "notes": notes,
        })

        if notes:
            self.add_note(incident_id, notes, updated_by)

        self._save_incident(incident)

        # Notify callbacks
        for callback in self.callbacks["on_update"]:
            try:
                callback(incident)
            except Exception as e:
                logger.error(f"Callback error: {e}")

        logger.info(f"Updated incident {incident_id} status to {status.value}")
        return incident

    def escalate(
        self,
        incident_id: str,
        new_severity: IncidentSeverity,
        reason: str,
        escalated_by: str = "system"
    ) -> Optional[Incident]:
        """Escalate incident severity."""
        incident = self.incidents.get(incident_id)
        if not incident:
            return None

        old_severity = incident.severity
        incident.severity = new_severity
        incident.updated_at = datetime.now()

        incident.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "event": "escalation",
            "old_severity": old_severity.value,
            "new_severity": new_severity.value,
            "reason": reason,
            "escalated_by": escalated_by,
        })

        self._save_incident(incident)

        # Notify callbacks
        for callback in self.callbacks["on_escalate"]:
            try:
                callback(incident)
            except Exception as e:
                logger.error(f"Callback error: {e}")

        logger.warning(f"Escalated incident {incident_id} to {new_severity.value}: {reason}")
        return incident

    def assign(
        self,
        incident_id: str,
        assignee: str,
        assigned_by: str = "system"
    ) -> Optional[Incident]:
        """Assign incident to a responder."""
        incident = self.incidents.get(incident_id)
        if not incident:
            return None

        old_assignee = incident.assigned_to
        incident.assigned_to = assignee
        incident.updated_at = datetime.now()

        incident.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "event": "assignment",
            "old_assignee": old_assignee,
            "new_assignee": assignee,
            "assigned_by": assigned_by,
        })

        self._save_incident(incident)
        logger.info(f"Assigned incident {incident_id} to {assignee}")
        return incident

    def add_note(
        self,
        incident_id: str,
        content: str,
        author: str = "system",
        attachments: List[str] = None
    ) -> Optional[IncidentNote]:
        """Add a note to incident."""
        incident = self.incidents.get(incident_id)
        if not incident:
            return None

        note = IncidentNote(
            id=uuid.uuid4().hex[:8],
            timestamp=datetime.now(),
            author=author,
            content=content,
            attachments=attachments or [],
        )

        incident.notes.append(note)
        incident.updated_at = datetime.now()

        self._save_incident(incident)
        return note

    def add_action(
        self,
        incident_id: str,
        action_type: str,
        description: str,
        performer: str = "system"
    ) -> Optional[IncidentAction]:
        """Add an action to incident."""
        incident = self.incidents.get(incident_id)
        if not incident:
            return None

        action = IncidentAction(
            id=uuid.uuid4().hex[:8],
            timestamp=datetime.now(),
            action_type=action_type,
            description=description,
            performer=performer,
            status="pending",
        )

        incident.actions.append(action)
        incident.updated_at = datetime.now()

        incident.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "event": "action_added",
            "action_type": action_type,
            "description": description,
            "performer": performer,
        })

        self._save_incident(incident)
        return action

    def complete_action(
        self,
        incident_id: str,
        action_id: str,
        result: str,
        status: str = "completed"
    ):
        """Mark an action as completed."""
        incident = self.incidents.get(incident_id)
        if not incident:
            return

        for action in incident.actions:
            if action.id == action_id:
                action.status = status
                action.result = result
                break

        incident.updated_at = datetime.now()
        self._save_incident(incident)

    def add_ioc(self, incident_id: str, ioc: str):
        """Add IOC to incident."""
        incident = self.incidents.get(incident_id)
        if incident and ioc not in incident.iocs:
            incident.iocs.append(ioc)
            incident.updated_at = datetime.now()
            self._save_incident(incident)

    def add_affected_asset(self, incident_id: str, asset: str):
        """Add affected asset to incident."""
        incident = self.incidents.get(incident_id)
        if incident and asset not in incident.affected_assets:
            incident.affected_assets.append(asset)
            incident.updated_at = datetime.now()
            self._save_incident(incident)

    def close_incident(
        self,
        incident_id: str,
        resolution: str,
        closed_by: str = "system"
    ) -> Optional[Incident]:
        """Close an incident."""
        incident = self.incidents.get(incident_id)
        if not incident:
            return None

        incident.status = IncidentStatus.CLOSED
        incident.resolution = resolution
        incident.closed_at = datetime.now()
        incident.updated_at = datetime.now()

        incident.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "event": "incident_closed",
            "resolution": resolution,
            "closed_by": closed_by,
        })

        self._save_incident(incident)

        # Notify callbacks
        for callback in self.callbacks["on_close"]:
            try:
                callback(incident)
            except Exception as e:
                logger.error(f"Callback error: {e}")

        logger.info(f"Closed incident {incident_id}: {resolution}")
        return incident

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get incident by ID."""
        return self.incidents.get(incident_id)

    def search_incidents(
        self,
        status: IncidentStatus = None,
        severity: IncidentSeverity = None,
        category: IncidentCategory = None,
        assigned_to: str = None,
        tag: str = None,
        limit: int = 100
    ) -> List[Incident]:
        """Search incidents with filters."""
        results = []

        for incident in self.incidents.values():
            if len(results) >= limit:
                break

            if status and incident.status != status:
                continue
            if severity and incident.severity != severity:
                continue
            if category and incident.category != category:
                continue
            if assigned_to and incident.assigned_to != assigned_to:
                continue
            if tag and tag not in incident.tags:
                continue

            results.append(incident)

        return sorted(results, key=lambda x: x.updated_at, reverse=True)

    def get_open_incidents(self) -> List[Incident]:
        """Get all open incidents."""
        return [i for i in self.incidents.values() if i.status != IncidentStatus.CLOSED]

    def get_statistics(self) -> Dict[str, Any]:
        """Get incident statistics."""
        open_incidents = self.get_open_incidents()

        return {
            "total": len(self.incidents),
            "open": len(open_incidents),
            "by_status": {
                status.value: len([i for i in self.incidents.values() if i.status == status])
                for status in IncidentStatus
            },
            "by_severity": {
                sev.value: len([i for i in self.incidents.values() if i.severity == sev])
                for sev in IncidentSeverity
            },
            "by_category": {
                cat.value: len([i for i in self.incidents.values() if i.category == cat])
                for cat in IncidentCategory
            },
        }

    def generate_report(self, incident_id: str) -> str:
        """Generate incident report."""
        incident = self.incidents.get(incident_id)
        if not incident:
            return "Incident not found"

        report = f"""
# Incident Report: {incident.id}

## Summary
- **Title:** {incident.title}
- **Category:** {incident.category.value}
- **Severity:** {incident.severity.value}
- **Status:** {incident.status.value}
- **Created:** {incident.created_at.isoformat()}
- **Assigned To:** {incident.assigned_to or 'Unassigned'}

## Description
{incident.description}

## Affected Assets
{chr(10).join(f'- {asset}' for asset in incident.affected_assets) or 'None documented'}

## Indicators of Compromise
{chr(10).join(f'- {ioc}' for ioc in incident.iocs) or 'None documented'}

## Timeline
"""
        for event in incident.timeline:
            report += f"- **{event['timestamp']}:** {event['event']} - {event.get('description', '')}\n"

        report += "\n## Actions Taken\n"
        for action in incident.actions:
            report += f"- [{action.status}] {action.action_type}: {action.description}\n"

        report += "\n## Notes\n"
        for note in incident.notes:
            report += f"### {note.timestamp.isoformat()} by {note.author}\n{note.content}\n\n"

        if incident.resolution:
            report += f"\n## Resolution\n{incident.resolution}\n"

        return report

    def on(self, event: str, callback: Callable):
        """Register event callback."""
        if event in self.callbacks:
            self.callbacks[event].append(callback)
