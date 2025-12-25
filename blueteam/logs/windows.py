"""
Windows Event Log Parser - Parse and analyze Windows event logs.
"""

import xml.etree.ElementTree as ET
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional
from dataclasses import dataclass, field

from blueteam.core.logger import get_logger
from blueteam.logs.parser import LogEntry

logger = get_logger(__name__)


@dataclass
class WindowsEvent:
    """Represents a Windows Event Log entry."""
    event_id: int
    timestamp: datetime
    source: str
    level: str
    computer: str
    message: str
    user: Optional[str] = None
    keywords: List[str] = field(default_factory=list)
    task: Optional[str] = None
    opcode: Optional[str] = None
    raw_xml: str = ""
    data: Dict[str, Any] = field(default_factory=dict)


class WindowsEventParser:
    """
    Parse Windows Event Logs (EVTX files) and live events.

    Features:
    - Parse EVTX files
    - Security event analysis
    - Suspicious event detection
    - Lateral movement detection
    - PowerShell logging analysis
    """

    # Critical Security Event IDs
    SECURITY_EVENTS = {
        # Logon events
        4624: ("Successful Logon", "low"),
        4625: ("Failed Logon", "medium"),
        4634: ("Logoff", "low"),
        4648: ("Explicit Credentials Logon", "medium"),
        4672: ("Special Privileges Assigned", "medium"),
        4776: ("Credential Validation", "low"),

        # Account management
        4720: ("User Account Created", "medium"),
        4722: ("User Account Enabled", "medium"),
        4723: ("Password Change Attempt", "low"),
        4724: ("Password Reset Attempt", "medium"),
        4725: ("User Account Disabled", "medium"),
        4726: ("User Account Deleted", "high"),
        4728: ("Member Added to Security Group", "high"),
        4732: ("Member Added to Local Group", "medium"),
        4756: ("Member Added to Universal Group", "high"),

        # Privilege use
        4673: ("Sensitive Privilege Use", "medium"),
        4674: ("Operation on Privileged Object", "medium"),

        # Process events
        4688: ("Process Creation", "low"),
        4689: ("Process Termination", "low"),

        # Object access
        4656: ("Object Handle Request", "low"),
        4663: ("Object Access", "low"),
        4670: ("Object Permissions Changed", "medium"),

        # Policy changes
        4719: ("Audit Policy Changed", "high"),
        4739: ("Domain Policy Changed", "high"),

        # System events
        4697: ("Service Installed", "high"),
        7045: ("New Service Installed", "high"),

        # Scheduled tasks
        4698: ("Scheduled Task Created", "high"),
        4699: ("Scheduled Task Deleted", "medium"),
        4700: ("Scheduled Task Enabled", "medium"),
        4701: ("Scheduled Task Disabled", "low"),

        # Firewall
        4946: ("Firewall Rule Added", "high"),
        4947: ("Firewall Rule Modified", "high"),
        4948: ("Firewall Rule Deleted", "high"),
        4950: ("Firewall Setting Changed", "high"),

        # Sysmon events (if installed)
        1: ("Sysmon - Process Create", "low"),
        3: ("Sysmon - Network Connection", "low"),
        7: ("Sysmon - Image Loaded", "low"),
        8: ("Sysmon - CreateRemoteThread", "high"),
        10: ("Sysmon - Process Access", "medium"),
        11: ("Sysmon - File Create", "low"),
        12: ("Sysmon - Registry Event", "low"),
        13: ("Sysmon - Registry Value Set", "low"),
        22: ("Sysmon - DNS Query", "low"),
    }

    # Logon Types
    LOGON_TYPES = {
        2: "Interactive",
        3: "Network",
        4: "Batch",
        5: "Service",
        7: "Unlock",
        8: "NetworkCleartext",
        9: "NewCredentials",
        10: "RemoteInteractive",
        11: "CachedInteractive",
    }

    # Suspicious patterns
    SUSPICIOUS_COMMANDS = [
        r"powershell.*-enc",
        r"cmd.*\/c.*whoami",
        r"net\s+user",
        r"net\s+localgroup",
        r"mimikatz",
        r"psexec",
        r"wmic\s+process\s+call",
        r"certutil.*-decode",
        r"bitsadmin.*\/transfer",
        r"mshta.*javascript",
        r"regsvr32.*\/s.*\/n.*\/u",
        r"rundll32.*javascript",
    ]

    def __init__(self):
        self.events: List[WindowsEvent] = []
        self.findings: List[Dict[str, Any]] = []
        self._suspicious_patterns = [re.compile(p, re.IGNORECASE) for p in self.SUSPICIOUS_COMMANDS]

    def parse_evtx(self, file_path: str) -> Generator[WindowsEvent, None, None]:
        """Parse EVTX file and yield events."""
        try:
            # Try using python-evtx if available
            import Evtx.Evtx as evtx
            import Evtx.Views as views

            with evtx.Evtx(file_path) as log:
                for record in log.records():
                    try:
                        event = self._parse_record_xml(record.xml())
                        if event:
                            yield event
                    except Exception as e:
                        logger.debug(f"Error parsing record: {e}")

        except ImportError:
            logger.warning("python-evtx not installed. Using XML export method.")
            # Fallback to XML parsing
            yield from self._parse_exported_xml(file_path)

    def _parse_record_xml(self, xml_str: str) -> Optional[WindowsEvent]:
        """Parse event from XML string."""
        try:
            root = ET.fromstring(xml_str)
            ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

            # Get System data
            system = root.find("e:System", ns)
            if system is None:
                return None

            event_id_elem = system.find("e:EventID", ns)
            event_id = int(event_id_elem.text) if event_id_elem is not None and event_id_elem.text else 0

            time_elem = system.find("e:TimeCreated", ns)
            timestamp = None
            if time_elem is not None:
                ts_str = time_elem.get("SystemTime", "")
                timestamp = self._parse_timestamp(ts_str)

            provider = system.find("e:Provider", ns)
            source = provider.get("Name", "Unknown") if provider is not None else "Unknown"

            level_elem = system.find("e:Level", ns)
            level_map = {0: "Info", 1: "Critical", 2: "Error", 3: "Warning", 4: "Info", 5: "Verbose"}
            level = level_map.get(int(level_elem.text) if level_elem is not None and level_elem.text else 4, "Info")

            computer_elem = system.find("e:Computer", ns)
            computer = computer_elem.text if computer_elem is not None else "Unknown"

            # Get EventData
            data = {}
            event_data = root.find("e:EventData", ns)
            if event_data is not None:
                for elem in event_data:
                    name = elem.get("Name", "")
                    if name:
                        data[name] = elem.text or ""

            # Build message
            message = self._build_message(event_id, data)

            return WindowsEvent(
                event_id=event_id,
                timestamp=timestamp or datetime.now(),
                source=source,
                level=level,
                computer=computer,
                message=message,
                user=data.get("TargetUserName") or data.get("SubjectUserName"),
                raw_xml=xml_str,
                data=data
            )

        except Exception as e:
            logger.debug(f"XML parse error: {e}")
            return None

    def _parse_exported_xml(self, file_path: str) -> Generator[WindowsEvent, None, None]:
        """Parse exported XML event log."""
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            for event_elem in root.iter():
                if "Event" in event_elem.tag:
                    try:
                        xml_str = ET.tostring(event_elem, encoding="unicode")
                        event = self._parse_record_xml(xml_str)
                        if event:
                            yield event
                    except Exception:
                        continue

        except Exception as e:
            logger.error(f"Error parsing XML file: {e}")

    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse Windows timestamp."""
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(ts_str[:26], fmt[:len(ts_str)])
            except ValueError:
                continue

        return None

    def _build_message(self, event_id: int, data: Dict[str, Any]) -> str:
        """Build human-readable message from event data."""
        event_info = self.SECURITY_EVENTS.get(event_id, (f"Event {event_id}", "low"))

        if event_id == 4624:  # Logon
            logon_type = self.LOGON_TYPES.get(int(data.get("LogonType", 0)), "Unknown")
            return f"{event_info[0]}: {data.get('TargetUserName', 'N/A')} ({logon_type}) from {data.get('IpAddress', 'N/A')}"

        elif event_id == 4625:  # Failed logon
            return f"{event_info[0]}: {data.get('TargetUserName', 'N/A')} from {data.get('IpAddress', 'N/A')} - {data.get('FailureReason', '')}"

        elif event_id == 4688:  # Process creation
            return f"{event_info[0]}: {data.get('NewProcessName', 'N/A')} by {data.get('SubjectUserName', 'N/A')}"

        elif event_id in (4720, 4726):  # User account changes
            return f"{event_info[0]}: {data.get('TargetUserName', 'N/A')} by {data.get('SubjectUserName', 'N/A')}"

        elif event_id == 4697:  # Service installed
            return f"{event_info[0]}: {data.get('ServiceName', 'N/A')} - {data.get('ServiceFileName', 'N/A')}"

        else:
            return event_info[0]

    def analyze_events(self, events: List[WindowsEvent]) -> List[Dict[str, Any]]:
        """Analyze events for security issues."""
        self.events = events
        self.findings = []

        self._detect_suspicious_logons()
        self._detect_privilege_escalation()
        self._detect_lateral_movement()
        self._detect_suspicious_processes()
        self._detect_persistence()

        return self.findings

    def _detect_suspicious_logons(self):
        """Detect suspicious logon patterns."""
        failed_logons: Dict[str, List[WindowsEvent]] = {}
        successful_after_failed: List[WindowsEvent] = []

        for event in self.events:
            if event.event_id == 4625:  # Failed logon
                key = f"{event.data.get('IpAddress', 'unknown')}:{event.data.get('TargetUserName', 'unknown')}"
                if key not in failed_logons:
                    failed_logons[key] = []
                failed_logons[key].append(event)

            elif event.event_id == 4624:  # Successful logon
                key = f"{event.data.get('IpAddress', 'unknown')}:{event.data.get('TargetUserName', 'unknown')}"
                if key in failed_logons and len(failed_logons[key]) >= 5:
                    successful_after_failed.append(event)

        # Report brute force attempts
        for key, failures in failed_logons.items():
            if len(failures) >= 10:
                self.findings.append({
                    "type": "brute_force",
                    "severity": "high",
                    "title": f"Brute Force Attack Detected",
                    "description": f"{len(failures)} failed logon attempts for {key}",
                    "events": failures[:10],
                })

        # Report successful logon after brute force
        for event in successful_after_failed:
            self.findings.append({
                "type": "credential_compromise",
                "severity": "critical",
                "title": "Successful Logon After Brute Force",
                "description": f"User {event.data.get('TargetUserName')} logged in after multiple failures",
                "events": [event],
            })

    def _detect_privilege_escalation(self):
        """Detect privilege escalation attempts."""
        for event in self.events:
            if event.event_id == 4672:  # Special privileges assigned
                if event.data.get("PrivilegeList"):
                    privileges = event.data.get("PrivilegeList", "")
                    dangerous_privs = ["SeDebugPrivilege", "SeTcbPrivilege", "SeLoadDriverPrivilege"]
                    if any(p in privileges for p in dangerous_privs):
                        self.findings.append({
                            "type": "privilege_escalation",
                            "severity": "high",
                            "title": "Dangerous Privileges Assigned",
                            "description": f"User {event.user} assigned sensitive privileges",
                            "events": [event],
                        })

            elif event.event_id in (4728, 4756):  # Added to admin groups
                group = event.data.get("TargetUserName", "")
                if any(g in group.lower() for g in ["admin", "domain admin", "enterprise admin"]):
                    self.findings.append({
                        "type": "privilege_escalation",
                        "severity": "critical",
                        "title": "User Added to Admin Group",
                        "description": f"User added to {group}",
                        "events": [event],
                    })

    def _detect_lateral_movement(self):
        """Detect lateral movement indicators."""
        remote_logons = [e for e in self.events if e.event_id == 4624 and e.data.get("LogonType") in ("3", "10")]

        # Group by source IP
        by_source: Dict[str, List[WindowsEvent]] = {}
        for event in remote_logons:
            ip = event.data.get("IpAddress", "unknown")
            if ip not in by_source:
                by_source[ip] = []
            by_source[ip].append(event)

        # Detect single source accessing multiple systems
        for ip, events in by_source.items():
            computers = set(e.computer for e in events)
            if len(computers) >= 3:
                self.findings.append({
                    "type": "lateral_movement",
                    "severity": "high",
                    "title": "Potential Lateral Movement",
                    "description": f"IP {ip} accessed {len(computers)} systems",
                    "events": events[:10],
                })

    def _detect_suspicious_processes(self):
        """Detect suspicious process execution."""
        for event in self.events:
            if event.event_id in (4688, 1):  # Process creation
                cmd_line = event.data.get("CommandLine", "") or event.data.get("NewProcessName", "")

                for pattern in self._suspicious_patterns:
                    if pattern.search(cmd_line):
                        self.findings.append({
                            "type": "suspicious_process",
                            "severity": "high",
                            "title": "Suspicious Process Detected",
                            "description": f"Suspicious command: {cmd_line[:200]}",
                            "events": [event],
                        })
                        break

    def _detect_persistence(self):
        """Detect persistence mechanisms."""
        for event in self.events:
            # Service installation
            if event.event_id in (4697, 7045):
                service_name = event.data.get("ServiceName", "")
                service_file = event.data.get("ServiceFileName", "") or event.data.get("ImagePath", "")

                # Check for suspicious paths
                suspicious_paths = ["temp", "appdata", "public", "programdata"]
                if any(p in service_file.lower() for p in suspicious_paths):
                    self.findings.append({
                        "type": "persistence",
                        "severity": "critical",
                        "title": "Suspicious Service Installed",
                        "description": f"Service {service_name} installed from suspicious path",
                        "events": [event],
                    })

            # Scheduled task
            elif event.event_id == 4698:
                task_name = event.data.get("TaskName", "")
                self.findings.append({
                    "type": "persistence",
                    "severity": "medium",
                    "title": "Scheduled Task Created",
                    "description": f"New scheduled task: {task_name}",
                    "events": [event],
                })

    def to_log_entries(self, events: List[WindowsEvent]) -> List[LogEntry]:
        """Convert Windows events to generic LogEntry format."""
        return [
            LogEntry(
                timestamp=e.timestamp,
                source=f"windows:{e.source}",
                level=e.level.upper(),
                message=e.message,
                raw=e.raw_xml,
                parsed=e.data,
                tags=[f"event_id:{e.event_id}", f"computer:{e.computer}"]
            )
            for e in events
        ]

    def get_summary(self) -> Dict[str, Any]:
        """Get analysis summary."""
        event_counts = {}
        for event in self.events:
            event_counts[event.event_id] = event_counts.get(event.event_id, 0) + 1

        return {
            "total_events": len(self.events),
            "findings": len(self.findings),
            "event_id_counts": dict(sorted(event_counts.items(), key=lambda x: x[1], reverse=True)[:20]),
            "by_severity": {
                "critical": len([f for f in self.findings if f["severity"] == "critical"]),
                "high": len([f for f in self.findings if f["severity"] == "high"]),
                "medium": len([f for f in self.findings if f["severity"] == "medium"]),
            }
        }
