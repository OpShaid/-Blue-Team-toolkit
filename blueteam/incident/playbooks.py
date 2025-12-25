

import json
import yaml
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from blueteam.core.logger import get_logger
from blueteam.incident.response import Incident, IncidentResponder, IncidentCategory

logger = get_logger(__name__)


class StepType(Enum):
    COMMAND = "command"
    SCRIPT = "script"
    API_CALL = "api_call"
    MANUAL = "manual"
    CONDITION = "condition"
    PARALLEL = "parallel"
    NOTIFICATION = "notification"


@dataclass
class PlaybookStep:
    """A step in a playbook."""
    id: str
    name: str
    step_type: StepType
    description: str
    action: Dict[str, Any]
    timeout: int = 300  # seconds
    required: bool = True
    on_failure: str = "stop"  # stop, continue, skip
    conditions: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class Playbook:
    """Incident response playbook."""
    id: str
    name: str
    description: str
    version: str
    category: IncidentCategory
    severity_levels: List[str]
    steps: List[PlaybookStep]
    tags: List[str] = field(default_factory=list)
    author: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass
class PlaybookExecution:
    """Record of playbook execution."""
    id: str
    playbook_id: str
    incident_id: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str = "running"  # running, completed, failed, aborted
    current_step: int = 0
    step_results: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None


class PlaybookEngine:
    """
    Execute incident response playbooks.

    Features:
    - YAML/JSON playbook definitions
    - Conditional execution
    - Parallel step execution
    - Manual approval steps
    - Variable substitution
    - Execution history
    """

    def __init__(self, playbook_dir: str = "playbooks"):
        self.playbook_dir = Path(playbook_dir)
        self.playbook_dir.mkdir(parents=True, exist_ok=True)

        self.playbooks: Dict[str, Playbook] = {}
        self.executions: Dict[str, PlaybookExecution] = {}

        # Custom action handlers
        self.action_handlers: Dict[str, Callable] = {}

        # Load built-in playbooks
        self._load_builtin_playbooks()
        self._load_playbooks()

    def _load_builtin_playbooks(self):
        """Load built-in playbooks."""
        # Malware Response Playbook
        malware_playbook = Playbook(
            id="pb-malware-001",
            name="Malware Incident Response",
            description="Standard response procedure for malware infections",
            version="1.0",
            category=IncidentCategory.MALWARE,
            severity_levels=["medium", "high", "critical"],
            steps=[
                PlaybookStep(
                    id="step-1",
                    name="Isolate Affected System",
                    step_type=StepType.COMMAND,
                    description="Isolate the infected system from the network",
                    action={
                        "type": "network_isolation",
                        "target": "${affected_host}",
                    },
                ),
                PlaybookStep(
                    id="step-2",
                    name="Collect Volatile Data",
                    step_type=StepType.SCRIPT,
                    description="Collect memory dump and running processes",
                    action={
                        "script": "collect_volatile_data.py",
                        "args": ["${affected_host}"],
                    },
                ),
                PlaybookStep(
                    id="step-3",
                    name="Identify Malware",
                    step_type=StepType.API_CALL,
                    description="Submit suspicious files to malware analysis",
                    action={
                        "service": "virustotal",
                        "method": "scan_file",
                        "params": {"file": "${malware_sample}"},
                    },
                ),
                PlaybookStep(
                    id="step-4",
                    name="Analyst Review",
                    step_type=StepType.MANUAL,
                    description="Security analyst reviews findings and confirms remediation",
                    action={
                        "message": "Review malware analysis results and confirm remediation approach",
                        "options": ["proceed", "escalate", "abort"],
                    },
                ),
                PlaybookStep(
                    id="step-5",
                    name="Remove Malware",
                    step_type=StepType.COMMAND,
                    description="Remove identified malware and artifacts",
                    action={
                        "type": "remediation",
                        "actions": [
                            {"type": "kill_process", "target": "${malware_process}"},
                            {"type": "delete_file", "target": "${malware_path}"},
                            {"type": "remove_persistence", "target": "${persistence_mechanism}"},
                        ],
                    },
                ),
                PlaybookStep(
                    id="step-6",
                    name="Scan for Additional Infections",
                    step_type=StepType.COMMAND,
                    description="Run full system scan to ensure complete remediation",
                    action={
                        "type": "av_scan",
                        "target": "${affected_host}",
                        "full_scan": True,
                    },
                ),
                PlaybookStep(
                    id="step-7",
                    name="Restore Network Access",
                    step_type=StepType.COMMAND,
                    description="Restore network connectivity after successful remediation",
                    action={
                        "type": "network_restore",
                        "target": "${affected_host}",
                    },
                    conditions=[{"step": "step-6", "status": "success"}],
                ),
                PlaybookStep(
                    id="step-8",
                    name="Notification",
                    step_type=StepType.NOTIFICATION,
                    description="Notify stakeholders of incident resolution",
                    action={
                        "channels": ["email", "slack"],
                        "template": "incident_resolved",
                        "recipients": ["${incident_owner}", "security-team"],
                    },
                ),
            ],
            tags=["malware", "automated"],
            author="BlueTeam Arsenal",
        )
        self.playbooks[malware_playbook.id] = malware_playbook

        # Phishing Response Playbook
        phishing_playbook = Playbook(
            id="pb-phishing-001",
            name="Phishing Incident Response",
            description="Response procedure for phishing attacks",
            version="1.0",
            category=IncidentCategory.PHISHING,
            severity_levels=["low", "medium", "high"],
            steps=[
                PlaybookStep(
                    id="step-1",
                    name="Identify Affected Users",
                    step_type=StepType.COMMAND,
                    description="Query email logs to identify all recipients",
                    action={
                        "type": "email_search",
                        "query": "subject:${phishing_subject} OR from:${sender_address}",
                    },
                ),
                PlaybookStep(
                    id="step-2",
                    name="Block Sender",
                    step_type=StepType.API_CALL,
                    description="Block the phishing sender in email gateway",
                    action={
                        "service": "email_gateway",
                        "method": "block_sender",
                        "params": {"address": "${sender_address}"},
                    },
                ),
                PlaybookStep(
                    id="step-3",
                    name="Block Malicious URLs",
                    step_type=StepType.COMMAND,
                    description="Block phishing URLs in proxy/firewall",
                    action={
                        "type": "url_block",
                        "urls": "${phishing_urls}",
                    },
                ),
                PlaybookStep(
                    id="step-4",
                    name="Quarantine Emails",
                    step_type=StepType.API_CALL,
                    description="Remove phishing emails from all mailboxes",
                    action={
                        "service": "email_gateway",
                        "method": "purge_messages",
                        "params": {"message_id": "${message_id}"},
                    },
                ),
                PlaybookStep(
                    id="step-5",
                    name="Check for Compromised Accounts",
                    step_type=StepType.COMMAND,
                    description="Check if any users clicked links or entered credentials",
                    action={
                        "type": "proxy_log_search",
                        "query": "${phishing_domain}",
                        "timeframe": "24h",
                    },
                ),
                PlaybookStep(
                    id="step-6",
                    name="Reset Compromised Credentials",
                    step_type=StepType.MANUAL,
                    description="Reset passwords for users who may be compromised",
                    action={
                        "message": "Reset passwords for the following users: ${compromised_users}",
                        "options": ["completed", "skip"],
                    },
                ),
                PlaybookStep(
                    id="step-7",
                    name="User Notification",
                    step_type=StepType.NOTIFICATION,
                    description="Notify affected users about the phishing attempt",
                    action={
                        "channels": ["email"],
                        "template": "phishing_awareness",
                        "recipients": "${affected_users}",
                    },
                ),
            ],
            tags=["phishing", "email"],
            author="BlueTeam Arsenal",
        )
        self.playbooks[phishing_playbook.id] = phishing_playbook

        # Ransomware Response Playbook
        ransomware_playbook = Playbook(
            id="pb-ransomware-001",
            name="Ransomware Incident Response",
            description="Critical response procedure for ransomware attacks",
            version="1.0",
            category=IncidentCategory.RANSOMWARE,
            severity_levels=["critical"],
            steps=[
                PlaybookStep(
                    id="step-1",
                    name="Immediate Network Isolation",
                    step_type=StepType.PARALLEL,
                    description="Isolate all affected systems immediately",
                    action={
                        "steps": [
                            {"type": "network_isolation", "target": "${affected_hosts}"},
                            {"type": "disable_shares", "target": "all"},
                        ],
                    },
                    timeout=60,
                ),
                PlaybookStep(
                    id="step-2",
                    name="Notify Incident Commander",
                    step_type=StepType.NOTIFICATION,
                    description="Alert incident commander and management",
                    action={
                        "channels": ["phone", "slack", "email"],
                        "priority": "critical",
                        "template": "ransomware_alert",
                        "recipients": ["incident-commander", "ciso", "it-director"],
                    },
                ),
                PlaybookStep(
                    id="step-3",
                    name="Preserve Evidence",
                    step_type=StepType.SCRIPT,
                    description="Collect forensic evidence from affected systems",
                    action={
                        "script": "forensic_collection.py",
                        "args": ["${affected_hosts}", "--preserve"],
                    },
                ),
                PlaybookStep(
                    id="step-4",
                    name="Identify Ransomware Variant",
                    step_type=StepType.COMMAND,
                    description="Identify ransomware strain for decryption options",
                    action={
                        "type": "ransomware_id",
                        "sample": "${ransom_note}",
                        "encrypted_file": "${encrypted_sample}",
                    },
                ),
                PlaybookStep(
                    id="step-5",
                    name="Check Backup Integrity",
                    step_type=StepType.COMMAND,
                    description="Verify backups are intact and not encrypted",
                    action={
                        "type": "backup_verify",
                        "scope": "all_critical",
                    },
                ),
                PlaybookStep(
                    id="step-6",
                    name="Management Decision Point",
                    step_type=StepType.MANUAL,
                    description="Management decision on recovery approach",
                    action={
                        "message": "Recovery options: 1) Restore from backup, 2) Attempt decryption, 3) Other",
                        "options": ["restore_backup", "attempt_decrypt", "escalate_external"],
                        "requires_approval": True,
                    },
                ),
            ],
            tags=["ransomware", "critical", "encryption"],
            author="BlueTeam Arsenal",
        )
        self.playbooks[ransomware_playbook.id] = ransomware_playbook

    def _load_playbooks(self):
        """Load playbooks from directory."""
        for file in self.playbook_dir.glob("*.yaml"):
            try:
                self._load_playbook_file(file)
            except Exception as e:
                logger.error(f"Failed to load playbook {file}: {e}")

        for file in self.playbook_dir.glob("*.json"):
            try:
                self._load_playbook_file(file)
            except Exception as e:
                logger.error(f"Failed to load playbook {file}: {e}")

    def _load_playbook_file(self, file_path: Path):
        """Load playbook from file."""
        with open(file_path) as f:
            if file_path.suffix == ".yaml":
                data = yaml.safe_load(f)
            else:
                data = json.load(f)

        playbook = self._parse_playbook(data)
        self.playbooks[playbook.id] = playbook
        logger.info(f"Loaded playbook: {playbook.name}")

    def _parse_playbook(self, data: Dict[str, Any]) -> Playbook:
        """Parse playbook from dictionary."""
        steps = []
        for step_data in data.get("steps", []):
            steps.append(PlaybookStep(
                id=step_data["id"],
                name=step_data["name"],
                step_type=StepType(step_data.get("type", "command")),
                description=step_data.get("description", ""),
                action=step_data.get("action", {}),
                timeout=step_data.get("timeout", 300),
                required=step_data.get("required", True),
                on_failure=step_data.get("on_failure", "stop"),
                conditions=step_data.get("conditions", []),
            ))

        return Playbook(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            version=data.get("version", "1.0"),
            category=IncidentCategory(data.get("category", "other")),
            severity_levels=data.get("severity_levels", ["medium", "high", "critical"]),
            steps=steps,
            tags=data.get("tags", []),
            author=data.get("author", ""),
        )

    def register_action_handler(self, action_type: str, handler: Callable):
        """Register custom action handler."""
        self.action_handlers[action_type] = handler

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        """Get playbook by ID."""
        return self.playbooks.get(playbook_id)

    def get_playbooks_for_incident(self, incident: Incident) -> List[Playbook]:
        """Get applicable playbooks for an incident."""
        applicable = []

        for playbook in self.playbooks.values():
            if playbook.category == incident.category:
                if incident.severity.value in playbook.severity_levels:
                    applicable.append(playbook)

        return applicable

    def execute(
        self,
        playbook_id: str,
        incident_id: str,
        variables: Dict[str, Any] = None,
        responder: IncidentResponder = None
    ) -> PlaybookExecution:
        """Execute a playbook for an incident."""
        playbook = self.playbooks.get(playbook_id)
        if not playbook:
            raise ValueError(f"Playbook not found: {playbook_id}")

        import uuid
        execution = PlaybookExecution(
            id=uuid.uuid4().hex[:8],
            playbook_id=playbook_id,
            incident_id=incident_id,
            started_at=datetime.now(),
        )

        self.executions[execution.id] = execution
        variables = variables or {}

        logger.info(f"Starting playbook execution: {playbook.name} for incident {incident_id}")

        for i, step in enumerate(playbook.steps):
            execution.current_step = i

            # Check conditions
            if not self._check_conditions(step, execution):
                logger.info(f"Skipping step {step.id}: conditions not met")
                execution.step_results.append({
                    "step_id": step.id,
                    "status": "skipped",
                    "reason": "conditions not met",
                })
                continue

            # Execute step
            try:
                result = self._execute_step(step, variables, incident_id, responder)
                execution.step_results.append({
                    "step_id": step.id,
                    "status": "success",
                    "result": result,
                    "timestamp": datetime.now().isoformat(),
                })

                # Update variables with result
                if isinstance(result, dict):
                    variables.update(result)

            except Exception as e:
                logger.error(f"Step {step.id} failed: {e}")
                execution.step_results.append({
                    "step_id": step.id,
                    "status": "failed",
                    "error": str(e),
                    "timestamp": datetime.now().isoformat(),
                })

                if step.on_failure == "stop":
                    execution.status = "failed"
                    execution.error = str(e)
                    execution.completed_at = datetime.now()
                    return execution

        execution.status = "completed"
        execution.completed_at = datetime.now()

        logger.info(f"Playbook execution completed: {execution.id}")
        return execution

    def _check_conditions(self, step: PlaybookStep, execution: PlaybookExecution) -> bool:
        """Check if step conditions are met."""
        for condition in step.conditions:
            step_id = condition.get("step")
            required_status = condition.get("status", "success")

            # Find the referenced step result
            for result in execution.step_results:
                if result.get("step_id") == step_id:
                    if result.get("status") != required_status:
                        return False
                    break

        return True

    def _execute_step(
        self,
        step: PlaybookStep,
        variables: Dict[str, Any],
        incident_id: str,
        responder: IncidentResponder
    ) -> Any:
        """Execute a single playbook step."""
        logger.info(f"Executing step: {step.name}")

        # Substitute variables in action
        action = self._substitute_variables(step.action, variables)

        if step.step_type == StepType.COMMAND:
            return self._execute_command(action, step.timeout)

        elif step.step_type == StepType.SCRIPT:
            return self._execute_script(action, step.timeout)

        elif step.step_type == StepType.API_CALL:
            return self._execute_api_call(action)

        elif step.step_type == StepType.MANUAL:
            return self._handle_manual_step(step, action, incident_id, responder)

        elif step.step_type == StepType.NOTIFICATION:
            return self._send_notification(action)

        elif step.step_type == StepType.PARALLEL:
            return self._execute_parallel(action, step.timeout)

        else:
            # Check for custom handler
            action_type = action.get("type")
            if action_type in self.action_handlers:
                return self.action_handlers[action_type](action, variables)

            raise ValueError(f"Unknown step type: {step.step_type}")

    def _substitute_variables(self, action: Any, variables: Dict[str, Any]) -> Any:
        """Substitute variables in action."""
        if isinstance(action, str):
            for key, value in variables.items():
                action = action.replace(f"${{{key}}}", str(value))
            return action

        elif isinstance(action, dict):
            return {k: self._substitute_variables(v, variables) for k, v in action.items()}

        elif isinstance(action, list):
            return [self._substitute_variables(item, variables) for item in action]

        return action

    def _execute_command(self, action: Dict[str, Any], timeout: int) -> Dict[str, Any]:
        """Execute a command action."""
        action_type = action.get("type", "")
        logger.info(f"Executing command action: {action_type}")

        # Simulate command execution
        return {
            "action_type": action_type,
            "status": "executed",
            "message": f"Command '{action_type}' executed successfully",
        }

    def _execute_script(self, action: Dict[str, Any], timeout: int) -> Dict[str, Any]:
        """Execute a script."""
        script = action.get("script", "")
        args = action.get("args", [])

        logger.info(f"Executing script: {script}")

        # In production, this would actually run the script
        return {
            "script": script,
            "status": "executed",
            "output": "Script executed successfully",
        }

    def _execute_api_call(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an API call."""
        service = action.get("service", "")
        method = action.get("method", "")

        logger.info(f"API call: {service}.{method}")

        return {
            "service": service,
            "method": method,
            "status": "executed",
        }

    def _handle_manual_step(
        self,
        step: PlaybookStep,
        action: Dict[str, Any],
        incident_id: str,
        responder: IncidentResponder
    ) -> Dict[str, Any]:
        """Handle manual approval step."""
        message = action.get("message", "Manual step required")
        options = action.get("options", ["proceed", "abort"])

        logger.info(f"Manual step: {message}")

        # In production, this would wait for user input
        # For now, we'll add an action to the incident
        if responder:
            responder.add_action(
                incident_id,
                "manual_review",
                f"{step.name}: {message}",
                "playbook_engine"
            )

        return {
            "type": "manual",
            "message": message,
            "status": "pending_review",
        }

    def _send_notification(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """Send notification."""
        channels = action.get("channels", [])
        recipients = action.get("recipients", [])

        logger.info(f"Sending notification to {channels}")

        return {
            "channels": channels,
            "recipients": recipients,
            "status": "sent",
        }

    def _execute_parallel(self, action: Dict[str, Any], timeout: int) -> Dict[str, Any]:
        """Execute steps in parallel."""
        steps = action.get("steps", [])
        results = []

        for step_action in steps:
            result = self._execute_command(step_action, timeout)
            results.append(result)

        return {
            "parallel_steps": len(steps),
            "results": results,
        }

    def list_playbooks(self) -> List[Dict[str, Any]]:
        """List all available playbooks."""
        return [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "category": p.category.value,
                "severity_levels": p.severity_levels,
                "steps_count": len(p.steps),
                "tags": p.tags,
            }
            for p in self.playbooks.values()
        ]

    def get_execution_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get status of playbook execution."""
        execution = self.executions.get(execution_id)
        if not execution:
            return None

        return {
            "id": execution.id,
            "playbook_id": execution.playbook_id,
            "incident_id": execution.incident_id,
            "status": execution.status,
            "current_step": execution.current_step,
            "step_results": execution.step_results,
            "started_at": execution.started_at.isoformat(),
            "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
            "error": execution.error,
        }
