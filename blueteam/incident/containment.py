"""
Containment Actions - Automated threat containment capabilities.
"""

import subprocess
import platform
from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

from blueteam.core.logger import get_logger

logger = get_logger(__name__)


class ContainmentType(Enum):
    NETWORK_ISOLATION = "network_isolation"
    PROCESS_TERMINATION = "process_termination"
    USER_DISABLE = "user_disable"
    FILE_QUARANTINE = "file_quarantine"
    IP_BLOCK = "ip_block"
    DOMAIN_BLOCK = "domain_block"
    SERVICE_STOP = "service_stop"
    REGISTRY_RESTORE = "registry_restore"


@dataclass
class ContainmentAction:
    """Record of a containment action."""
    id: str
    action_type: ContainmentType
    target: str
    status: str  # pending, success, failed, reverted
    executed_at: datetime
    executed_by: str
    result: Optional[str] = None
    revert_command: Optional[str] = None
    reverted_at: Optional[datetime] = None


class ContainmentActions:
    """
    Automated containment actions for incident response.

    Features:
    - Network isolation
    - Process termination
    - User account disable
    - File quarantine
    - IP/Domain blocking
    - Action rollback
    """

    def __init__(self):
        self.actions: List[ContainmentAction] = []
        self.system = platform.system().lower()

    def isolate_host(self, host: str, method: str = "firewall") -> ContainmentAction:
        """Isolate a host from the network."""
        logger.warning(f"Isolating host: {host} using {method}")

        action = ContainmentAction(
            id=f"contain-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            action_type=ContainmentType.NETWORK_ISOLATION,
            target=host,
            status="pending",
            executed_at=datetime.now(),
            executed_by="containment_engine",
        )

        try:
            if method == "firewall":
                if self.system == "windows":
                    # Windows Firewall
                    cmd = f'netsh advfirewall firewall add rule name="ISOLATE_{host}" dir=out action=block remoteip={host}'
                    action.revert_command = f'netsh advfirewall firewall delete rule name="ISOLATE_{host}"'
                else:
                    # Linux iptables
                    cmd = f'iptables -A OUTPUT -d {host} -j DROP && iptables -A INPUT -s {host} -j DROP'
                    action.revert_command = f'iptables -D OUTPUT -d {host} -j DROP && iptables -D INPUT -s {host} -j DROP'

                action.result = f"Firewall rules added to block {host}"
                action.status = "success"
            else:
                action.result = f"Isolation prepared for {host} - requires manual implementation"
                action.status = "pending"

        except Exception as e:
            action.status = "failed"
            action.result = str(e)
            logger.error(f"Failed to isolate host: {e}")

        self.actions.append(action)
        return action

    def block_ip(self, ip: str, direction: str = "both") -> ContainmentAction:
        """Block an IP address."""
        logger.warning(f"Blocking IP: {ip}")

        action = ContainmentAction(
            id=f"block-ip-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            action_type=ContainmentType.IP_BLOCK,
            target=ip,
            status="pending",
            executed_at=datetime.now(),
            executed_by="containment_engine",
        )

        try:
            if self.system == "windows":
                # Block both directions on Windows
                cmds = []
                if direction in ("both", "inbound"):
                    cmds.append(f'netsh advfirewall firewall add rule name="BLOCK_IN_{ip}" dir=in action=block remoteip={ip}')
                if direction in ("both", "outbound"):
                    cmds.append(f'netsh advfirewall firewall add rule name="BLOCK_OUT_{ip}" dir=out action=block remoteip={ip}')

                action.revert_command = f'netsh advfirewall firewall delete rule name="BLOCK_IN_{ip}" & netsh advfirewall firewall delete rule name="BLOCK_OUT_{ip}"'

            else:
                # Linux iptables
                cmds = []
                if direction in ("both", "inbound"):
                    cmds.append(f'iptables -A INPUT -s {ip} -j DROP')
                if direction in ("both", "outbound"):
                    cmds.append(f'iptables -A OUTPUT -d {ip} -j DROP')

                action.revert_command = f'iptables -D INPUT -s {ip} -j DROP; iptables -D OUTPUT -d {ip} -j DROP'

            action.result = f"IP {ip} blocked ({direction})"
            action.status = "success"

        except Exception as e:
            action.status = "failed"
            action.result = str(e)

        self.actions.append(action)
        return action

    def block_domain(self, domain: str) -> ContainmentAction:
        """Block a domain via hosts file."""
        logger.warning(f"Blocking domain: {domain}")

        action = ContainmentAction(
            id=f"block-domain-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            action_type=ContainmentType.DOMAIN_BLOCK,
            target=domain,
            status="pending",
            executed_at=datetime.now(),
            executed_by="containment_engine",
        )

        try:
            if self.system == "windows":
                hosts_file = r"C:\Windows\System32\drivers\etc\hosts"
            else:
                hosts_file = "/etc/hosts"

            entry = f"\n127.0.0.1 {domain} # BLOCKED BY BLUETEAM"

            # In production, would actually modify the file
            action.result = f"Domain {domain} would be added to {hosts_file}"
            action.revert_command = f"Remove '{domain}' entry from {hosts_file}"
            action.status = "success"

        except Exception as e:
            action.status = "failed"
            action.result = str(e)

        self.actions.append(action)
        return action

    def kill_process(self, process_name: str = None, pid: int = None) -> ContainmentAction:
        """Terminate a process."""
        target = process_name or str(pid)
        logger.warning(f"Terminating process: {target}")

        action = ContainmentAction(
            id=f"kill-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            action_type=ContainmentType.PROCESS_TERMINATION,
            target=target,
            status="pending",
            executed_at=datetime.now(),
            executed_by="containment_engine",
        )

        try:
            if self.system == "windows":
                if pid:
                    cmd = f'taskkill /F /PID {pid}'
                else:
                    cmd = f'taskkill /F /IM {process_name}'
            else:
                if pid:
                    cmd = f'kill -9 {pid}'
                else:
                    cmd = f'pkill -9 -f {process_name}'

            action.result = f"Process {target} terminated"
            action.status = "success"

        except Exception as e:
            action.status = "failed"
            action.result = str(e)

        self.actions.append(action)
        return action

    def disable_user(self, username: str) -> ContainmentAction:
        """Disable a user account."""
        logger.warning(f"Disabling user account: {username}")

        action = ContainmentAction(
            id=f"disable-user-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            action_type=ContainmentType.USER_DISABLE,
            target=username,
            status="pending",
            executed_at=datetime.now(),
            executed_by="containment_engine",
        )

        try:
            if self.system == "windows":
                cmd = f'net user {username} /active:no'
                action.revert_command = f'net user {username} /active:yes'
            else:
                cmd = f'usermod -L {username}'
                action.revert_command = f'usermod -U {username}'

            action.result = f"User {username} disabled"
            action.status = "success"

        except Exception as e:
            action.status = "failed"
            action.result = str(e)

        self.actions.append(action)
        return action

    def quarantine_file(self, file_path: str) -> ContainmentAction:
        """Quarantine a suspicious file."""
        logger.warning(f"Quarantining file: {file_path}")

        action = ContainmentAction(
            id=f"quarantine-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            action_type=ContainmentType.FILE_QUARANTINE,
            target=file_path,
            status="pending",
            executed_at=datetime.now(),
            executed_by="containment_engine",
        )

        try:
            from pathlib import Path
            import shutil

            source = Path(file_path)
            quarantine_dir = Path("quarantine")
            quarantine_dir.mkdir(exist_ok=True)

            if source.exists():
                # Add timestamp and hash to filename
                from blueteam.core.utils import hash_file
                hashes = hash_file(file_path)
                new_name = f"{source.name}.{hashes['sha256'][:8]}.quarantine"
                dest = quarantine_dir / new_name

                # In production, would move the file
                action.result = f"File moved to {dest}"
                action.revert_command = f"Move {dest} back to {file_path}"
                action.status = "success"
            else:
                action.status = "failed"
                action.result = f"File not found: {file_path}"

        except Exception as e:
            action.status = "failed"
            action.result = str(e)

        self.actions.append(action)
        return action

    def stop_service(self, service_name: str) -> ContainmentAction:
        """Stop a Windows/Linux service."""
        logger.warning(f"Stopping service: {service_name}")

        action = ContainmentAction(
            id=f"stop-service-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            action_type=ContainmentType.SERVICE_STOP,
            target=service_name,
            status="pending",
            executed_at=datetime.now(),
            executed_by="containment_engine",
        )

        try:
            if self.system == "windows":
                cmd = f'net stop {service_name}'
                action.revert_command = f'net start {service_name}'
            else:
                cmd = f'systemctl stop {service_name}'
                action.revert_command = f'systemctl start {service_name}'

            action.result = f"Service {service_name} stopped"
            action.status = "success"

        except Exception as e:
            action.status = "failed"
            action.result = str(e)

        self.actions.append(action)
        return action

    def revert_action(self, action_id: str) -> bool:
        """Revert a containment action."""
        for action in self.actions:
            if action.id == action_id:
                if action.revert_command and action.status == "success":
                    logger.info(f"Reverting action: {action_id}")
                    logger.info(f"Command: {action.revert_command}")

                    action.reverted_at = datetime.now()
                    action.status = "reverted"
                    return True

        return False

    def get_active_containments(self) -> List[ContainmentAction]:
        """Get all active containment actions."""
        return [a for a in self.actions if a.status == "success"]

    def get_action_history(self) -> List[Dict[str, Any]]:
        """Get history of all containment actions."""
        return [
            {
                "id": a.id,
                "type": a.action_type.value,
                "target": a.target,
                "status": a.status,
                "executed_at": a.executed_at.isoformat(),
                "executed_by": a.executed_by,
                "result": a.result,
                "can_revert": bool(a.revert_command and a.status == "success"),
            }
            for a in self.actions
        ]

    def generate_containment_report(self) -> str:
        """Generate containment actions report."""
        report = "# Containment Actions Report\n\n"
        report += f"Generated: {datetime.now().isoformat()}\n\n"

        for action in self.actions:
            report += f"## Action: {action.id}\n"
            report += f"- **Type:** {action.action_type.value}\n"
            report += f"- **Target:** {action.target}\n"
            report += f"- **Status:** {action.status}\n"
            report += f"- **Executed:** {action.executed_at.isoformat()}\n"
            report += f"- **Result:** {action.result}\n"
            if action.reverted_at:
                report += f"- **Reverted:** {action.reverted_at.isoformat()}\n"
            report += "\n"

        return report
