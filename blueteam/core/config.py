"""
Configuration management for BlueTeam Arsenal.
Handles loading, validation, and access to configuration settings.
"""

import os
import json
import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class DatabaseConfig:
    """Database configuration settings."""
    type: str = "sqlite"
    path: str = "data/blueteam.db"
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    database: Optional[str] = None


@dataclass
class APIKeysConfig:
    """API keys for threat intelligence services."""
    virustotal: Optional[str] = None
    abuseipdb: Optional[str] = None
    shodan: Optional[str] = None
    alienvault_otx: Optional[str] = None
    hybrid_analysis: Optional[str] = None
    urlscan: Optional[str] = None
    greynoise: Optional[str] = None


@dataclass
class NetworkConfig:
    """Network monitoring configuration."""
    interface: str = "eth0"
    capture_filter: str = ""
    promiscuous: bool = True
    buffer_size: int = 65536
    timeout: int = 1000


@dataclass
class AlertConfig:
    """Alerting configuration."""
    enabled: bool = True
    email_enabled: bool = False
    slack_enabled: bool = False
    webhook_enabled: bool = False
    email_recipients: list = field(default_factory=list)
    slack_webhook: Optional[str] = None
    custom_webhook: Optional[str] = None
    severity_threshold: str = "medium"


@dataclass
class DashboardConfig:
    """Dashboard configuration."""
    host: str = "127.0.0.1"
    port: int = 5000
    debug: bool = False
    secret_key: Optional[str] = None
    enable_auth: bool = True
    session_timeout: int = 3600


class Config:
    """
    Central configuration manager for BlueTeam Arsenal.

    Supports loading from:
    - YAML configuration files
    - JSON configuration files
    - Environment variables
    - Programmatic configuration
    """

    _instance = None
    _config_file: Optional[Path] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self.database = DatabaseConfig()
        self.api_keys = APIKeysConfig()
        self.network = NetworkConfig()
        self.alerts = AlertConfig()
        self.dashboard = DashboardConfig()

        # Custom settings storage
        self._custom: Dict[str, Any] = {}

        # Try to load default config
        self._load_default_config()
        self._load_env_variables()

        self._initialized = True

    def _load_default_config(self):
        """Load configuration from default locations."""
        default_paths = [
            Path("config.yaml"),
            Path("config.yml"),
            Path("config.json"),
            Path.home() / ".blueteam" / "config.yaml",
            Path("/etc/blueteam/config.yaml"),
        ]

        for path in default_paths:
            if path.exists():
                self.load_file(path)
                break

    def _load_env_variables(self):
        """Load configuration from environment variables."""
        env_mappings = {
            "BLUETEAM_VT_API_KEY": ("api_keys", "virustotal"),
            "BLUETEAM_ABUSEIPDB_KEY": ("api_keys", "abuseipdb"),
            "BLUETEAM_SHODAN_KEY": ("api_keys", "shodan"),
            "BLUETEAM_OTX_KEY": ("api_keys", "alienvault_otx"),
            "BLUETEAM_HYBRID_KEY": ("api_keys", "hybrid_analysis"),
            "BLUETEAM_URLSCAN_KEY": ("api_keys", "urlscan"),
            "BLUETEAM_GREYNOISE_KEY": ("api_keys", "greynoise"),
            "BLUETEAM_DB_TYPE": ("database", "type"),
            "BLUETEAM_DB_PATH": ("database", "path"),
            "BLUETEAM_DB_HOST": ("database", "host"),
            "BLUETEAM_DB_PORT": ("database", "port"),
            "BLUETEAM_DASHBOARD_HOST": ("dashboard", "host"),
            "BLUETEAM_DASHBOARD_PORT": ("dashboard", "port"),
            "BLUETEAM_NETWORK_INTERFACE": ("network", "interface"),
        }

        for env_var, (section, key) in env_mappings.items():
            value = os.environ.get(env_var)
            if value:
                self.set(section, key, value)

    def load_file(self, path: Path) -> None:
        """Load configuration from a file."""
        path = Path(path)
        self._config_file = path

        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        content = path.read_text()

        if path.suffix in (".yaml", ".yml"):
            data = yaml.safe_load(content)
        elif path.suffix == ".json":
            data = json.loads(content)
        else:
            raise ValueError(f"Unsupported configuration format: {path.suffix}")

        self._apply_config(data)

    def _apply_config(self, data: Dict[str, Any]) -> None:
        """Apply configuration dictionary to settings."""
        if not data:
            return

        if "database" in data:
            for key, value in data["database"].items():
                if hasattr(self.database, key):
                    setattr(self.database, key, value)

        if "api_keys" in data:
            for key, value in data["api_keys"].items():
                if hasattr(self.api_keys, key):
                    setattr(self.api_keys, key, value)

        if "network" in data:
            for key, value in data["network"].items():
                if hasattr(self.network, key):
                    setattr(self.network, key, value)

        if "alerts" in data:
            for key, value in data["alerts"].items():
                if hasattr(self.alerts, key):
                    setattr(self.alerts, key, value)

        if "dashboard" in data:
            for key, value in data["dashboard"].items():
                if hasattr(self.dashboard, key):
                    setattr(self.dashboard, key, value)

        # Store any custom settings
        for key, value in data.items():
            if key not in ("database", "api_keys", "network", "alerts", "dashboard"):
                self._custom[key] = value

    def set(self, section: str, key: str, value: Any) -> None:
        """Set a configuration value."""
        section_obj = getattr(self, section, None)
        if section_obj and hasattr(section_obj, key):
            # Handle type conversion for port numbers
            if key == "port" and isinstance(value, str):
                value = int(value)
            setattr(section_obj, key, value)
        else:
            if section not in self._custom:
                self._custom[section] = {}
            self._custom[section][key] = value

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        section_obj = getattr(self, section, None)
        if section_obj and hasattr(section_obj, key):
            return getattr(section_obj, key)
        return self._custom.get(section, {}).get(key, default)

    def to_dict(self) -> Dict[str, Any]:
        """Export configuration as dictionary."""
        return {
            "database": {
                "type": self.database.type,
                "path": self.database.path,
                "host": self.database.host,
                "port": self.database.port,
            },
            "api_keys": {
                "virustotal": "***" if self.api_keys.virustotal else None,
                "abuseipdb": "***" if self.api_keys.abuseipdb else None,
                "shodan": "***" if self.api_keys.shodan else None,
            },
            "network": {
                "interface": self.network.interface,
                "promiscuous": self.network.promiscuous,
            },
            "alerts": {
                "enabled": self.alerts.enabled,
                "severity_threshold": self.alerts.severity_threshold,
            },
            "dashboard": {
                "host": self.dashboard.host,
                "port": self.dashboard.port,
            },
            "custom": self._custom,
        }

    def save(self, path: Optional[Path] = None) -> None:
        """Save current configuration to file."""
        path = Path(path) if path else self._config_file
        if not path:
            path = Path("config.yaml")

        data = {
            "database": vars(self.database),
            "api_keys": vars(self.api_keys),
            "network": vars(self.network),
            "alerts": vars(self.alerts),
            "dashboard": vars(self.dashboard),
            **self._custom,
        }

        # Convert lists properly
        if "email_recipients" in data.get("alerts", {}):
            data["alerts"]["email_recipients"] = list(data["alerts"]["email_recipients"])

        path.parent.mkdir(parents=True, exist_ok=True)

        if path.suffix in (".yaml", ".yml"):
            content = yaml.dump(data, default_flow_style=False, sort_keys=False)
        else:
            content = json.dumps(data, indent=2)

        path.write_text(content)


def get_config() -> Config:
    """Get the global configuration instance."""
    return Config()
