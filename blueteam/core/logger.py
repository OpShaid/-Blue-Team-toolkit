"""
Logging configuration for BlueTeam Arsenal.
Provides structured logging with support for multiple outputs.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
import json


class JSONFormatter(logging.Formatter):
    """Format log records as JSON for easy parsing."""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        if hasattr(record, "extra_data"):
            log_data["data"] = record.extra_data

        return json.dumps(log_data)


class ColoredFormatter(logging.Formatter):
    """Colored console output for better readability."""

    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)

        # Format timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Build the message
        level_display = f"{color}{self.BOLD}[{record.levelname:^8}]{self.RESET}"
        logger_display = f"\033[90m{record.name}\033[0m"

        formatted = f"{timestamp} {level_display} {logger_display}: {record.getMessage()}"

        if record.exc_info:
            formatted += f"\n{self.formatException(record.exc_info)}"

        return formatted


class SecurityLogger(logging.Logger):
    """
    Extended logger with security-specific methods.
    """

    def security_event(
        self,
        event_type: str,
        severity: str,
        message: str,
        source_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
        **kwargs
    ):
        """Log a security event with structured data."""
        extra_data = {
            "event_type": event_type,
            "severity": severity,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            **kwargs
        }

        # Map severity to log level
        level_map = {
            "low": logging.INFO,
            "medium": logging.WARNING,
            "high": logging.ERROR,
            "critical": logging.CRITICAL,
        }
        level = level_map.get(severity.lower(), logging.WARNING)

        record = self.makeRecord(
            self.name,
            level,
            "(security)",
            0,
            message,
            (),
            None
        )
        record.extra_data = extra_data
        self.handle(record)

    def alert(self, message: str, **kwargs):
        """Log an alert that may trigger notifications."""
        self.security_event("alert", "high", message, **kwargs)

    def incident(self, message: str, **kwargs):
        """Log an incident for investigation."""
        self.security_event("incident", "high", message, **kwargs)

    def ioc_detected(self, ioc_type: str, ioc_value: str, **kwargs):
        """Log detection of an Indicator of Compromise."""
        self.security_event(
            "ioc_detection",
            "high",
            f"IOC Detected: {ioc_type} = {ioc_value}",
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            **kwargs
        )


# Register our custom logger class
logging.setLoggerClass(SecurityLogger)


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    json_format: bool = False,
    max_size: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
) -> None:
    """
    Set up logging for the application.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file
        json_format: Use JSON format for file logs
        max_size: Max size of log file before rotation
        backup_count: Number of backup files to keep
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))

    # Clear existing handlers
    root_logger.handlers.clear()

    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(ColoredFormatter())
    root_logger.addHandler(console_handler)

    # File handler if specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_size,
            backupCount=backup_count
        )

        if json_format:
            file_handler.setFormatter(JSONFormatter())
        else:
            file_handler.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            ))

        root_logger.addHandler(file_handler)

    # Security events log (always JSON)
    security_log = Path("logs/security_events.json")
    security_log.parent.mkdir(parents=True, exist_ok=True)

    security_handler = TimedRotatingFileHandler(
        security_log,
        when="midnight",
        backupCount=30
    )
    security_handler.setFormatter(JSONFormatter())
    security_handler.setLevel(logging.WARNING)

    # Only add to security-related loggers
    security_logger = logging.getLogger("blueteam.security")
    security_logger.addHandler(security_handler)


def get_logger(name: str) -> SecurityLogger:
    """Get a logger instance with the given name."""
    return logging.getLogger(name)
