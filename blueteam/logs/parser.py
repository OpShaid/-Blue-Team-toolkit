"""
Log Parser - Multi-format log parsing engine.
"""

import re
import json
import gzip
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Pattern
from dataclasses import dataclass, field

from blueteam.core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class LogEntry:
    """Represents a parsed log entry."""
    timestamp: Optional[datetime]
    source: str
    level: str
    message: str
    raw: str
    parsed: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


class LogParser:
    """
    Universal log parser supporting multiple formats.

    Supported formats:
    - Common Log Format (CLF)
    - Combined Log Format (Apache)
    - JSON logs
    - Syslog
    - Windows Event Log XML
    - Custom patterns via regex
    """

    # Pre-defined patterns
    PATTERNS = {
        "apache_common": re.compile(
            r'^(?P<ip>[\d.]+)\s+-\s+(?P<user>\S+)\s+'
            r'\[(?P<timestamp>[^\]]+)\]\s+'
            r'"(?P<method>\w+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
            r'(?P<status>\d+)\s+(?P<size>\d+|-)'
        ),
        "apache_combined": re.compile(
            r'^(?P<ip>[\d.]+)\s+-\s+(?P<user>\S+)\s+'
            r'\[(?P<timestamp>[^\]]+)\]\s+'
            r'"(?P<method>\w+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
            r'(?P<status>\d+)\s+(?P<size>\d+|-)\s+'
            r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
        ),
        "nginx": re.compile(
            r'^(?P<ip>[\d.]+)\s+-\s+(?P<user>\S+)\s+'
            r'\[(?P<timestamp>[^\]]+)\]\s+'
            r'"(?P<request>[^"]+)"\s+'
            r'(?P<status>\d+)\s+(?P<size>\d+)\s+'
            r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
        ),
        "syslog_bsd": re.compile(
            r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
            r'(?P<message>.*)$'
        ),
        "syslog_rfc5424": re.compile(
            r'^<(?P<priority>\d+)>(?P<version>\d+)\s+'
            r'(?P<timestamp>\S+)\s+(?P<host>\S+)\s+'
            r'(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+'
            r'(?P<structured>\[.*?\]|-)\s*(?P<message>.*)$'
        ),
        "auth_log": re.compile(
            r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<host>\S+)\s+(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
            r'(?P<message>.*)$'
        ),
        "windows_security": re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<level>\w+)\s+(?P<source>\S+)\s+(?P<event_id>\d+)\s+'
            r'(?P<message>.*)$'
        ),
    }

    # Timestamp formats
    TIMESTAMP_FORMATS = [
        "%d/%b/%Y:%H:%M:%S %z",  # Apache
        "%b %d %H:%M:%S",  # Syslog BSD
        "%Y-%m-%dT%H:%M:%S.%fZ",  # ISO 8601
        "%Y-%m-%dT%H:%M:%S%z",  # ISO 8601 with tz
        "%Y-%m-%d %H:%M:%S",  # Simple datetime
        "%Y/%m/%d %H:%M:%S",  # Alternative
    ]

    def __init__(self, format_name: str = None, custom_pattern: str = None):
        self.format_name = format_name
        self.custom_pattern = None

        if custom_pattern:
            self.custom_pattern = re.compile(custom_pattern)
        elif format_name and format_name in self.PATTERNS:
            self.custom_pattern = self.PATTERNS[format_name]

        self.stats = {
            "total_lines": 0,
            "parsed_lines": 0,
            "failed_lines": 0,
            "formats_detected": set(),
        }

    def parse_file(self, file_path: str) -> Generator[LogEntry, None, None]:
        """Parse a log file and yield entries."""
        path = Path(file_path)

        if not path.exists():
            logger.error(f"Log file not found: {file_path}")
            return

        # Handle gzipped files
        if path.suffix == ".gz":
            opener = gzip.open
        else:
            opener = open

        try:
            with opener(path, "rt", errors="ignore") as f:
                for line in f:
                    self.stats["total_lines"] += 1
                    line = line.strip()

                    if not line:
                        continue

                    entry = self.parse_line(line, source=str(path.name))
                    if entry:
                        self.stats["parsed_lines"] += 1
                        yield entry
                    else:
                        self.stats["failed_lines"] += 1

        except Exception as e:
            logger.error(f"Error parsing file {file_path}: {e}")

    def parse_line(self, line: str, source: str = "unknown") -> Optional[LogEntry]:
        """Parse a single log line."""
        # Try JSON first
        if line.startswith("{"):
            return self._parse_json(line, source)

        # Try custom pattern
        if self.custom_pattern:
            match = self.custom_pattern.match(line)
            if match:
                return self._create_entry(match.groupdict(), line, source, self.format_name)

        # Try all known patterns
        for format_name, pattern in self.PATTERNS.items():
            match = pattern.match(line)
            if match:
                self.stats["formats_detected"].add(format_name)
                return self._create_entry(match.groupdict(), line, source, format_name)

        # Fallback: basic parsing
        return self._parse_generic(line, source)

    def _parse_json(self, line: str, source: str) -> Optional[LogEntry]:
        """Parse JSON log line."""
        try:
            data = json.loads(line)

            # Extract common fields
            timestamp = None
            for ts_field in ["timestamp", "time", "@timestamp", "datetime", "date"]:
                if ts_field in data:
                    timestamp = self._parse_timestamp(str(data[ts_field]))
                    break

            level = data.get("level", data.get("severity", data.get("log_level", "INFO")))
            message = data.get("message", data.get("msg", data.get("log", str(data))))

            return LogEntry(
                timestamp=timestamp,
                source=source,
                level=str(level).upper(),
                message=str(message),
                raw=line,
                parsed=data,
                tags=["json"]
            )
        except json.JSONDecodeError:
            return None

    def _create_entry(
        self,
        parsed: Dict[str, Any],
        raw: str,
        source: str,
        format_name: str
    ) -> LogEntry:
        """Create LogEntry from parsed data."""
        # Parse timestamp
        timestamp = None
        if "timestamp" in parsed:
            timestamp = self._parse_timestamp(parsed["timestamp"])

        # Determine level
        level = parsed.get("level", "INFO")
        if "status" in parsed:
            status = int(parsed["status"]) if parsed["status"].isdigit() else 0
            if status >= 500:
                level = "ERROR"
            elif status >= 400:
                level = "WARNING"

        # Build message
        if "message" in parsed:
            message = parsed["message"]
        elif "method" in parsed and "path" in parsed:
            message = f"{parsed['method']} {parsed['path']} - {parsed.get('status', 'N/A')}"
        else:
            message = raw

        return LogEntry(
            timestamp=timestamp,
            source=source,
            level=level.upper(),
            message=message,
            raw=raw,
            parsed=parsed,
            tags=[format_name]
        )

    def _parse_generic(self, line: str, source: str) -> LogEntry:
        """Generic parsing for unknown formats."""
        timestamp = None
        level = "INFO"

        # Try to extract timestamp from beginning
        timestamp_patterns = [
            r'^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})',
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
            r'^\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}[^\]]+)\]',
        ]

        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                timestamp = self._parse_timestamp(match.group(1))
                break

        # Try to detect level
        for lvl in ["CRITICAL", "ERROR", "WARN", "WARNING", "INFO", "DEBUG"]:
            if lvl in line.upper():
                level = lvl
                break

        return LogEntry(
            timestamp=timestamp,
            source=source,
            level=level,
            message=line,
            raw=line,
            parsed={},
            tags=["generic"]
        )

    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse timestamp string."""
        if not ts_str:
            return None

        for fmt in self.TIMESTAMP_FORMATS:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue

        # Try ISO format
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except ValueError:
            pass

        return None

    def get_stats(self) -> Dict[str, Any]:
        """Get parsing statistics."""
        return {
            **self.stats,
            "formats_detected": list(self.stats["formats_detected"]),
            "success_rate": (
                self.stats["parsed_lines"] / self.stats["total_lines"]
                if self.stats["total_lines"] > 0 else 0
            ),
        }


class MultiLogParser:
    """Parse multiple log files with different formats."""

    def __init__(self):
        self.parsers: Dict[str, LogParser] = {}
        self.entries: List[LogEntry] = []

    def add_source(self, name: str, file_path: str, format_name: str = None):
        """Add a log source."""
        parser = LogParser(format_name=format_name)
        self.parsers[name] = (parser, file_path)

    def parse_all(self) -> Generator[LogEntry, None, None]:
        """Parse all configured sources."""
        for name, (parser, file_path) in self.parsers.items():
            logger.info(f"Parsing {name}: {file_path}")
            for entry in parser.parse_file(file_path):
                entry.tags.append(f"source:{name}")
                yield entry

    def search(
        self,
        pattern: str = None,
        level: str = None,
        start_time: datetime = None,
        end_time: datetime = None,
        source: str = None,
        limit: int = 100
    ) -> List[LogEntry]:
        """Search through parsed entries."""
        results = []
        regex = re.compile(pattern, re.IGNORECASE) if pattern else None

        for entry in self.entries:
            if len(results) >= limit:
                break

            if level and entry.level != level.upper():
                continue

            if source and source not in entry.source:
                continue

            if start_time and entry.timestamp and entry.timestamp < start_time:
                continue

            if end_time and entry.timestamp and entry.timestamp > end_time:
                continue

            if regex and not regex.search(entry.message) and not regex.search(entry.raw):
                continue

            results.append(entry)

        return results
