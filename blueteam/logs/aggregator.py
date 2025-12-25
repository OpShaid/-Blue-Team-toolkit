"""
Log Aggregator - Centralized log collection and storage.
"""

import os
import socket
import threading
import json
import time
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from queue import Queue, Empty
import socketserver

from blueteam.core.logger import get_logger
from blueteam.core.database import Database
from blueteam.logs.parser import LogParser, LogEntry

logger = get_logger(__name__)


class LogAggregator:
    """
    Centralized log aggregation service.

    Features:
    - Syslog receiver (UDP/TCP)
    - File tailing
    - Log buffering and batching
    - Real-time streaming
    - Index and search
    """

    def __init__(self, db: Database = None, buffer_size: int = 10000):
        self.db = db or Database()
        self.buffer_size = buffer_size
        self.buffer: deque = deque(maxlen=buffer_size)
        self.log_queue: Queue = Queue()

        self._running = False
        self._threads: List[threading.Thread] = []
        self._file_watchers: Dict[str, threading.Thread] = {}

        # Callbacks
        self.on_log_received: Optional[Callable[[LogEntry], None]] = None

        # Stats
        self.stats = {
            "total_received": 0,
            "by_source": {},
            "by_level": {},
        }

    def start(self):
        """Start the aggregator."""
        if self._running:
            return

        self._running = True

        # Start processor thread
        processor = threading.Thread(target=self._process_queue, daemon=True)
        processor.start()
        self._threads.append(processor)

        logger.info("Log aggregator started")

    def stop(self):
        """Stop the aggregator."""
        self._running = False

        for thread in self._threads:
            thread.join(timeout=2)

        for watcher in self._file_watchers.values():
            watcher.join(timeout=2)

        logger.info("Log aggregator stopped")

    def start_syslog_receiver(self, host: str = "0.0.0.0", port: int = 514, protocol: str = "udp"):
        """Start syslog receiver."""
        if protocol.lower() == "udp":
            receiver = threading.Thread(
                target=self._udp_receiver,
                args=(host, port),
                daemon=True
            )
        else:
            receiver = threading.Thread(
                target=self._tcp_receiver,
                args=(host, port),
                daemon=True
            )

        receiver.start()
        self._threads.append(receiver)
        logger.info(f"Started syslog receiver on {host}:{port}/{protocol}")

    def _udp_receiver(self, host: str, port: int):
        """UDP syslog receiver."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, port))
        sock.settimeout(1)

        parser = LogParser(format_name="syslog_bsd")

        while self._running:
            try:
                data, addr = sock.recvfrom(65536)
                message = data.decode("utf-8", errors="ignore")

                entry = parser.parse_line(message, source=f"syslog-{addr[0]}")
                if entry:
                    self._queue_entry(entry)

            except socket.timeout:
                continue
            except Exception as e:
                logger.debug(f"Syslog receive error: {e}")

        sock.close()

    def _tcp_receiver(self, host: str, port: int):
        """TCP syslog receiver."""

        class SyslogHandler(socketserver.StreamRequestHandler):
            aggregator = self

            def handle(self):
                parser = LogParser(format_name="syslog_bsd")
                while SyslogHandler.aggregator._running:
                    try:
                        line = self.rfile.readline()
                        if not line:
                            break
                        message = line.decode("utf-8", errors="ignore").strip()
                        entry = parser.parse_line(message, source=f"syslog-{self.client_address[0]}")
                        if entry:
                            SyslogHandler.aggregator._queue_entry(entry)
                    except Exception:
                        break

        server = socketserver.ThreadingTCPServer((host, port), SyslogHandler)
        server.timeout = 1

        while self._running:
            server.handle_request()

        server.server_close()

    def watch_file(self, file_path: str, format_name: str = None):
        """Watch a log file for new entries."""
        path = Path(file_path)

        if not path.exists():
            logger.warning(f"Log file not found: {file_path}")
            return

        if file_path in self._file_watchers:
            logger.warning(f"Already watching: {file_path}")
            return

        watcher = threading.Thread(
            target=self._tail_file,
            args=(file_path, format_name),
            daemon=True
        )
        watcher.start()
        self._file_watchers[file_path] = watcher
        logger.info(f"Started watching: {file_path}")

    def _tail_file(self, file_path: str, format_name: str):
        """Tail a file for new lines."""
        parser = LogParser(format_name=format_name)
        path = Path(file_path)

        # Start from end of file
        with open(path, "r") as f:
            f.seek(0, 2)  # End of file
            position = f.tell()

        while self._running:
            try:
                with open(path, "r") as f:
                    f.seek(position)

                    for line in f:
                        line = line.strip()
                        if line:
                            entry = parser.parse_line(line, source=path.name)
                            if entry:
                                self._queue_entry(entry)

                    position = f.tell()

                time.sleep(0.5)

            except Exception as e:
                logger.debug(f"File watch error for {file_path}: {e}")
                time.sleep(1)

    def _queue_entry(self, entry: LogEntry):
        """Add entry to processing queue."""
        self.log_queue.put(entry)
        self.stats["total_received"] += 1

    def _process_queue(self):
        """Process log entries from queue."""
        batch = []
        batch_size = 100
        last_flush = time.time()

        while self._running:
            try:
                entry = self.log_queue.get(timeout=1)
                batch.append(entry)

                # Flush on batch size or time
                if len(batch) >= batch_size or (time.time() - last_flush) > 5:
                    self._process_batch(batch)
                    batch = []
                    last_flush = time.time()

            except Empty:
                if batch:
                    self._process_batch(batch)
                    batch = []
                    last_flush = time.time()

        # Final flush
        if batch:
            self._process_batch(batch)

    def _process_batch(self, entries: List[LogEntry]):
        """Process a batch of log entries."""
        for entry in entries:
            # Add to buffer
            self.buffer.append(entry)

            # Update stats
            self.stats["by_source"][entry.source] = self.stats["by_source"].get(entry.source, 0) + 1
            self.stats["by_level"][entry.level] = self.stats["by_level"].get(entry.level, 0) + 1

            # Store in database
            try:
                self.db.add_event(
                    event_type="log",
                    severity=self._level_to_severity(entry.level),
                    description=entry.message[:500],
                    raw_data=entry.raw[:1000] if entry.raw else None,
                    tags=",".join(entry.tags) if entry.tags else None,
                )
            except Exception as e:
                logger.debug(f"Failed to store log entry: {e}")

            # Callback
            if self.on_log_received:
                try:
                    self.on_log_received(entry)
                except Exception as e:
                    logger.debug(f"Log callback error: {e}")

    def _level_to_severity(self, level: str) -> str:
        """Map log level to severity."""
        mapping = {
            "CRITICAL": "critical",
            "ERROR": "high",
            "WARN": "medium",
            "WARNING": "medium",
            "INFO": "low",
            "DEBUG": "low",
        }
        return mapping.get(level.upper(), "low")

    def add_entry(self, entry: LogEntry):
        """Manually add a log entry."""
        self._queue_entry(entry)

    def add_log(
        self,
        message: str,
        source: str = "manual",
        level: str = "INFO",
        timestamp: datetime = None
    ):
        """Add a log message directly."""
        entry = LogEntry(
            timestamp=timestamp or datetime.now(),
            source=source,
            level=level.upper(),
            message=message,
            raw=message,
        )
        self._queue_entry(entry)

    def search(
        self,
        query: str = None,
        level: str = None,
        source: str = None,
        start_time: datetime = None,
        end_time: datetime = None,
        limit: int = 100
    ) -> List[LogEntry]:
        """Search buffered log entries."""
        results = []
        import re
        pattern = re.compile(query, re.IGNORECASE) if query else None

        for entry in self.buffer:
            if len(results) >= limit:
                break

            if level and entry.level != level.upper():
                continue

            if source and source.lower() not in entry.source.lower():
                continue

            if start_time and entry.timestamp and entry.timestamp < start_time:
                continue

            if end_time and entry.timestamp and entry.timestamp > end_time:
                continue

            if pattern:
                if not pattern.search(entry.message) and not pattern.search(entry.raw):
                    continue

            results.append(entry)

        return results

    def get_recent(self, count: int = 100, level: str = None) -> List[LogEntry]:
        """Get most recent log entries."""
        entries = list(self.buffer)[-count:]

        if level:
            entries = [e for e in entries if e.level == level.upper()]

        return entries

    def get_stats(self) -> Dict[str, Any]:
        """Get aggregator statistics."""
        return {
            "total_received": self.stats["total_received"],
            "buffer_size": len(self.buffer),
            "buffer_capacity": self.buffer_size,
            "sources": dict(sorted(
                self.stats["by_source"].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            "by_level": self.stats["by_level"],
            "watching_files": list(self._file_watchers.keys()),
        }

    def export(self, output_file: str, format: str = "json"):
        """Export buffered logs."""
        from blueteam.core.utils import export_to_json, export_to_csv

        data = [
            {
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "source": e.source,
                "level": e.level,
                "message": e.message,
                "tags": e.tags,
            }
            for e in self.buffer
        ]

        if format == "json":
            export_to_json(data, output_file)
        else:
            export_to_csv(data, output_file)

        logger.info(f"Exported {len(data)} log entries to {output_file}")
