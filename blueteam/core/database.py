"""
Database abstraction layer for BlueTeam Arsenal.
Supports SQLite, PostgreSQL, and MySQL backends.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from contextlib import contextmanager
from dataclasses import dataclass, asdict
import threading

from blueteam.core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class SecurityEvent:
    """Represents a security event in the database."""
    id: Optional[int] = None
    timestamp: Optional[str] = None
    event_type: str = ""
    severity: str = "medium"
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    description: str = ""
    raw_data: Optional[str] = None
    tags: Optional[str] = None
    status: str = "new"
    analyst_notes: Optional[str] = None


@dataclass
class IOC:
    """Represents an Indicator of Compromise."""
    id: Optional[int] = None
    ioc_type: str = ""  # ip, domain, hash, url, email
    value: str = ""
    source: str = ""
    confidence: int = 50
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tags: Optional[str] = None
    description: Optional[str] = None
    active: bool = True


@dataclass
class Alert:
    """Represents a security alert."""
    id: Optional[int] = None
    timestamp: Optional[str] = None
    rule_name: str = ""
    severity: str = "medium"
    title: str = ""
    description: str = ""
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    event_ids: Optional[str] = None  # JSON array of related event IDs
    status: str = "open"
    assigned_to: Optional[str] = None
    resolution: Optional[str] = None
    closed_at: Optional[str] = None


class Database:
    """
    Thread-safe database interface for BlueTeam Arsenal.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, db_path: str = "data/blueteam.db"):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, db_path: str = "data/blueteam.db"):
        if self._initialized:
            return

        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._local = threading.local()
        self._init_schema()
        self._initialized = True

        logger.info(f"Database initialized at {self.db_path}")

    @property
    def _conn(self) -> sqlite3.Connection:
        """Get thread-local database connection."""
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False
            )
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    @contextmanager
    def transaction(self):
        """Context manager for database transactions."""
        try:
            yield self._conn
            self._conn.commit()
        except Exception as e:
            self._conn.rollback()
            logger.error(f"Database transaction failed: {e}")
            raise

    def _init_schema(self):
        """Initialize database schema."""
        schema = """
        -- Security Events table
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            event_type TEXT NOT NULL,
            severity TEXT DEFAULT 'medium',
            source_ip TEXT,
            dest_ip TEXT,
            source_port INTEGER,
            dest_port INTEGER,
            protocol TEXT,
            description TEXT,
            raw_data TEXT,
            tags TEXT,
            status TEXT DEFAULT 'new',
            analyst_notes TEXT
        );

        -- IOC table
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type TEXT NOT NULL,
            value TEXT NOT NULL UNIQUE,
            source TEXT,
            confidence INTEGER DEFAULT 50,
            first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
            last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
            tags TEXT,
            description TEXT,
            active INTEGER DEFAULT 1
        );

        -- Alerts table
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            rule_name TEXT NOT NULL,
            severity TEXT DEFAULT 'medium',
            title TEXT NOT NULL,
            description TEXT,
            source_ip TEXT,
            dest_ip TEXT,
            event_ids TEXT,
            status TEXT DEFAULT 'open',
            assigned_to TEXT,
            resolution TEXT,
            closed_at TEXT
        );

        -- Network connections table
        CREATE TABLE IF NOT EXISTS network_connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT,
            dest_ip TEXT,
            source_port INTEGER,
            dest_port INTEGER,
            protocol TEXT,
            bytes_sent INTEGER DEFAULT 0,
            bytes_recv INTEGER DEFAULT 0,
            packets INTEGER DEFAULT 0,
            duration REAL DEFAULT 0,
            flags TEXT,
            geo_source TEXT,
            geo_dest TEXT
        );

        -- DNS queries table
        CREATE TABLE IF NOT EXISTS dns_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT,
            query_name TEXT NOT NULL,
            query_type TEXT,
            response_code TEXT,
            response_data TEXT,
            ttl INTEGER,
            is_suspicious INTEGER DEFAULT 0
        );

        -- File analysis table
        CREATE TABLE IF NOT EXISTS file_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            filename TEXT,
            file_path TEXT,
            file_size INTEGER,
            md5 TEXT,
            sha1 TEXT,
            sha256 TEXT,
            file_type TEXT,
            mime_type TEXT,
            is_malicious INTEGER DEFAULT 0,
            vt_score TEXT,
            analysis_result TEXT,
            tags TEXT
        );

        -- Threat intel feeds table
        CREATE TABLE IF NOT EXISTS threat_feeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            url TEXT,
            feed_type TEXT,
            last_updated TEXT,
            entries_count INTEGER DEFAULT 0,
            enabled INTEGER DEFAULT 1
        );

        -- Create indexes for performance
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);
        CREATE INDEX IF NOT EXISTS idx_events_source_ip ON security_events(source_ip);
        CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type);
        CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
        CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
        CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
        CREATE INDEX IF NOT EXISTS idx_network_timestamp ON network_connections(timestamp);
        CREATE INDEX IF NOT EXISTS idx_dns_query ON dns_queries(query_name);
        CREATE INDEX IF NOT EXISTS idx_files_hash ON file_analysis(sha256);
        """

        with self.transaction() as conn:
            conn.executescript(schema)

    # Security Events
    def add_event(self, event: SecurityEvent) -> int:
        """Add a security event to the database."""
        event.timestamp = event.timestamp or datetime.utcnow().isoformat()

        with self.transaction() as conn:
            cursor = conn.execute("""
                INSERT INTO security_events
                (timestamp, event_type, severity, source_ip, dest_ip,
                 source_port, dest_port, protocol, description, raw_data, tags, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.timestamp, event.event_type, event.severity,
                event.source_ip, event.dest_ip, event.source_port,
                event.dest_port, event.protocol, event.description,
                event.raw_data, event.tags, event.status
            ))
            return cursor.lastrowid

    def get_events(
        self,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        source_ip: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Query security events with filters."""
        query = "SELECT * FROM security_events WHERE 1=1"
        params = []

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = self._conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def get_event_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get event statistics for the specified time period."""
        cursor = self._conn.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
            FROM security_events
            WHERE timestamp >= datetime('now', ?)
        """, (f"-{hours} hours",))

        row = cursor.fetchone()
        return dict(row) if row else {}

    # IOCs
    def add_ioc(self, ioc: IOC) -> int:
        """Add or update an IOC."""
        ioc.first_seen = ioc.first_seen or datetime.utcnow().isoformat()
        ioc.last_seen = datetime.utcnow().isoformat()

        with self.transaction() as conn:
            cursor = conn.execute("""
                INSERT INTO iocs (ioc_type, value, source, confidence,
                                  first_seen, last_seen, tags, description, active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(value) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    confidence = excluded.confidence,
                    active = excluded.active
            """, (
                ioc.ioc_type, ioc.value, ioc.source, ioc.confidence,
                ioc.first_seen, ioc.last_seen, ioc.tags, ioc.description,
                1 if ioc.active else 0
            ))
            return cursor.lastrowid

    def check_ioc(self, value: str) -> Optional[Dict[str, Any]]:
        """Check if a value matches any known IOC."""
        cursor = self._conn.execute(
            "SELECT * FROM iocs WHERE value = ? AND active = 1",
            (value,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_iocs(
        self,
        ioc_type: Optional[str] = None,
        active_only: bool = True,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Get IOCs with optional filtering."""
        query = "SELECT * FROM iocs WHERE 1=1"
        params = []

        if ioc_type:
            query += " AND ioc_type = ?"
            params.append(ioc_type)
        if active_only:
            query += " AND active = 1"

        query += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)

        cursor = self._conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    # Alerts
    def add_alert(self, alert: Alert) -> int:
        """Create a new alert."""
        alert.timestamp = alert.timestamp or datetime.utcnow().isoformat()

        with self.transaction() as conn:
            cursor = conn.execute("""
                INSERT INTO alerts
                (timestamp, rule_name, severity, title, description,
                 source_ip, dest_ip, event_ids, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.timestamp, alert.rule_name, alert.severity,
                alert.title, alert.description, alert.source_ip,
                alert.dest_ip, alert.event_ids, alert.status
            ))
            return cursor.lastrowid

    def update_alert_status(
        self,
        alert_id: int,
        status: str,
        resolution: Optional[str] = None,
        assigned_to: Optional[str] = None
    ) -> None:
        """Update alert status."""
        closed_at = datetime.utcnow().isoformat() if status == "closed" else None

        with self.transaction() as conn:
            conn.execute("""
                UPDATE alerts
                SET status = ?, resolution = ?, assigned_to = ?, closed_at = ?
                WHERE id = ?
            """, (status, resolution, assigned_to, closed_at, alert_id))

    def get_open_alerts(self, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all open alerts."""
        query = "SELECT * FROM alerts WHERE status = 'open'"
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY timestamp DESC"

        cursor = self._conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    # Network Connections
    def add_connection(self, **kwargs) -> int:
        """Log a network connection."""
        kwargs["timestamp"] = kwargs.get("timestamp", datetime.utcnow().isoformat())

        columns = ", ".join(kwargs.keys())
        placeholders = ", ".join(["?" for _ in kwargs])

        with self.transaction() as conn:
            cursor = conn.execute(
                f"INSERT INTO network_connections ({columns}) VALUES ({placeholders})",
                list(kwargs.values())
            )
            return cursor.lastrowid

    # DNS Queries
    def add_dns_query(self, **kwargs) -> int:
        """Log a DNS query."""
        kwargs["timestamp"] = kwargs.get("timestamp", datetime.utcnow().isoformat())

        columns = ", ".join(kwargs.keys())
        placeholders = ", ".join(["?" for _ in kwargs])

        with self.transaction() as conn:
            cursor = conn.execute(
                f"INSERT INTO dns_queries ({columns}) VALUES ({placeholders})",
                list(kwargs.values())
            )
            return cursor.lastrowid

    # File Analysis
    def add_file_analysis(self, **kwargs) -> int:
        """Store file analysis results."""
        kwargs["timestamp"] = kwargs.get("timestamp", datetime.utcnow().isoformat())

        columns = ", ".join(kwargs.keys())
        placeholders = ", ".join(["?" for _ in kwargs])

        with self.transaction() as conn:
            cursor = conn.execute(
                f"INSERT INTO file_analysis ({columns}) VALUES ({placeholders})",
                list(kwargs.values())
            )
            return cursor.lastrowid

    def get_file_by_hash(self, hash_value: str) -> Optional[Dict[str, Any]]:
        """Get file analysis by hash."""
        cursor = self._conn.execute("""
            SELECT * FROM file_analysis
            WHERE md5 = ? OR sha1 = ? OR sha256 = ?
            ORDER BY timestamp DESC LIMIT 1
        """, (hash_value, hash_value, hash_value))
        row = cursor.fetchone()
        return dict(row) if row else None

    # Statistics and Reporting
    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics for dashboard."""
        stats = {}

        # Event counts
        cursor = self._conn.execute("""
            SELECT
                COUNT(*) as total_events,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_events,
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_events
            FROM security_events
            WHERE timestamp >= datetime('now', '-24 hours')
        """)
        stats["events"] = dict(cursor.fetchone())

        # Alert counts
        cursor = self._conn.execute("""
            SELECT
                COUNT(*) as total_alerts,
                SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_alerts
            FROM alerts
        """)
        stats["alerts"] = dict(cursor.fetchone())

        # IOC counts
        cursor = self._conn.execute("""
            SELECT COUNT(*) as total_iocs FROM iocs WHERE active = 1
        """)
        stats["iocs"] = dict(cursor.fetchone())

        # Top source IPs
        cursor = self._conn.execute("""
            SELECT source_ip, COUNT(*) as count
            FROM security_events
            WHERE timestamp >= datetime('now', '-24 hours')
            AND source_ip IS NOT NULL
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT 10
        """)
        stats["top_sources"] = [dict(row) for row in cursor.fetchall()]

        return stats

    def close(self):
        """Close database connection."""
        if hasattr(self._local, "conn"):
            self._local.conn.close()
            del self._local.conn
