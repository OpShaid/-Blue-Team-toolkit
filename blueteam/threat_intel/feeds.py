"""
Threat Intelligence Feeds - Manage and aggregate threat feeds.
"""

import hashlib
import re
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Set
from dataclasses import dataclass, field
import json

from blueteam.core.logger import get_logger
from blueteam.core.database import Database, IOC
from blueteam.core.utils import safe_request, validate_ip, validate_domain

logger = get_logger(__name__)


@dataclass
class ThreatFeed:
    """Represents a threat intelligence feed."""
    name: str
    url: str
    feed_type: str  # ip, domain, hash, url
    format: str  # txt, csv, json, stix
    enabled: bool = True
    update_interval: int = 3600  # seconds
    last_updated: Optional[datetime] = None
    entries_count: int = 0
    description: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    parser: Optional[str] = None  # Custom parser name


class ThreatFeedManager:
    """
    Manage threat intelligence feeds.

    Features:
    - Multiple feed sources
    - Automatic updates
    - Deduplication
    - IOC normalization
    - STIX/TAXII support
    """

    # Built-in free feeds
    DEFAULT_FEEDS = [
        ThreatFeed(
            name="abuse.ch URLhaus",
            url="https://urlhaus.abuse.ch/downloads/text_recent/",
            feed_type="url",
            format="txt",
            description="Recent malware URLs"
        ),
        ThreatFeed(
            name="abuse.ch Feodo Tracker",
            url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            feed_type="ip",
            format="txt",
            description="Feodo botnet C2 IPs"
        ),
        ThreatFeed(
            name="abuse.ch SSL Blacklist",
            url="https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
            feed_type="ip",
            format="txt",
            description="SSL certificate blacklist IPs"
        ),
        ThreatFeed(
            name="Blocklist.de All",
            url="https://lists.blocklist.de/lists/all.txt",
            feed_type="ip",
            format="txt",
            description="All attack IPs"
        ),
        ThreatFeed(
            name="C2 IntelFeed",
            url="https://osint.digitalside.it/Threat-Intel/lists/latestips.txt",
            feed_type="ip",
            format="txt",
            description="C2 server IPs"
        ),
        ThreatFeed(
            name="PhishTank",
            url="http://data.phishtank.com/data/online-valid.csv",
            feed_type="url",
            format="csv",
            description="Active phishing URLs"
        ),
        ThreatFeed(
            name="OpenPhish",
            url="https://openphish.com/feed.txt",
            feed_type="url",
            format="txt",
            description="OpenPhish phishing URLs"
        ),
        ThreatFeed(
            name="MalwareBazaar Hashes",
            url="https://bazaar.abuse.ch/export/txt/md5/recent/",
            feed_type="hash",
            format="txt",
            description="Recent malware MD5 hashes"
        ),
        ThreatFeed(
            name="Emergingthreats Compromised IPs",
            url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            feed_type="ip",
            format="txt",
            description="Compromised IP addresses"
        ),
        ThreatFeed(
            name="CINSscore Bad IPs",
            url="https://cinsscore.com/list/ci-badguys.txt",
            feed_type="ip",
            format="txt",
            description="CINS Army bad reputation IPs"
        ),
    ]

    def __init__(self, db: Database = None, cache_dir: str = "data/feeds"):
        self.db = db or Database()
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.feeds: Dict[str, ThreatFeed] = {}
        self.iocs: Dict[str, Set[str]] = {
            "ip": set(),
            "domain": set(),
            "url": set(),
            "hash": set(),
        }

        self._running = False
        self._update_thread = None
        self._callbacks: List[Callable[[str, str, str], None]] = []

        # Load default feeds
        for feed in self.DEFAULT_FEEDS:
            self.feeds[feed.name] = feed

    def add_feed(self, feed: ThreatFeed):
        """Add a new threat feed."""
        self.feeds[feed.name] = feed
        logger.info(f"Added feed: {feed.name}")

    def remove_feed(self, name: str):
        """Remove a threat feed."""
        if name in self.feeds:
            del self.feeds[name]

    def enable_feed(self, name: str, enabled: bool = True):
        """Enable or disable a feed."""
        if name in self.feeds:
            self.feeds[name].enabled = enabled

    def start_updates(self):
        """Start automatic feed updates."""
        if self._running:
            return

        self._running = True
        self._update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self._update_thread.start()
        logger.info("Started feed update service")

    def stop_updates(self):
        """Stop automatic updates."""
        self._running = False
        if self._update_thread:
            self._update_thread.join(timeout=5)

    def _update_loop(self):
        """Background update loop."""
        while self._running:
            for name, feed in self.feeds.items():
                if not feed.enabled:
                    continue

                # Check if update needed
                if feed.last_updated:
                    next_update = feed.last_updated + timedelta(seconds=feed.update_interval)
                    if datetime.now() < next_update:
                        continue

                try:
                    self.update_feed(name)
                except Exception as e:
                    logger.error(f"Failed to update feed {name}: {e}")

            time.sleep(60)  # Check every minute

    def update_feed(self, name: str) -> int:
        """Update a specific feed."""
        if name not in self.feeds:
            logger.warning(f"Feed not found: {name}")
            return 0

        feed = self.feeds[name]
        logger.info(f"Updating feed: {name}")

        try:
            response = safe_request(feed.url, headers=feed.headers, timeout=60)
            if not response or response.status_code != 200:
                logger.error(f"Failed to fetch feed {name}: {response.status_code if response else 'No response'}")
                return 0

            # Parse based on format
            if feed.format == "txt":
                count = self._parse_txt_feed(feed, response.text)
            elif feed.format == "csv":
                count = self._parse_csv_feed(feed, response.text)
            elif feed.format == "json":
                count = self._parse_json_feed(feed, response.text)
            else:
                count = self._parse_txt_feed(feed, response.text)

            feed.last_updated = datetime.now()
            feed.entries_count = count

            logger.info(f"Updated feed {name}: {count} entries")
            return count

        except Exception as e:
            logger.error(f"Error updating feed {name}: {e}")
            return 0

    def _parse_txt_feed(self, feed: ThreatFeed, content: str) -> int:
        """Parse text-based feed."""
        count = 0

        for line in content.split("\n"):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#") or line.startswith(";"):
                continue

            # Extract IOC
            ioc = self._extract_ioc(line, feed.feed_type)
            if ioc:
                self._add_ioc(ioc, feed.feed_type, feed.name)
                count += 1

        return count

    def _parse_csv_feed(self, feed: ThreatFeed, content: str) -> int:
        """Parse CSV feed."""
        import csv
        from io import StringIO

        count = 0
        reader = csv.reader(StringIO(content))

        # Skip header
        next(reader, None)

        for row in reader:
            if not row:
                continue

            # Try to find IOC in columns
            for cell in row:
                ioc = self._extract_ioc(cell, feed.feed_type)
                if ioc:
                    self._add_ioc(ioc, feed.feed_type, feed.name)
                    count += 1
                    break

        return count

    def _parse_json_feed(self, feed: ThreatFeed, content: str) -> int:
        """Parse JSON feed."""
        count = 0

        try:
            data = json.loads(content)

            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                # Try common keys
                for key in ["data", "items", "results", "indicators"]:
                    if key in data:
                        items = data[key]
                        break
                else:
                    items = [data]

            for item in items:
                if isinstance(item, str):
                    ioc = self._extract_ioc(item, feed.feed_type)
                elif isinstance(item, dict):
                    # Try common IOC keys
                    for key in ["indicator", "ioc", "value", "ip", "domain", "url", "hash", "md5", "sha256"]:
                        if key in item:
                            ioc = self._extract_ioc(str(item[key]), feed.feed_type)
                            break
                    else:
                        continue

                if ioc:
                    self._add_ioc(ioc, feed.feed_type, feed.name)
                    count += 1

        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")

        return count

    def _extract_ioc(self, text: str, ioc_type: str) -> Optional[str]:
        """Extract and validate IOC from text."""
        text = text.strip()

        if ioc_type == "ip":
            match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text)
            if match and validate_ip(match.group(1)):
                return match.group(1)

        elif ioc_type == "domain":
            match = re.search(r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b', text)
            if match:
                domain = match.group(0).lower()
                if validate_domain(domain):
                    return domain

        elif ioc_type == "url":
            match = re.search(r'(https?://[^\s<>"{}|\\^`\[\]]+)', text)
            if match:
                return match.group(1)

        elif ioc_type == "hash":
            # MD5
            match = re.search(r'\b([a-fA-F0-9]{32})\b', text)
            if match:
                return match.group(1).lower()
            # SHA1
            match = re.search(r'\b([a-fA-F0-9]{40})\b', text)
            if match:
                return match.group(1).lower()
            # SHA256
            match = re.search(r'\b([a-fA-F0-9]{64})\b', text)
            if match:
                return match.group(1).lower()

        return None

    def _add_ioc(self, value: str, ioc_type: str, source: str):
        """Add IOC to database and memory."""
        # Add to in-memory set
        self.iocs[ioc_type].add(value)

        # Add to database
        try:
            self.db.add_ioc(IOC(
                ioc_type=ioc_type,
                value=value,
                source=source,
                confidence=70,
            ))
        except Exception:
            pass

        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(value, ioc_type, source)
            except Exception:
                pass

    def on_ioc_added(self, callback: Callable[[str, str, str], None]):
        """Register callback for new IOCs."""
        self._callbacks.append(callback)

    def update_all(self) -> Dict[str, int]:
        """Update all enabled feeds."""
        results = {}
        for name, feed in self.feeds.items():
            if feed.enabled:
                results[name] = self.update_feed(name)
        return results

    def check_ioc(self, value: str, ioc_type: str = None) -> Optional[Dict[str, Any]]:
        """Check if value matches any known IOC."""
        # Auto-detect type
        if not ioc_type:
            if validate_ip(value):
                ioc_type = "ip"
            elif re.match(r'^[a-fA-F0-9]{32,64}$', value):
                ioc_type = "hash"
            elif value.startswith("http"):
                ioc_type = "url"
            else:
                ioc_type = "domain"

        value = value.lower()

        # Check in-memory first
        if value in self.iocs.get(ioc_type, set()):
            # Get details from database
            return self.db.check_ioc(value)

        # Check database
        return self.db.check_ioc(value)

    def check_batch(self, values: List[str], ioc_type: str = None) -> List[Dict[str, Any]]:
        """Check multiple values against IOC database."""
        results = []
        for value in values:
            result = self.check_ioc(value, ioc_type)
            if result:
                results.append(result)
        return results

    def search_iocs(
        self,
        pattern: str = None,
        ioc_type: str = None,
        source: str = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Search IOCs with filters."""
        return self.db.get_iocs(ioc_type=ioc_type, limit=limit)

    def get_statistics(self) -> Dict[str, Any]:
        """Get feed statistics."""
        return {
            "total_feeds": len(self.feeds),
            "enabled_feeds": sum(1 for f in self.feeds.values() if f.enabled),
            "iocs_in_memory": {
                ioc_type: len(iocs) for ioc_type, iocs in self.iocs.items()
            },
            "feeds": [
                {
                    "name": f.name,
                    "enabled": f.enabled,
                    "type": f.feed_type,
                    "entries": f.entries_count,
                    "last_updated": f.last_updated.isoformat() if f.last_updated else None,
                }
                for f in self.feeds.values()
            ]
        }

    def export_iocs(self, output_file: str, ioc_type: str = None):
        """Export IOCs to file."""
        from blueteam.core.utils import export_to_json

        iocs = self.db.get_iocs(ioc_type=ioc_type, limit=100000)
        export_to_json(iocs, output_file)
        logger.info(f"Exported {len(iocs)} IOCs to {output_file}")
