"""
IOC Manager - Manage and correlate Indicators of Compromise.
"""

import re
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict

from blueteam.core.logger import get_logger
from blueteam.core.database import Database, IOC
from blueteam.core.utils import (
    validate_ip, validate_domain, validate_url, validate_hash,
    extract_iocs, defang_ioc, refang_ioc
)

logger = get_logger(__name__)


@dataclass
class IOCMatch:
    """Represents a matched IOC."""
    ioc_type: str
    value: str
    original_value: str
    source: str
    confidence: int
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    tags: List[str]
    context: Dict[str, Any]


class IOCManager:
    """
    Comprehensive IOC management system.

    Features:
    - IOC extraction from text/files
    - IOC validation and normalization
    - Bulk import/export
    - IOC correlation
    - Tagging and categorization
    - STIX/MISP format support
    """

    # IOC type patterns
    PATTERNS = {
        "ipv4": re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
        "ipv6": re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
        "domain": re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
        "url": re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
        "email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
        "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
        "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
        "sha512": re.compile(r'\b[a-fA-F0-9]{128}\b'),
        "cve": re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE),
        "registry": re.compile(r'(?:HKEY_[A-Z_]+|HKLM|HKCU|HKU|HKCR|HKCC)\\[^\s]+'),
        "filepath_windows": re.compile(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*'),
        "filepath_unix": re.compile(r'(?:/[^/\s]+)+'),
    }

    # Common false positive patterns
    FALSE_POSITIVES = {
        "domain": {"example.com", "localhost", "test.com", "domain.com"},
        "ipv4": {"127.0.0.1", "0.0.0.0", "255.255.255.255"},
    }

    def __init__(self, db: Database = None):
        self.db = db or Database()
        self.iocs: Dict[str, Dict[str, IOC]] = defaultdict(dict)
        self.tags: Dict[str, Set[str]] = defaultdict(set)  # tag -> IOC values
        self.campaigns: Dict[str, Set[str]] = defaultdict(set)  # campaign -> IOC values

    def add_ioc(
        self,
        value: str,
        ioc_type: str = None,
        source: str = "manual",
        confidence: int = 50,
        tags: List[str] = None,
        description: str = None
    ) -> Optional[IOC]:
        """Add a single IOC."""
        # Auto-detect type
        if not ioc_type:
            ioc_type = self._detect_type(value)

        if not ioc_type:
            logger.warning(f"Could not determine IOC type for: {value}")
            return None

        # Normalize value
        value = self._normalize(value, ioc_type)

        if not value:
            return None

        # Check false positives
        if value in self.FALSE_POSITIVES.get(ioc_type, set()):
            logger.debug(f"Skipping false positive: {value}")
            return None

        # Create IOC
        ioc = IOC(
            ioc_type=ioc_type,
            value=value,
            source=source,
            confidence=confidence,
            tags=",".join(tags) if tags else None,
            description=description,
        )

        # Store in memory and database
        self.iocs[ioc_type][value] = ioc

        if tags:
            for tag in tags:
                self.tags[tag].add(value)

        try:
            self.db.add_ioc(ioc)
        except Exception as e:
            logger.debug(f"Failed to store IOC: {e}")

        return ioc

    def add_batch(self, iocs: List[Dict[str, Any]], source: str = "batch_import") -> int:
        """Add multiple IOCs."""
        count = 0
        for ioc_data in iocs:
            result = self.add_ioc(
                value=ioc_data.get("value", ""),
                ioc_type=ioc_data.get("type"),
                source=ioc_data.get("source", source),
                confidence=ioc_data.get("confidence", 50),
                tags=ioc_data.get("tags"),
                description=ioc_data.get("description"),
            )
            if result:
                count += 1
        return count

    def extract_from_text(self, text: str, source: str = "text_extraction") -> List[IOC]:
        """Extract IOCs from text."""
        # Refang first
        text = refang_ioc(text)

        extracted = []

        for ioc_type, pattern in self.PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(0)
                ioc = self.add_ioc(value, ioc_type=ioc_type, source=source)
                if ioc:
                    extracted.append(ioc)

        return extracted

    def extract_from_file(self, file_path: str, source: str = None) -> List[IOC]:
        """Extract IOCs from file."""
        path = Path(file_path)

        if not path.exists():
            logger.error(f"File not found: {file_path}")
            return []

        source = source or path.name

        try:
            content = path.read_text(errors="ignore")
            return self.extract_from_text(content, source)
        except Exception as e:
            logger.error(f"Error reading file: {e}")
            return []

    def _detect_type(self, value: str) -> Optional[str]:
        """Detect IOC type from value."""
        value = value.strip()

        # Check in order of specificity
        if re.match(r'^[a-fA-F0-9]{128}$', value):
            return "sha512"
        if re.match(r'^[a-fA-F0-9]{64}$', value):
            return "sha256"
        if re.match(r'^[a-fA-F0-9]{40}$', value):
            return "sha1"
        if re.match(r'^[a-fA-F0-9]{32}$', value):
            return "md5"
        if value.startswith("CVE-"):
            return "cve"
        if value.startswith(("http://", "https://", "hxxp://", "hxxps://")):
            return "url"
        if "@" in value and "." in value:
            return "email"
        if validate_ip(value):
            return "ipv4"
        if validate_domain(value):
            return "domain"
        if "\\" in value and ":" in value:
            return "filepath_windows"
        if value.startswith("/"):
            return "filepath_unix"

        return None

    def _normalize(self, value: str, ioc_type: str) -> Optional[str]:
        """Normalize IOC value."""
        value = value.strip()

        if ioc_type in ("md5", "sha1", "sha256", "sha512"):
            return value.lower()

        if ioc_type == "domain":
            value = value.lower()
            # Remove trailing dot
            value = value.rstrip(".")
            # Remove protocol if present
            value = re.sub(r'^https?://', '', value)
            return value

        if ioc_type == "url":
            # Refang
            value = refang_ioc(value)
            return value

        if ioc_type == "ipv4":
            if validate_ip(value):
                return value
            return None

        if ioc_type == "email":
            return value.lower()

        return value

    def check(self, value: str) -> Optional[IOCMatch]:
        """Check if value matches any known IOC."""
        value = value.strip().lower()
        ioc_type = self._detect_type(value)

        if ioc_type and value in self.iocs.get(ioc_type, {}):
            ioc = self.iocs[ioc_type][value]
            return IOCMatch(
                ioc_type=ioc_type,
                value=value,
                original_value=value,
                source=ioc.source,
                confidence=ioc.confidence,
                first_seen=datetime.fromisoformat(ioc.first_seen) if ioc.first_seen else None,
                last_seen=datetime.fromisoformat(ioc.last_seen) if ioc.last_seen else None,
                tags=ioc.tags.split(",") if ioc.tags else [],
                context={}
            )

        # Check database
        db_result = self.db.check_ioc(value)
        if db_result:
            return IOCMatch(
                ioc_type=db_result["ioc_type"],
                value=value,
                original_value=value,
                source=db_result["source"],
                confidence=db_result["confidence"],
                first_seen=datetime.fromisoformat(db_result["first_seen"]) if db_result.get("first_seen") else None,
                last_seen=datetime.fromisoformat(db_result["last_seen"]) if db_result.get("last_seen") else None,
                tags=db_result["tags"].split(",") if db_result.get("tags") else [],
                context={}
            )

        return None

    def check_batch(self, values: List[str]) -> List[IOCMatch]:
        """Check multiple values."""
        return [m for v in values if (m := self.check(v))]

    def search(
        self,
        pattern: str = None,
        ioc_type: str = None,
        tag: str = None,
        source: str = None,
        min_confidence: int = 0,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Search IOCs with filters."""
        results = []

        # Get from database
        db_results = self.db.get_iocs(ioc_type=ioc_type, limit=limit * 2)

        for ioc in db_results:
            if len(results) >= limit:
                break

            # Apply filters
            if min_confidence and ioc["confidence"] < min_confidence:
                continue

            if source and ioc.get("source") != source:
                continue

            if tag and tag not in (ioc.get("tags") or ""):
                continue

            if pattern:
                if not re.search(pattern, ioc["value"], re.IGNORECASE):
                    continue

            results.append(ioc)

        return results

    def get_by_tag(self, tag: str) -> List[str]:
        """Get all IOC values with a specific tag."""
        return list(self.tags.get(tag, set()))

    def add_tag(self, value: str, tag: str):
        """Add tag to an IOC."""
        self.tags[tag].add(value)

        for ioc_type, iocs in self.iocs.items():
            if value in iocs:
                existing_tags = iocs[value].tags or ""
                new_tags = set(existing_tags.split(",")) if existing_tags else set()
                new_tags.add(tag)
                iocs[value].tags = ",".join(new_tags)

    def link_to_campaign(self, value: str, campaign: str):
        """Link IOC to a campaign/threat actor."""
        self.campaigns[campaign].add(value)
        self.add_tag(value, f"campaign:{campaign}")

    def get_campaign_iocs(self, campaign: str) -> List[str]:
        """Get all IOCs for a campaign."""
        return list(self.campaigns.get(campaign, set()))

    def import_stix(self, file_path: str) -> int:
        """Import IOCs from STIX bundle."""
        try:
            with open(file_path) as f:
                data = json.load(f)

            count = 0
            objects = data.get("objects", [])

            for obj in objects:
                if obj.get("type") == "indicator":
                    pattern = obj.get("pattern", "")
                    # Parse STIX pattern
                    iocs = self._parse_stix_pattern(pattern)
                    for ioc_type, value in iocs:
                        result = self.add_ioc(
                            value=value,
                            ioc_type=ioc_type,
                            source=f"stix:{Path(file_path).name}",
                            confidence=70,
                        )
                        if result:
                            count += 1

            return count

        except Exception as e:
            logger.error(f"STIX import error: {e}")
            return 0

    def _parse_stix_pattern(self, pattern: str) -> List[tuple]:
        """Parse STIX pattern to extract IOCs."""
        iocs = []

        # Simple pattern parsing
        type_mapping = {
            "ipv4-addr:value": "ipv4",
            "domain-name:value": "domain",
            "url:value": "url",
            "file:hashes.MD5": "md5",
            "file:hashes.'SHA-1'": "sha1",
            "file:hashes.'SHA-256'": "sha256",
        }

        for stix_type, ioc_type in type_mapping.items():
            matches = re.findall(rf"\[{re.escape(stix_type)}\s*=\s*'([^']+)'\]", pattern)
            for match in matches:
                iocs.append((ioc_type, match))

        return iocs

    def export_stix(self, output_file: str, ioc_type: str = None):
        """Export IOCs as STIX bundle."""
        import uuid

        objects = []
        iocs = self.db.get_iocs(ioc_type=ioc_type, limit=10000)

        type_mapping = {
            "ipv4": "ipv4-addr",
            "domain": "domain-name",
            "url": "url",
            "md5": "file:hashes.MD5",
            "sha1": "file:hashes.'SHA-1'",
            "sha256": "file:hashes.'SHA-256'",
        }

        for ioc in iocs:
            stix_type = type_mapping.get(ioc["ioc_type"])
            if not stix_type:
                continue

            indicator = {
                "type": "indicator",
                "id": f"indicator--{uuid.uuid4()}",
                "created": ioc.get("first_seen", datetime.now().isoformat()),
                "modified": ioc.get("last_seen", datetime.now().isoformat()),
                "pattern": f"[{stix_type}:value = '{ioc['value']}']",
                "pattern_type": "stix",
                "valid_from": ioc.get("first_seen", datetime.now().isoformat()),
            }
            objects.append(indicator)

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects
        }

        with open(output_file, "w") as f:
            json.dump(bundle, f, indent=2)

        logger.info(f"Exported {len(objects)} IOCs to STIX format")

    def get_statistics(self) -> Dict[str, Any]:
        """Get IOC statistics."""
        type_counts = {}
        for ioc_type in self.iocs:
            type_counts[ioc_type] = len(self.iocs[ioc_type])

        return {
            "total_iocs": sum(type_counts.values()),
            "by_type": type_counts,
            "total_tags": len(self.tags),
            "total_campaigns": len(self.campaigns),
            "top_tags": sorted(
                [(tag, len(vals)) for tag, vals in self.tags.items()],
                key=lambda x: x[1],
                reverse=True
            )[:10],
        }
