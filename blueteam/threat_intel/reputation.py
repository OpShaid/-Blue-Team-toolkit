"""
Reputation Checker - Quick reputation checks for IOCs.
"""

import socket
import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

from blueteam.core.logger import get_logger
from blueteam.core.database import Database
from blueteam.core.utils import safe_request, validate_ip, validate_domain, is_private_ip

logger = get_logger(__name__)


@dataclass
class ReputationResult:
    """Result of reputation check."""
    ioc: str
    ioc_type: str
    reputation: str  # clean, suspicious, malicious, unknown
    score: int  # 0-100 (higher = worse)
    sources_checked: int
    malicious_sources: int
    details: Dict[str, Any]


class ReputationChecker:
    """
    Quick reputation checking for IOCs.

    Features:
    - DNS-based blacklist checking
    - Local IOC database lookup
    - Multiple reputation sources
    - Caching for performance
    """

    # DNS-based blacklists for IP reputation
    IP_BLACKLISTS = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "b.barracudacentral.org",
        "dnsbl.sorbs.net",
        "spam.dnsbl.sorbs.net",
        "cbl.abuseat.org",
        "dnsbl-1.uceprotect.net",
    ]

    # Domain blacklists
    DOMAIN_BLACKLISTS = [
        "dbl.spamhaus.org",
        "multi.surbl.org",
        "black.uribl.com",
    ]

    def __init__(self, db: Database = None):
        self.db = db or Database()
        self.cache: Dict[str, ReputationResult] = {}
        self.cache_ttl = 300  # 5 minutes

        # Statistics
        self.stats = {
            "checks": 0,
            "cache_hits": 0,
            "malicious_found": 0,
        }

    def check(self, ioc: str) -> ReputationResult:
        """Check reputation of an IOC."""
        self.stats["checks"] += 1

        # Check cache
        if ioc in self.cache:
            result = self.cache[ioc]
            age = (datetime.now() - result.details.get("timestamp", datetime.now())).seconds
            if age < self.cache_ttl:
                self.stats["cache_hits"] += 1
                return result

        # Determine type and check
        if validate_ip(ioc):
            result = self._check_ip(ioc)
        elif validate_domain(ioc):
            result = self._check_domain(ioc)
        elif ioc.startswith("http"):
            result = self._check_url(ioc)
        else:
            result = self._check_hash(ioc)

        # Update cache and stats
        self.cache[ioc] = result
        if result.reputation == "malicious":
            self.stats["malicious_found"] += 1

        return result

    def check_batch(self, iocs: List[str]) -> Dict[str, ReputationResult]:
        """Check multiple IOCs."""
        results = {}
        for ioc in iocs:
            results[ioc] = self.check(ioc)
        return results

    def _check_ip(self, ip: str) -> ReputationResult:
        """Check IP reputation."""
        result = ReputationResult(
            ioc=ip,
            ioc_type="ip",
            reputation="unknown",
            score=0,
            sources_checked=0,
            malicious_sources=0,
            details={"timestamp": datetime.now(), "blacklists": []}
        )

        # Skip private IPs
        if is_private_ip(ip):
            result.reputation = "clean"
            result.details["note"] = "Private IP address"
            return result

        # Check local database first
        db_result = self.db.check_ioc(ip)
        if db_result:
            result.sources_checked += 1
            result.malicious_sources += 1
            result.details["local_db"] = db_result
            result.score += 50

        # DNS blacklist checks
        reversed_ip = ".".join(reversed(ip.split(".")))

        for bl in self.IP_BLACKLISTS:
            result.sources_checked += 1
            query = f"{reversed_ip}.{bl}"

            try:
                socket.gethostbyname(query)
                # Listed in blacklist
                result.malicious_sources += 1
                result.details["blacklists"].append(bl)
                result.score += 15
            except socket.gaierror:
                # Not listed
                pass
            except Exception:
                pass

        # Determine reputation
        if result.malicious_sources == 0:
            result.reputation = "clean"
        elif result.malicious_sources <= 2:
            result.reputation = "suspicious"
        else:
            result.reputation = "malicious"

        result.score = min(100, result.score)
        return result

    def _check_domain(self, domain: str) -> ReputationResult:
        """Check domain reputation."""
        result = ReputationResult(
            ioc=domain,
            ioc_type="domain",
            reputation="unknown",
            score=0,
            sources_checked=0,
            malicious_sources=0,
            details={"timestamp": datetime.now(), "blacklists": []}
        )

        # Check local database
        db_result = self.db.check_ioc(domain)
        if db_result:
            result.sources_checked += 1
            result.malicious_sources += 1
            result.details["local_db"] = db_result
            result.score += 50

        # DNS blacklist checks
        for bl in self.DOMAIN_BLACKLISTS:
            result.sources_checked += 1
            query = f"{domain}.{bl}"

            try:
                socket.gethostbyname(query)
                result.malicious_sources += 1
                result.details["blacklists"].append(bl)
                result.score += 20
            except socket.gaierror:
                pass
            except Exception:
                pass

        # Check domain age (new domains are suspicious)
        try:
            # Try to resolve
            ips = socket.gethostbyname_ex(domain)[2]
            result.details["resolved_ips"] = ips
        except socket.gaierror:
            result.details["note"] = "Domain does not resolve"
            result.score += 10

        # Check for suspicious TLDs
        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work"]
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            result.score += 15
            result.details["suspicious_tld"] = True

        # Determine reputation
        if result.malicious_sources == 0 and result.score < 20:
            result.reputation = "clean"
        elif result.score < 50:
            result.reputation = "suspicious"
        else:
            result.reputation = "malicious"

        result.score = min(100, result.score)
        return result

    def _check_url(self, url: str) -> ReputationResult:
        """Check URL reputation."""
        from urllib.parse import urlparse

        result = ReputationResult(
            ioc=url,
            ioc_type="url",
            reputation="unknown",
            score=0,
            sources_checked=0,
            malicious_sources=0,
            details={"timestamp": datetime.now()}
        )

        # Extract domain
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
        except Exception:
            domain = None

        # Check local database
        db_result = self.db.check_ioc(url)
        if db_result:
            result.sources_checked += 1
            result.malicious_sources += 1
            result.score += 70
            result.details["local_db"] = db_result

        # Check domain if extracted
        if domain:
            domain_result = self._check_domain(domain)
            result.sources_checked += domain_result.sources_checked
            result.malicious_sources += domain_result.malicious_sources
            result.score += domain_result.score // 2
            result.details["domain_check"] = domain_result.reputation

        # Check for suspicious URL patterns
        suspicious_patterns = [
            "/login", "/signin", "/password", "/verify",
            "update", "confirm", "secure", "account",
            ".php?", ".aspx?", "base64",
        ]

        url_lower = url.lower()
        for pattern in suspicious_patterns:
            if pattern in url_lower:
                result.score += 5
                result.details.setdefault("suspicious_patterns", []).append(pattern)

        # Determine reputation
        if result.malicious_sources == 0 and result.score < 20:
            result.reputation = "clean"
        elif result.score < 50:
            result.reputation = "suspicious"
        else:
            result.reputation = "malicious"

        result.score = min(100, result.score)
        return result

    def _check_hash(self, hash_value: str) -> ReputationResult:
        """Check file hash reputation."""
        result = ReputationResult(
            ioc=hash_value,
            ioc_type="hash",
            reputation="unknown",
            score=0,
            sources_checked=0,
            malicious_sources=0,
            details={"timestamp": datetime.now()}
        )

        # Determine hash type
        if len(hash_value) == 32:
            hash_type = "md5"
        elif len(hash_value) == 40:
            hash_type = "sha1"
        elif len(hash_value) == 64:
            hash_type = "sha256"
        else:
            result.details["error"] = "Unknown hash type"
            return result

        result.details["hash_type"] = hash_type

        # Check local database
        db_result = self.db.check_ioc(hash_value.lower())
        if db_result:
            result.sources_checked += 1
            result.malicious_sources += 1
            result.score += 80
            result.reputation = "malicious"
            result.details["local_db"] = db_result

        return result

    def is_malicious(self, ioc: str) -> bool:
        """Quick check if IOC is malicious."""
        result = self.check(ioc)
        return result.reputation == "malicious"

    def is_suspicious(self, ioc: str) -> bool:
        """Quick check if IOC is suspicious or malicious."""
        result = self.check(ioc)
        return result.reputation in ("suspicious", "malicious")

    def get_score(self, ioc: str) -> int:
        """Get reputation score for IOC."""
        result = self.check(ioc)
        return result.score

    def clear_cache(self):
        """Clear reputation cache."""
        self.cache.clear()

    def get_statistics(self) -> Dict[str, Any]:
        """Get checker statistics."""
        return {
            **self.stats,
            "cache_size": len(self.cache),
            "cache_hit_rate": (
                self.stats["cache_hits"] / self.stats["checks"]
                if self.stats["checks"] > 0 else 0
            ),
        }
