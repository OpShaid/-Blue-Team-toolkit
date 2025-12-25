"""
DNS Monitor - Monitor and analyze DNS traffic for threats.
"""

import socket
import struct
import threading
import time
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set
import math

from blueteam.core.logger import get_logger
from blueteam.core.database import Database

logger = get_logger(__name__)


@dataclass
class DNSQuery:
    """Represents a DNS query."""
    timestamp: datetime
    source_ip: str
    query_name: str
    query_type: str
    response_code: Optional[str] = None
    response_data: Optional[List[str]] = None
    ttl: Optional[int] = None
    is_suspicious: bool = False
    threat_indicators: Optional[List[str]] = None


class DNSMonitor:
    """
    DNS traffic monitor with threat detection.

    Features:
    - DNS query/response logging
    - DGA (Domain Generation Algorithm) detection
    - DNS tunneling detection
    - Suspicious TLD monitoring
    - Fast-flux detection
    - Known malicious domain blocking
    """

    # Suspicious TLDs often used by malware
    SUSPICIOUS_TLDS = {
        ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs
        ".top", ".xyz", ".work", ".click", ".link",
        ".online", ".site", ".win", ".download",
        ".pw", ".cc", ".su", ".ru", ".cn",
    }

    # Known malicious patterns
    MALICIOUS_PATTERNS = [
        r"^[a-z0-9]{20,}\..*$",  # Very long random subdomain
        r"^\d+\.\d+\.\d+\.\d+\..*$",  # IP in subdomain
        r".*\.(onion|tor2web)\..*$",  # Tor related
        r".*--(wpad|isatap)\..*$",  # WPAD/ISATAP abuse
    ]

    # Common legitimate domains to whitelist
    WHITELIST = {
        "google.com", "googleapis.com", "gstatic.com",
        "microsoft.com", "windows.com", "office.com",
        "apple.com", "icloud.com",
        "amazon.com", "amazonaws.com",
        "cloudflare.com", "akamai.com",
        "github.com", "githubusercontent.com",
    }

    def __init__(self, db: Database = None):
        self.db = db or Database()
        self._running = False
        self._monitor_thread = None

        # Statistics
        self.query_count = 0
        self.queries: List[DNSQuery] = []
        self.domain_stats = defaultdict(int)
        self.client_stats = defaultdict(int)
        self.alerts: List[Dict[str, Any]] = []

        # DGA detection
        self._domain_history: Dict[str, List[str]] = defaultdict(list)
        self._entropy_threshold = 3.5

    def start_monitoring(self, interface: str = None, callback: Callable = None):
        """Start DNS monitoring."""
        if self._running:
            logger.warning("DNS monitoring already running")
            return

        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interface, callback),
            daemon=True
        )
        self._monitor_thread.start()
        logger.info("Started DNS monitoring")

    def stop_monitoring(self):
        """Stop DNS monitoring."""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2)
        logger.info("Stopped DNS monitoring")

    def _monitor_loop(self, interface: str, callback: Callable):
        """Main DNS monitoring loop."""
        try:
            # Create raw socket for DNS traffic (port 53)
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.settimeout(1)

            while self._running:
                try:
                    raw_data, addr = sock.recvfrom(65536)
                    query = self._parse_dns_packet(raw_data, addr[0])
                    if query:
                        self._process_query(query)
                        if callback:
                            callback(query)
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.debug(f"DNS parse error: {e}")

            sock.close()

        except PermissionError:
            logger.error("Permission denied. Run with administrator/root privileges.")
        except Exception as e:
            logger.error(f"DNS monitoring error: {e}")

    def _parse_dns_packet(self, raw_data: bytes, source_ip: str) -> Optional[DNSQuery]:
        """Parse DNS packet from raw data."""
        # Skip IP header
        ip_header_len = (raw_data[0] & 0x0F) * 4
        udp_data = raw_data[ip_header_len:]

        if len(udp_data) < 8:
            return None

        src_port, dst_port = struct.unpack("!HH", udp_data[:4])

        # Check if DNS (port 53)
        if src_port != 53 and dst_port != 53:
            return None

        dns_data = udp_data[8:]
        if len(dns_data) < 12:
            return None

        # Parse DNS header
        flags = struct.unpack("!H", dns_data[2:4])[0]
        is_response = (flags >> 15) & 1
        rcode = flags & 0x0F
        qdcount = struct.unpack("!H", dns_data[4:6])[0]

        if qdcount == 0:
            return None

        # Parse question
        offset = 12
        name_parts = []

        while offset < len(dns_data):
            length = dns_data[offset]
            if length == 0:
                offset += 1
                break
            if length >= 192:
                offset += 2
                break
            if offset + length + 1 > len(dns_data):
                break
            name_parts.append(dns_data[offset + 1:offset + 1 + length].decode(errors='ignore'))
            offset += length + 1

        if not name_parts:
            return None

        query_name = ".".join(name_parts)

        qtype = 0
        if offset + 2 <= len(dns_data):
            qtype = struct.unpack("!H", dns_data[offset:offset + 2])[0]

        type_names = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 255: "ANY"}
        rcode_names = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}

        return DNSQuery(
            timestamp=datetime.now(),
            source_ip=source_ip,
            query_name=query_name.lower(),
            query_type=type_names.get(qtype, str(qtype)),
            response_code=rcode_names.get(rcode) if is_response else None,
        )

    def _process_query(self, query: DNSQuery):
        """Process a DNS query for threats."""
        self.query_count += 1
        self.domain_stats[query.query_name] += 1
        self.client_stats[query.source_ip] += 1

        # Track domain history for DGA detection
        self._domain_history[query.source_ip].append(query.query_name)
        if len(self._domain_history[query.source_ip]) > 100:
            self._domain_history[query.source_ip] = self._domain_history[query.source_ip][-100:]

        # Threat detection
        threats = self._detect_threats(query)
        if threats:
            query.is_suspicious = True
            query.threat_indicators = threats
            self._create_alert(query, threats)

        self.queries.append(query)

        # Keep last 10000 queries
        if len(self.queries) > 10000:
            self.queries = self.queries[-10000:]

        # Store in database
        try:
            self.db.add_dns_query(
                source_ip=query.source_ip,
                query_name=query.query_name,
                query_type=query.query_type,
                response_code=query.response_code,
                is_suspicious=1 if query.is_suspicious else 0
            )
        except Exception as e:
            logger.debug(f"Failed to store DNS query: {e}")

    def _detect_threats(self, query: DNSQuery) -> List[str]:
        """Detect threats in DNS query."""
        threats = []
        domain = query.query_name

        # Check whitelist
        for whitelisted in self.WHITELIST:
            if domain.endswith(whitelisted):
                return []

        # Suspicious TLD
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                threats.append(f"Suspicious TLD: {tld}")
                break

        # Malicious patterns
        for pattern in self.MALICIOUS_PATTERNS:
            if re.match(pattern, domain):
                threats.append(f"Malicious pattern match")
                break

        # DGA detection - high entropy domain
        parts = domain.split(".")
        if len(parts) >= 2:
            subdomain = parts[0]
            if len(subdomain) > 10:
                entropy = self._calculate_entropy(subdomain)
                if entropy > self._entropy_threshold:
                    threats.append(f"High entropy domain (DGA indicator): {entropy:.2f}")

        # DNS tunneling detection - very long queries
        if len(domain) > 100:
            threats.append("Extremely long domain (possible DNS tunneling)")

        # TXT record abuse (often used for tunneling/C2)
        if query.query_type == "TXT" and not any(
            domain.endswith(d) for d in [".google.com", ".microsoft.com", "._domainkey."]
        ):
            if len(domain) > 50 or self._calculate_entropy(domain.split(".")[0]) > 3.0:
                threats.append("Suspicious TXT query (possible C2/tunneling)")

        # Rapid unique domain queries (DGA behavior)
        recent_domains = self._domain_history.get(query.source_ip, [])
        if len(recent_domains) >= 20:
            unique_domains = len(set(recent_domains[-20:]))
            if unique_domains >= 18:  # 90% unique
                threats.append("Rapid unique domain queries (DGA behavior)")

        # NXDOMAIN flood (DGA indicator)
        if query.response_code == "NXDOMAIN":
            recent = [q for q in self.queries[-100:] if q.source_ip == query.source_ip]
            nxdomain_count = sum(1 for q in recent if q.response_code == "NXDOMAIN")
            if nxdomain_count > 50:
                threats.append("High NXDOMAIN rate (DGA indicator)")

        return threats

    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not string:
            return 0.0

        prob = [float(string.count(c)) / len(string) for c in set(string)]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    def _create_alert(self, query: DNSQuery, threats: List[str]):
        """Create alert for suspicious DNS activity."""
        alert = {
            "timestamp": query.timestamp.isoformat(),
            "source_ip": query.source_ip,
            "query": query.query_name,
            "query_type": query.query_type,
            "threats": threats,
            "severity": "high" if len(threats) > 1 else "medium",
        }
        self.alerts.append(alert)
        logger.warning(f"DNS Alert: {query.query_name} from {query.source_ip} - {', '.join(threats)}")

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze a specific domain."""
        domain = domain.lower()
        parts = domain.split(".")

        analysis = {
            "domain": domain,
            "tld": f".{parts[-1]}" if parts else "",
            "levels": len(parts),
            "length": len(domain),
            "entropy": self._calculate_entropy(parts[0]) if parts else 0,
            "is_suspicious": False,
            "threat_indicators": [],
        }

        # Check TLD
        if analysis["tld"] in self.SUSPICIOUS_TLDS:
            analysis["threat_indicators"].append(f"Suspicious TLD: {analysis['tld']}")

        # Check patterns
        for pattern in self.MALICIOUS_PATTERNS:
            if re.match(pattern, domain):
                analysis["threat_indicators"].append("Matches malicious pattern")
                break

        # Check entropy
        if analysis["entropy"] > self._entropy_threshold:
            analysis["threat_indicators"].append(f"High entropy: {analysis['entropy']:.2f}")

        # Check length
        if len(domain) > 100:
            analysis["threat_indicators"].append("Extremely long domain")

        analysis["is_suspicious"] = len(analysis["threat_indicators"]) > 0

        # Resolve domain
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            analysis["resolved_ips"] = ips
        except socket.gaierror:
            analysis["resolved_ips"] = []
            analysis["note"] = "Domain does not resolve"

        return analysis

    def get_statistics(self) -> Dict[str, Any]:
        """Get DNS monitoring statistics."""
        return {
            "total_queries": self.query_count,
            "unique_domains": len(self.domain_stats),
            "unique_clients": len(self.client_stats),
            "top_domains": sorted(
                self.domain_stats.items(),
                key=lambda x: x[1],
                reverse=True
            )[:20],
            "top_clients": sorted(
                self.client_stats.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10],
            "alerts": len(self.alerts),
            "recent_alerts": self.alerts[-10:],
        }

    def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain against known bad lists."""
        result = {
            "domain": domain,
            "is_malicious": False,
            "sources": [],
        }

        # Check local IOC database
        try:
            ioc = self.db.check_ioc(domain)
            if ioc:
                result["is_malicious"] = True
                result["sources"].append({
                    "source": "local_ioc_db",
                    "confidence": ioc.get("confidence", 50),
                    "first_seen": ioc.get("first_seen"),
                })
        except Exception:
            pass

        return result

    def export_logs(self, output_file: str, format: str = "json"):
        """Export DNS logs to file."""
        from blueteam.core.utils import export_to_json, export_to_csv

        data = []
        for query in self.queries:
            data.append({
                "timestamp": query.timestamp.isoformat(),
                "source_ip": query.source_ip,
                "query_name": query.query_name,
                "query_type": query.query_type,
                "response_code": query.response_code,
                "is_suspicious": query.is_suspicious,
                "threats": query.threat_indicators,
            })

        if format == "json":
            export_to_json(data, output_file)
        else:
            export_to_csv(data, output_file)

        logger.info(f"Exported {len(data)} DNS queries to {output_file}")
