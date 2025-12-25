"""
Threat Enrichment - Enrich IOCs with external threat intelligence.
"""

import json
import time
import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

from blueteam.core.logger import get_logger
from blueteam.core.config import Config
from blueteam.core.utils import safe_request, validate_ip, validate_domain

logger = get_logger(__name__)


@dataclass
class EnrichmentResult:
    """Result of IOC enrichment."""
    ioc: str
    ioc_type: str
    risk_score: int  # 0-100
    is_malicious: bool
    sources: List[Dict[str, Any]] = field(default_factory=list)
    whois: Optional[Dict[str, Any]] = None
    geo: Optional[Dict[str, Any]] = None
    asn: Optional[Dict[str, Any]] = None
    dns: Optional[Dict[str, Any]] = None
    tags: List[str] = field(default_factory=list)
    related_iocs: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


class ThreatEnricher:
    """
    Enrich IOCs with multiple threat intelligence sources.

    Supported services:
    - VirusTotal
    - AbuseIPDB
    - Shodan
    - AlienVault OTX
    - GreyNoise
    - URLScan.io
    - IPinfo
    """

    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.cache: Dict[str, EnrichmentResult] = {}
        self.cache_ttl = 3600  # 1 hour

        # Rate limiting
        self._rate_limits = {
            "virustotal": 4,  # 4 requests per minute
            "abuseipdb": 60,
            "shodan": 1,
        }
        self._last_request: Dict[str, float] = {}

    def enrich(self, ioc: str, ioc_type: str = None) -> EnrichmentResult:
        """Enrich a single IOC."""
        # Auto-detect type
        if not ioc_type:
            if validate_ip(ioc):
                ioc_type = "ip"
            elif validate_domain(ioc):
                ioc_type = "domain"
            elif ioc.startswith("http"):
                ioc_type = "url"
            else:
                ioc_type = "hash"

        # Check cache
        cache_key = f"{ioc_type}:{ioc}"
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if (datetime.now() - cached.timestamp).seconds < self.cache_ttl:
                return cached

        result = EnrichmentResult(
            ioc=ioc,
            ioc_type=ioc_type,
            risk_score=0,
            is_malicious=False,
        )

        # Run enrichments based on type
        if ioc_type == "ip":
            self._enrich_ip(result)
        elif ioc_type == "domain":
            self._enrich_domain(result)
        elif ioc_type == "url":
            self._enrich_url(result)
        elif ioc_type == "hash":
            self._enrich_hash(result)

        # Calculate overall risk score
        result.risk_score = self._calculate_risk_score(result)
        result.is_malicious = result.risk_score >= 70

        # Cache result
        self.cache[cache_key] = result

        return result

    def enrich_batch(self, iocs: List[str], ioc_type: str = None, max_workers: int = 5) -> List[EnrichmentResult]:
        """Enrich multiple IOCs in parallel."""
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.enrich, ioc, ioc_type): ioc for ioc in iocs}

            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Enrichment failed for {futures[future]}: {e}")

        return results

    def _enrich_ip(self, result: EnrichmentResult):
        """Enrich IP address."""
        # AbuseIPDB
        if self.config.api_keys.abuseipdb:
            self._check_abuseipdb(result)

        # VirusTotal
        if self.config.api_keys.virustotal:
            self._check_virustotal(result)

        # Shodan
        if self.config.api_keys.shodan:
            self._check_shodan(result)

        # GreyNoise
        if self.config.api_keys.greynoise:
            self._check_greynoise(result)

        # Free services
        self._get_ip_geolocation(result)
        self._get_ip_asn(result)

    def _enrich_domain(self, result: EnrichmentResult):
        """Enrich domain."""
        # VirusTotal
        if self.config.api_keys.virustotal:
            self._check_virustotal(result)

        # DNS lookup
        self._get_dns_records(result)

        # WHOIS
        self._get_whois(result)

    def _enrich_url(self, result: EnrichmentResult):
        """Enrich URL."""
        # VirusTotal
        if self.config.api_keys.virustotal:
            self._check_virustotal(result)

        # URLScan.io
        if self.config.api_keys.urlscan:
            self._check_urlscan(result)

    def _enrich_hash(self, result: EnrichmentResult):
        """Enrich file hash."""
        # VirusTotal
        if self.config.api_keys.virustotal:
            self._check_virustotal_hash(result)

        # Hybrid Analysis
        if self.config.api_keys.hybrid_analysis:
            self._check_hybrid_analysis(result)

    def _rate_limit(self, service: str):
        """Apply rate limiting."""
        limit = self._rate_limits.get(service, 10)
        last = self._last_request.get(service, 0)
        wait = (60 / limit) - (time.time() - last)

        if wait > 0:
            time.sleep(wait)

        self._last_request[service] = time.time()

    def _check_virustotal(self, result: EnrichmentResult):
        """Check VirusTotal."""
        self._rate_limit("virustotal")

        api_key = self.config.api_keys.virustotal
        ioc = result.ioc

        if result.ioc_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        elif result.ioc_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
        elif result.ioc_type == "url":
            url_id = hashlib.sha256(ioc.encode()).hexdigest()
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        else:
            return

        response = safe_request(url, headers={"x-apikey": api_key})

        if response and response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0

            result.sources.append({
                "source": "virustotal",
                "malicious_count": malicious,
                "total_engines": total,
                "reputation": data.get("reputation", 0),
            })

            if malicious > 0:
                result.tags.append("virustotal:malicious")

    def _check_virustotal_hash(self, result: EnrichmentResult):
        """Check VirusTotal for file hash."""
        self._rate_limit("virustotal")

        api_key = self.config.api_keys.virustotal
        url = f"https://www.virustotal.com/api/v3/files/{result.ioc}"

        response = safe_request(url, headers={"x-apikey": api_key})

        if response and response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0

            result.sources.append({
                "source": "virustotal",
                "malicious_count": malicious,
                "total_engines": total,
                "file_type": data.get("type_description"),
                "file_name": data.get("meaningful_name"),
            })

            if malicious > 0:
                result.tags.append("virustotal:malicious")
                result.tags.append(f"detections:{malicious}")

    def _check_abuseipdb(self, result: EnrichmentResult):
        """Check AbuseIPDB."""
        self._rate_limit("abuseipdb")

        api_key = self.config.api_keys.abuseipdb
        url = f"https://api.abuseipdb.com/api/v2/check"

        response = safe_request(
            url,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": result.ioc}
        )

        if response and response.status_code == 200:
            data = response.json().get("data", {})

            result.sources.append({
                "source": "abuseipdb",
                "abuse_confidence": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "is_tor": data.get("isTor", False),
            })

            if data.get("abuseConfidenceScore", 0) >= 50:
                result.tags.append("abuseipdb:high_confidence")

    def _check_shodan(self, result: EnrichmentResult):
        """Check Shodan."""
        self._rate_limit("shodan")

        api_key = self.config.api_keys.shodan
        url = f"https://api.shodan.io/shodan/host/{result.ioc}?key={api_key}"

        response = safe_request(url)

        if response and response.status_code == 200:
            data = response.json()

            result.sources.append({
                "source": "shodan",
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "org": data.get("org"),
                "isp": data.get("isp"),
                "os": data.get("os"),
                "vulns": list(data.get("vulns", {}).keys()) if data.get("vulns") else [],
            })

            result.asn = {
                "asn": data.get("asn"),
                "org": data.get("org"),
            }

            if data.get("vulns"):
                result.tags.append("shodan:vulnerable")

    def _check_greynoise(self, result: EnrichmentResult):
        """Check GreyNoise."""
        api_key = self.config.api_keys.greynoise
        url = f"https://api.greynoise.io/v3/community/{result.ioc}"

        headers = {"key": api_key} if api_key else {}
        response = safe_request(url, headers=headers)

        if response and response.status_code == 200:
            data = response.json()

            result.sources.append({
                "source": "greynoise",
                "noise": data.get("noise", False),
                "riot": data.get("riot", False),
                "classification": data.get("classification"),
                "name": data.get("name"),
            })

            if data.get("classification") == "malicious":
                result.tags.append("greynoise:malicious")
            elif data.get("riot"):
                result.tags.append("greynoise:benign")

    def _check_urlscan(self, result: EnrichmentResult):
        """Check URLScan.io."""
        api_key = self.config.api_keys.urlscan
        url = "https://urlscan.io/api/v1/search/"

        response = safe_request(
            url,
            headers={"API-Key": api_key} if api_key else {},
            params={"q": result.ioc}
        )

        if response and response.status_code == 200:
            results = response.json().get("results", [])
            if results:
                latest = results[0]
                result.sources.append({
                    "source": "urlscan",
                    "url": latest.get("page", {}).get("url"),
                    "domain": latest.get("page", {}).get("domain"),
                    "ip": latest.get("page", {}).get("ip"),
                    "country": latest.get("page", {}).get("country"),
                    "malicious": latest.get("verdicts", {}).get("overall", {}).get("malicious", False),
                })

    def _check_hybrid_analysis(self, result: EnrichmentResult):
        """Check Hybrid Analysis."""
        api_key = self.config.api_keys.hybrid_analysis
        url = f"https://www.hybrid-analysis.com/api/v2/search/hash"

        response = safe_request(
            url,
            method="POST",
            headers={"api-key": api_key, "Content-Type": "application/x-www-form-urlencoded"},
            data={"hash": result.ioc}
        )

        if response and response.status_code == 200:
            data = response.json()
            if data:
                sample = data[0] if isinstance(data, list) else data

                result.sources.append({
                    "source": "hybrid_analysis",
                    "verdict": sample.get("verdict"),
                    "threat_score": sample.get("threat_score"),
                    "type": sample.get("type"),
                    "tags": sample.get("type_short", []),
                })

    def _get_ip_geolocation(self, result: EnrichmentResult):
        """Get IP geolocation from free service."""
        url = f"http://ip-api.com/json/{result.ioc}"

        response = safe_request(url)

        if response and response.status_code == 200:
            data = response.json()

            result.geo = {
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "isp": data.get("isp"),
                "org": data.get("org"),
            }

    def _get_ip_asn(self, result: EnrichmentResult):
        """Get ASN information."""
        # Using ip-api data if available
        if result.geo and result.geo.get("org"):
            result.asn = {
                "org": result.geo.get("org"),
                "isp": result.geo.get("isp"),
            }

    def _get_dns_records(self, result: EnrichmentResult):
        """Get DNS records for domain."""
        import socket

        try:
            ips = socket.gethostbyname_ex(result.ioc)[2]
            result.dns = {
                "a_records": ips,
            }
            result.related_iocs.extend(ips)
        except socket.gaierror:
            pass

    def _get_whois(self, result: EnrichmentResult):
        """Get WHOIS information."""
        # Simplified WHOIS using web API
        url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={result.ioc}&outputFormat=JSON"

        response = safe_request(url)

        if response and response.status_code == 200:
            try:
                data = response.json().get("WhoisRecord", {})
                result.whois = {
                    "registrar": data.get("registrarName"),
                    "created": data.get("createdDate"),
                    "expires": data.get("expiresDate"),
                    "updated": data.get("updatedDate"),
                }
            except Exception:
                pass

    def _calculate_risk_score(self, result: EnrichmentResult) -> int:
        """Calculate overall risk score."""
        score = 0
        weights = []

        for source in result.sources:
            source_name = source.get("source", "")

            if source_name == "virustotal":
                malicious = source.get("malicious_count", 0)
                total = source.get("total_engines", 1)
                vt_score = (malicious / total) * 100 if total > 0 else 0
                weights.append(("virustotal", vt_score, 0.4))

            elif source_name == "abuseipdb":
                abuse_score = source.get("abuse_confidence", 0)
                weights.append(("abuseipdb", abuse_score, 0.3))

            elif source_name == "greynoise":
                if source.get("classification") == "malicious":
                    weights.append(("greynoise", 100, 0.2))
                elif source.get("riot"):
                    weights.append(("greynoise", 0, 0.1))

            elif source_name == "shodan":
                if source.get("vulns"):
                    weights.append(("shodan", 50, 0.1))

        if not weights:
            return 0

        total_weight = sum(w[2] for w in weights)
        if total_weight == 0:
            return 0

        score = sum(s * w for _, s, w in weights) / total_weight
        return min(100, max(0, int(score)))

    def get_summary(self, result: EnrichmentResult) -> str:
        """Get human-readable summary."""
        lines = [
            f"IOC: {result.ioc} ({result.ioc_type})",
            f"Risk Score: {result.risk_score}/100",
            f"Malicious: {result.is_malicious}",
        ]

        if result.tags:
            lines.append(f"Tags: {', '.join(result.tags)}")

        if result.geo:
            lines.append(f"Location: {result.geo.get('city', 'N/A')}, {result.geo.get('country', 'N/A')}")

        for source in result.sources:
            lines.append(f"  - {source.get('source')}: {json.dumps(source, default=str)[:100]}")

        return "\n".join(lines)
