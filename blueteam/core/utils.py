

import hashlib
import ipaddress
import re
import json
import csv
import socket
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse
import requests


def hash_file(file_path: Union[str, Path], algorithms: List[str] = None) -> Dict[str, str]:
    """Calculate file hashes."""
    if algorithms is None:
        algorithms = ["md5", "sha1", "sha256"]

    hashes = {}
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    hash_objects = {alg: hashlib.new(alg) for alg in algorithms}

    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            for h in hash_objects.values():
                h.update(chunk)

    for alg, h in hash_objects.items():
        hashes[alg] = h.hexdigest()

    return hashes


def hash_string(data: str, algorithm: str = "sha256") -> str:
    """Calculate hash of a string."""
    return hashlib.new(algorithm, data.encode()).hexdigest()


def validate_ip(ip: str) -> bool:
    """Validate an IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_domain(domain: str) -> bool:
    """Validate a domain name."""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def validate_url(url: str) -> bool:
    """Validate a URL."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def validate_email(email: str) -> bool:
    """Validate an email address."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_hash(hash_value: str) -> Optional[str]:
    """Validate and identify hash type."""
    hash_value = hash_value.lower().strip()

    if re.match(r'^[a-f0-9]{32}$', hash_value):
        return "md5"
    elif re.match(r'^[a-f0-9]{40}$', hash_value):
        return "sha1"
    elif re.match(r'^[a-f0-9]{64}$', hash_value):
        return "sha256"
    elif re.match(r'^[a-f0-9]{128}$', hash_value):
        return "sha512"
    return None


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is private."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def get_ip_info(ip: str) -> Dict[str, Any]:
    """Get information about an IP address."""
    info = {
        "ip": ip,
        "is_valid": False,
        "is_private": False,
        "version": None,
        "reverse_dns": None,
    }

    try:
        ip_obj = ipaddress.ip_address(ip)
        info["is_valid"] = True
        info["is_private"] = ip_obj.is_private
        info["version"] = ip_obj.version
        info["is_loopback"] = ip_obj.is_loopback
        info["is_multicast"] = ip_obj.is_multicast
        info["is_reserved"] = ip_obj.is_reserved

        try:
            info["reverse_dns"] = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            pass

    except ValueError:
        pass

    return info


def resolve_domain(domain: str) -> List[str]:
    """Resolve a domain to IP addresses."""
    try:
        return list(set(socket.gethostbyname_ex(domain)[2]))
    except socket.gaierror:
        return []


def safe_request(
    url: str,
    method: str = "GET",
    timeout: int = 10,
    verify_ssl: bool = True,
    **kwargs
) -> Optional[requests.Response]:
    """Make a safe HTTP request with error handling."""
    try:
        response = requests.request(
            method,
            url,
            timeout=timeout,
            verify=verify_ssl,
            **kwargs
        )
        return response
    except requests.RequestException:
        return None


def parse_timestamp(timestamp: str) -> Optional[datetime]:
    """Parse various timestamp formats."""
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%b %d %H:%M:%S",
        "%Y-%m-%d",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(timestamp, fmt)
        except ValueError:
            continue
    return None


def export_to_json(data: Any, file_path: Union[str, Path], indent: int = 2) -> None:
    """Export data to JSON file."""
    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(file_path, "w") as f:
        json.dump(data, f, indent=indent, default=str)


def export_to_csv(
    data: List[Dict[str, Any]],
    file_path: Union[str, Path],
    fieldnames: List[str] = None
) -> None:
    """Export data to CSV file."""
    if not data:
        return

    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    if fieldnames is None:
        fieldnames = list(data[0].keys())

    with open(file_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)


def defang_ioc(ioc: str) -> str:
    """Defang an IOC for safe sharing."""
    ioc = ioc.replace("http://", "hxxp://")
    ioc = ioc.replace("https://", "hxxps://")
    ioc = ioc.replace(".", "[.]")
    ioc = ioc.replace("@", "[@]")
    return ioc


def refang_ioc(ioc: str) -> str:
    """Refang an IOC for analysis."""
    ioc = ioc.replace("hxxp://", "http://")
    ioc = ioc.replace("hxxps://", "https://")
    ioc = ioc.replace("[.]", ".")
    ioc = ioc.replace("[@]", "@")
    return ioc


def extract_iocs(text: str) -> Dict[str, List[str]]:
    """Extract IOCs from text."""
    iocs = {
        "ips": [],
        "domains": [],
        "urls": [],
        "emails": [],
        "md5": [],
        "sha1": [],
        "sha256": [],
    }

    # Refang first
    text = refang_ioc(text)

    # IP addresses
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    iocs["ips"] = list(set(re.findall(ip_pattern, text)))

    # URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    iocs["urls"] = list(set(re.findall(url_pattern, text)))

    # Emails
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    iocs["emails"] = list(set(re.findall(email_pattern, text)))

    # Hashes
    iocs["md5"] = list(set(re.findall(r'\b[a-fA-F0-9]{32}\b', text)))
    iocs["sha1"] = list(set(re.findall(r'\b[a-fA-F0-9]{40}\b', text)))
    iocs["sha256"] = list(set(re.findall(r'\b[a-fA-F0-9]{64}\b', text)))

    # Domains (basic extraction)
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|co|info|biz|xyz|top|online|site|club|tech|app|dev|cloud|ru|cn|tk|ml|ga|cf|gq)\b'
    iocs["domains"] = list(set(re.findall(domain_pattern, text, re.IGNORECASE)))

    return iocs


def entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0

    from collections import Counter
    import math

    counter = Counter(data)
    length = len(data)

    ent = 0.0
    for count in counter.values():
        p = count / length
        ent -= p * math.log2(p)

    return ent


def is_base64(s: str) -> bool:
    """Check if a string is valid base64."""
    import base64
    try:
        if len(s) % 4 != 0:
            return False
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


def decode_base64(s: str) -> Optional[bytes]:
    """Decode base64 string."""
    import base64
    try:
        return base64.b64decode(s)
    except Exception:
        return None


def format_bytes(size: int) -> str:
    """Format bytes to human readable format."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def get_file_type(file_path: Union[str, Path]) -> Dict[str, str]:
    """Get file type information using magic bytes."""
    file_path = Path(file_path)

    if not file_path.exists():
        return {"error": "File not found"}

    # Common magic bytes
    signatures = {
        b'\x4D\x5A': "PE Executable (Windows)",
        b'\x7F\x45\x4C\x46': "ELF Executable (Linux)",
        b'\xCA\xFE\xBA\xBE': "Mach-O (macOS)",
        b'\x50\x4B\x03\x04': "ZIP Archive",
        b'\x50\x4B\x05\x06': "ZIP Archive (empty)",
        b'\x52\x61\x72\x21': "RAR Archive",
        b'\x1F\x8B': "GZIP Archive",
        b'\x42\x5A\x68': "BZIP2 Archive",
        b'\x25\x50\x44\x46': "PDF Document",
        b'\xD0\xCF\x11\xE0': "MS Office Document",
        b'\x50\x4B\x03\x04\x14': "Office Open XML",
        b'\x89\x50\x4E\x47': "PNG Image",
        b'\xFF\xD8\xFF': "JPEG Image",
        b'\x47\x49\x46\x38': "GIF Image",
        b'PK': "ZIP-based format",
    }

    with open(file_path, "rb") as f:
        header = f.read(16)

    for sig, file_type in signatures.items():
        if header.startswith(sig):
            return {
                "type": file_type,
                "extension": file_path.suffix,
                "magic_bytes": sig.hex(),
            }

    return {
        "type": "Unknown",
        "extension": file_path.suffix,
        "magic_bytes": header[:8].hex(),
    }
