"""
BlueTeam Arsenal - Enterprise-Grade Blue Team Security Toolkit
===============================================================

A comprehensive, modular security toolkit for defenders, SOC analysts,
incident responders, and security researchers.

Modules:
    - network: Network traffic analysis and monitoring
    - logs: Log analysis and SIEM-like capabilities
    - threat_intel: Threat intelligence gathering and correlation
    - incident: Incident response automation
    - malware: Static and dynamic malware analysis
    - forensics: Digital forensics utilities
    - dashboard: Real-time security monitoring dashboard

Author: Blue Team Arsenal Contributors
License: MIT
"""

__version__ = "1.0.0"
__author__ = "Blue Team Arsenal"
__license__ = "MIT"

from blueteam.core.config import Config
from blueteam.core.logger import setup_logging

# Initialize logging
setup_logging()

__all__ = [
    "Config",
    "__version__",
    "__author__",
    "__license__",
]
