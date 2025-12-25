"""
Log Analysis Module for BlueTeam Arsenal.
SIEM-like log aggregation, parsing, and analysis.
"""

from blueteam.logs.parser import LogParser
from blueteam.logs.aggregator import LogAggregator
from blueteam.logs.analyzer import LogAnalyzer
from blueteam.logs.correlator import EventCorrelator
from blueteam.logs.windows import WindowsEventParser
from blueteam.logs.syslog import SyslogParser

__all__ = [
    "LogParser",
    "LogAggregator",
    "LogAnalyzer",
    "EventCorrelator",
    "WindowsEventParser",
    "SyslogParser",
]
