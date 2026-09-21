"""acve -- Agentic Configuration Vulnerability Enumeration.

A CVE-style registry format for resolved AI agent configurations.
Zero third-party dependencies; Python 3.11+.
"""

from .feed import build_feed, iter_records, load_schema, write_feed
from .lockhash import canonicalize, config_sha256, verify
from .match import match_lockfile, scan
from .validator import validate, validate_file

__version__ = "0.1.0"

__all__ = [
    "build_feed",
    "canonicalize",
    "config_sha256",
    "iter_records",
    "load_schema",
    "match_lockfile",
    "scan",
    "validate",
    "validate_file",
    "verify",
]
