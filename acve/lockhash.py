"""Configuration unit identity: canonicalization + config_sha256.

The unit hash is SHA-256 over the RFC 8785 (JCS) canonicalization of the
lockfile with 'provenance' excluded. For documents containing only ASCII
strings, integers, and ordinary floats, JCS reduces to sorted keys +
compact separators -- stdlib json.dumps suffices.

ponytail: not a full RFC 8785 implementation -- ECMAScript number
serialization (shortest round-trip) is approximated by Python repr,
which agrees for integers and common floats but can diverge on edge
cases (e.g. 1e21). If cross-implementation identity is ever required,
swap in a real JCS library; the hash contract is the canonical bytes,
not this code.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonicalize(doc: dict[str, Any]) -> str:
    """Canonical JSON string of a lockfile, minus 'provenance'."""
    payload = {k: v for k, v in doc.items() if k != "provenance"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def config_sha256(doc: dict[str, Any]) -> str:
    """Compute the configuration unit hash for a lockfile document."""
    return hashlib.sha256(canonicalize(doc).encode("utf-8")).hexdigest()


def verify(doc: dict[str, Any]) -> bool:
    """True iff provenance.config_sha256 equals the computed hash."""
    claimed = doc.get("provenance", {}).get("config_sha256")
    return bool(claimed) and claimed == config_sha256(doc)
