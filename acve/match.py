"""Affected-matching: does an agent-lock unit fall inside an AVR's affected set?

A lockfile is affected iff ANY affected[] entry matches.

Component mode (CVE-style): the component kind+name exists in the lockfile
and its version is inside a ranges[] interval or listed in versions[].
SEMVER and DATE ranges evaluate introduced/fixed/last_affected/limit bounds.
GIT ranges only match via explicit versions[] -- ordering over commits needs
history data this package doesn't have (documented limitation).

Configuration mode (the agentic part): exact config_sha256 membership, or
ALL require[] predicates true. Paths are dot-paths; 'tools[kind=exec]'
selects array elements by field equality, 'tools[]' selects all elements.
Non-exists ops are existential (any resolved value satisfies). 'exists'
tests resolution non-emptiness; value:false inverts it (require absence).
'window' bounds the match by the lockfile's generated_at.
"""

from __future__ import annotations

import re
from typing import Any

from .validator import _json_equal

_SELECTOR_RE = re.compile(r"^(\w+)\[(\w+)=([^\]]*)\]$")
_WILDCARD_RE = re.compile(r"^(\w+)\[\]$")


def _resolve_path(doc: Any, path: str) -> list[Any]:
    """Resolve a predicate path to a list of candidate values."""
    cur = [doc]
    for seg in path.split("."):
        sel = _SELECTOR_RE.match(seg)
        wild = _WILDCARD_RE.match(seg)
        nxt: list[Any] = []
        for v in cur:
            if sel:
                coll = v.get(sel.group(1)) if isinstance(v, dict) else None
                if isinstance(coll, list):
                    key, want = sel.group(2), sel.group(3)
                    nxt.extend(x for x in coll if isinstance(x, dict) and str(x.get(key)) == want)
            elif wild:
                coll = v.get(wild.group(1)) if isinstance(v, dict) else None
                if isinstance(coll, list):
                    nxt.extend(coll)
            elif isinstance(v, dict):
                if seg in v:
                    nxt.append(v[seg])
            elif isinstance(v, list):
                nxt.extend(x[seg] for x in v if isinstance(x, dict) and seg in x)
        cur = nxt
    return cur


def _ver_key(v: str) -> tuple:
    """Version-ish sort key: numeric runs sort numerically, before strings."""
    return tuple((0, int(p)) if p.isdigit() else (1, p) for p in re.split(r"[.\-+]", v))


def _compare(a: Any, b: Any) -> int | None:
    """Return -1/0/1, or None if incomparable. Numbers numerically;
    version-ish strings (leading digit) by _ver_key; other strings
    lexicographically."""
    if isinstance(a, bool) or isinstance(b, bool):
        return None
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return (a > b) - (a < b)
    if isinstance(a, str) and isinstance(b, str):
        if re.match(r"^\d", a) and re.match(r"^\d", b):
            ka, kb = _ver_key(a), _ver_key(b)
            return (ka > kb) - (ka < kb)
        return (a > b) - (a < b)
    return None


def _satisfies(value: Any, op: str, operand: Any) -> bool:
    if op == "eq":
        return _json_equal(value, operand)
    if op == "ne":
        return not _json_equal(value, operand)
    if op in ("lt", "lte", "gt", "gte"):
        c = _compare(value, operand)
        if c is None:
            return False
        return {"lt": c < 0, "lte": c <= 0, "gt": c > 0, "gte": c >= 0}[op]
    if op == "in":
        return isinstance(operand, list) and any(_json_equal(value, x) for x in operand)
    if op == "pattern":
        return isinstance(value, str) and isinstance(operand, str) and bool(re.search(operand, value))
    if op == "contains":
        if isinstance(value, list):
            return any(_json_equal(x, operand) for x in value)
        return isinstance(value, str) and isinstance(operand, str) and operand in value
    return False


def _predicate_ok(lock: dict[str, Any], pred: dict[str, Any]) -> bool:
    resolved = _resolve_path(lock, pred["path"])
    if pred["op"] == "exists":
        want_present = pred.get("value", True) is not False
        return bool(resolved) == want_present
    return any(_satisfies(v, pred["op"], pred.get("value")) for v in resolved)


def _in_window(lock: dict[str, Any], window: dict[str, Any]) -> bool:
    gen = lock.get("generated_at", "")
    if "introduced_at" in window and gen < window["introduced_at"]:
        return False
    if "fixed_at" in window and gen >= window["fixed_at"]:
        return False
    if "last_affected_at" in window and gen > window["last_affected_at"]:
        return False
    return True


def _match_configuration(lock: dict[str, Any], conf: dict[str, Any]) -> bool:
    hashes = conf.get("config_sha256", [])
    if hashes and lock.get("provenance", {}).get("config_sha256") in hashes:
        return True
    if "require" in conf and all(_predicate_ok(lock, p) for p in conf["require"]):
        return _in_window(lock, conf.get("window", {}))
    return False


def _component_slots(lock: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    """Map a component kind onto the lockfile locations it can occupy."""
    if kind == "harness":
        return [lock.get("harness", {})]
    if kind == "model":
        return [lock.get("model", {})]
    if kind == "tool":
        return list(lock.get("tools", []))
    if kind == "skill":
        return list(lock.get("skills", []))
    if kind == "policy":
        return [lock.get("policy", {})] if lock.get("policy") else []
    if kind == "prompt":
        slots = list(lock.get("skills", []))
        if lock.get("agent", {}).get("system_prompt_sha256"):
            slots.append({"name": "system-prompt"})
        return slots
    if kind == "package":
        # purl-bearing slots anywhere in the lockfile
        slots = [lock.get("harness", {})] + list(lock.get("tools", []))
        return [s for s in slots if s.get("purl")]
    return []


def _in_range(version: str, rng: dict[str, Any]) -> bool:
    if rng.get("type") == "GIT":
        return False  # ordering needs commit history; use versions[] for GIT
    lo = hi_fixed = hi_last = hi_limit = None
    for ev in rng.get("events", []):
        lo = ev.get("introduced", lo)
        hi_fixed = ev.get("fixed", hi_fixed)
        hi_last = ev.get("last_affected", hi_last)
        hi_limit = ev.get("limit", hi_limit)
    if lo not in (None, "0") and (_compare(version, lo) or -1) < 0:
        return False
    for bound, strict in ((hi_fixed, True), (hi_limit, True), (hi_last, False)):
        if bound is None:
            continue
        c = _compare(version, bound)
        if c is None or (c >= 0 if strict else c > 0):
            return False
    return True


def _version_hit(version: str | None, comp: dict[str, Any]) -> bool:
    if version is None:
        return not comp.get("ranges") and not comp.get("versions")
    if version in comp.get("versions", []):
        return True
    return any(_in_range(version, r) for r in comp.get("ranges", []))


def _match_component(lock: dict[str, Any], comp: dict[str, Any]) -> bool:
    for slot in _component_slots(lock, comp["kind"]):
        if slot.get("name") != comp["name"]:
            continue
        cpurl = comp.get("purl")
        if cpurl:
            spurl = slot.get("purl", "")
            if not (spurl == cpurl or spurl.startswith(cpurl + "@")):
                continue
        if _version_hit(slot.get("version"), comp):
            return True
    return False


def match_entry(lock: dict[str, Any], entry: dict[str, Any]) -> bool:
    """Does one affected[] entry match this lockfile?"""
    if entry.get("unit") == "component" and "component" in entry:
        return _match_component(lock, entry["component"])
    if entry.get("unit") == "configuration" and "configuration" in entry:
        return _match_configuration(lock, entry["configuration"])
    return False


def match_lockfile(lock: dict[str, Any], record: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the affected[] entries that match (empty list = not affected)."""
    if record.get("status") in ("rejected", "withdrawn"):
        return []
    return [e for e in record.get("affected", []) if match_entry(lock, e)]


def scan(lock: dict[str, Any], records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Match a lockfile against a feed. Returns {record_id: matched_entries}."""
    return {
        r["id"]: m
        for r in records
        if (m := match_lockfile(lock, r))
    }
