"""Bounded, offline execution observations; independent of native ACVE formats.

The digest profile is restricted Python JSON, not JCS or authentication.
Nesting counts containers with the root as one; node counts include values and
containers, not object keys. Validation diagnostics contain fixed schema paths, never input
values (including caller-supplied keys and JSON Pointers).
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any

FORMAT = "acve-observation/0.1.0"
ALGORITHM = "acve-observation-json/0.1.0"
MAX_BYTES = 1024 * 1024
MAX_DEPTH = 32
MAX_NODES = 10000
MAX_ASSERTIONS = 512
MAX_EXPRESSION_NODES = 1024
MAX_EXPRESSION_DEPTH = 16
SAFE_INTEGER = 9007199254740991

_ROOT = {"format", "observation_id", "observed_at", "valid_until", "subject",
         "source", "assertions", "links", "receipts", "integrity"}
_SUBJECT = {"agent", "host", "surface", "session_id", "execution_id", "configuration_epoch"}
_RELS = {"objective", "authorization", "capacity", "capability", "taxonomy",
         "base120", "factory-admission", "policy", "evaluation"}
_STATUSES = {"known", "unknown", "invalid", "unavailable"}
_BASES = {"observed", "configured", "inferred"}
_RECEIPTS = {"invocation", "transport", "durability", "evaluation"}
_OUTCOMES = {"succeeded", "failed", "unknown", "not_attempted"}
_TIME = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?([Zz]|[+-][0-9]{2}:[0-9]{2})")
_SURROGATE = re.compile("[\ud800-\udfff]")


class ObservationError(ValueError):
    """A structured, redacted contract failure, never an evaluation no-hit."""

    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        self.errors = [f"{path}: {code}"]
        super().__init__(self.errors[0])


def _fail(code: str, path: str = "$") -> None:
    raise ObservationError(code, path)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def _profile(value: Any, path: str = "$") -> None:
    """Bound work before serialization, including cycles and oversized strings."""
    count = 0
    text_size = 0
    # An occurrence counts separately even when a caller aliases containers.
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > MAX_NODES:
            _fail("node_limit", path)
        kind = type(item)
        if kind is str:
            text_size += len(item)
            if text_size > MAX_BYTES:
                _fail("byte_limit", path)
            if _SURROGATE.search(item):
                _fail("lone_surrogate", path)
        elif kind is int:
            if not -SAFE_INTEGER <= item <= SAFE_INTEGER:
                _fail("unsafe_integer", path)
        elif kind is list or kind is dict:
            if depth > MAX_DEPTH:
                _fail("depth_limit", path)
            if count + len(stack) + len(item) > MAX_NODES:
                _fail("node_limit", path)
            if kind is dict:
                for key in item:
                    if type(key) is not str:
                        _fail("non_string_key", path)
                    text_size += len(key)
                    if text_size > MAX_BYTES:
                        _fail("byte_limit", path)
                    if _SURROGATE.search(key):
                        _fail("lone_surrogate", path)
                stack.extend((v, depth + 1) for v in item.values())
            else:
                stack.extend((v, depth + 1) for v in item)
        elif item is not None and kind is not bool:
            _fail("non_json_type", path)
    # iterencode avoids allocating an unbounded aggregate representation.
    size = 0
    for chunk in json.JSONEncoder(sort_keys=True, ensure_ascii=True,
                                  separators=(",", ":"), allow_nan=False).iterencode(value):
        size += len(chunk)
        if size > MAX_BYTES:
            _fail("byte_limit", path)


def _closed(value: Any, required: set[str], path: str,
            optional: frozenset[str] = frozenset()) -> None:
    if type(value) is not dict:
        _fail("expected_object", path)
    if not required <= value.keys():
        _fail("missing_field", path)
    if value.keys() - required - optional:
        _fail("unknown_field", path)


def _text(value: Any, path: str) -> None:
    if type(value) is not str or not value.strip():
        _fail("expected_nonempty_string", path)


def _enum(value: Any, choices: set[str], path: str) -> None:
    if type(value) is not str or value not in choices:
        _fail("invalid_enum", path)


def _timestamp(value: Any, path: str) -> tuple[int, str]:
    """Compare fractions exactly, without datetime's microsecond truncation."""
    if type(value) is not str:
        _fail("invalid_timestamp", path)
    match = _TIME.fullmatch(value)
    if match is None:
        _fail("invalid_timestamp", path)
    year, month, day, hour, minute, second = map(int, match.group(1, 2, 3, 4, 5, 6))
    try:
        date = datetime(year, month, day, hour, minute, second)
    except ValueError:
        _fail("invalid_timestamp", path)
    zone = match.group(8)
    offset = 0
    if zone not in ("Z", "z"):
        zh, zm = int(zone[1:3]), int(zone[4:6])
        if zh > 23 or zm > 59:
            _fail("invalid_timestamp", path)
        offset = (zh * 60 + zm) * 60 * (1 if zone[0] == "+" else -1)
    seconds = date.toordinal() * 86400 + hour * 3600 + minute * 60 + second - offset
    return seconds, (match.group(7) or "").rstrip("0")


def _pointer(value: Any, path: str) -> None:
    if type(value) is not str:
        _fail("invalid_pointer", path)
    # The empty pointer denotes the whole observed subject. Tokens are literal;
    # selector/wildcard syntax is outside this restricted query language.
    if (value and not value.startswith("/")) or any(c in value for c in "*[]"):
        _fail("invalid_pointer", path)
    if re.search(r"~(?![01])", value):
        _fail("invalid_pointer", path)


def _digest(document: dict) -> str:
    return hashlib.sha256(_canonical({k: v for k, v in document.items()
                                      if k != "integrity"})).hexdigest()


def _validate(document: Any, *, digest: bool = True) -> None:
    _profile(document)
    _closed(document, _ROOT, "$")
    if document["format"] != FORMAT:
        _fail("invalid_format", "$.format")
    _text(document["observation_id"], "$.observation_id")
    start = _timestamp(document["observed_at"], "$.observed_at")
    end = _timestamp(document["valid_until"], "$.valid_until")
    if start >= end:
        _fail("invalid_interval", "$.valid_until")
    subject = document["subject"]
    _closed(subject, _SUBJECT, "$.subject")
    for field in sorted(_SUBJECT - {"configuration_epoch"}):
        _text(subject[field], "$.subject." + field)
    epoch = subject["configuration_epoch"]
    if type(epoch) is not int or epoch < 0:
        _fail("invalid_epoch", "$.subject.configuration_epoch")
    source = document["source"]
    _closed(source, {"repository", "revision", "path"}, "$.source")
    for field in ("repository", "revision", "path"):
        _text(source[field], "$.source." + field)
    # Explicit namespaces are opaque identifiers; neither form is dereferenced.
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+|[A-Za-z][A-Za-z0-9+.-]*:[^\s]+", source["repository"]):
        _fail("invalid_repository", "$.source.repository")
    if not re.fullmatch(r"[0-9a-f]{40}", source["revision"]):
        _fail("invalid_revision", "$.source.revision")
    source_path = source["path"]
    if (any(c in source_path for c in "\\:") or any(ord(c) < 32 for c in source_path)
            or any(part in ("", ".", "..") for part in source_path.split("/"))):
        _fail("invalid_source_path", "$.source.path")
    assertions = document["assertions"]
    if type(assertions) is not list:
        _fail("expected_array", "$.assertions")
    if len(assertions) > MAX_ASSERTIONS:
        _fail("assertion_limit", "$.assertions")
    seen: set[str] = set()
    for index, assertion in enumerate(assertions):
        p = f"$.assertions[{index}]"
        _closed(assertion, {"path", "status", "basis", "evidence_ref"}, p, frozenset({"value"}))
        _pointer(assertion["path"], p + ".path")
        if assertion["path"] in seen:
            _fail("duplicate_pointer", p + ".path")
        seen.add(assertion["path"])
        _enum(assertion["status"], _STATUSES, p + ".status")
        _enum(assertion["basis"], _BASES, p + ".basis")
        _text(assertion["evidence_ref"], p + ".evidence_ref")
        if (assertion["status"] == "known") != ("value" in assertion):
            _fail("value_presence", p)
    if type(document["links"]) is not list:
        _fail("expected_array", "$.links")
    for index, link in enumerate(document["links"]):
        p = f"$.links[{index}]"
        _closed(link, {"rel", "namespace", "id", "revision"}, p)
        _enum(link["rel"], _RELS, p + ".rel")
        for field in ("namespace", "id", "revision"):
            _text(link[field], p + "." + field)
    _closed(document["receipts"], _RECEIPTS, "$.receipts")
    for field in sorted(_RECEIPTS):
        _enum(document["receipts"][field], _OUTCOMES, "$.receipts." + field)
    integrity = document["integrity"]
    _closed(integrity, {"algorithm", "sha256"}, "$.integrity")
    if integrity["algorithm"] != ALGORITHM:
        _fail("invalid_algorithm", "$.integrity.algorithm")
    if type(integrity["sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", integrity["sha256"]):
        _fail("invalid_digest", "$.integrity.sha256")
    if digest and integrity["sha256"] != _digest(document):
        _fail("digest_mismatch", "$.integrity.sha256")


def validate_observation(document: dict) -> list[str]:
    """Return zero or one bounded, deterministic path/reason diagnostics."""
    try:
        _validate(document)
    except ObservationError as error:
        return error.errors.copy()
    return []


def seal_observation(document: dict) -> dict:
    """Deep copy and seal an unsigned or previously sealed observation.

    Existing integrity must have valid shape/algorithm, but its digest is
    replaced. All other content is validated; no unknown fields are dropped.
    """
    _profile(document)
    if type(document) is not dict:
        _fail("expected_object")
    copied = json.loads(_canonical(document))
    if "integrity" not in copied:
        copied["integrity"] = {"algorithm": ALGORITHM, "sha256": "0" * 64}
    _validate(copied, digest=False)
    copied["integrity"]["sha256"] = _digest(copied)
    _validate(copied)
    return copied


def load_observation(raw: bytes) -> dict:
    """Strict UTF-8 JSON; reject duplicate keys and forbidden numbers at parse."""
    if type(raw) is not bytes:
        _fail("expected_bytes")
    if len(raw) > MAX_BYTES:
        _fail("byte_limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ObservationError("invalid_utf8") from None
    # Bound the stdlib recursive decoder before it sees hostile nesting. JSON
    # syntax itself is still checked by json.loads; braces in strings are inert.
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                _fail("depth_limit")
        elif char in "]}":
            depth -= 1

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result: dict = {}
        for key, value in items:
            if key in result:
                _fail("duplicate_key")
            result[key] = value
        return result

    def integer(token: str) -> int:
        # Avoid Python's integer-string limit, huge integer allocations, and
        # silently rounded values. Leading zeros remain the decoder's concern.
        if len(token.lstrip("-")) > 16:
            _fail("unsafe_integer")
        value = int(token)
        if not -SAFE_INTEGER <= value <= SAFE_INTEGER:
            _fail("unsafe_integer")
        return value

    def forbidden_number(token: str) -> Any:
        _fail("non_integer_number")

    try:
        document = json.loads(text, object_pairs_hook=pairs, parse_int=integer,
                              parse_float=forbidden_number, parse_constant=forbidden_number)
    except (json.JSONDecodeError, RecursionError):
        raise ObservationError("invalid_json") from None
    _validate(document)
    return document


def _expression(expression: Any) -> None:
    _profile(expression, "$.expression")
    stack = [(expression, 1)]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > MAX_EXPRESSION_NODES:
            _fail("expression_node_limit", "$.expression")
        if depth > MAX_EXPRESSION_DEPTH:
            _fail("expression_depth_limit", "$.expression")
        if type(node) is not dict or len(node) != 1:
            _fail("invalid_expression", "$.expression")
        op = next(iter(node))
        body = node[op]
        if op in ("all", "any"):
            if type(body) is not list or not body:
                _fail("expected_nonempty_array", "$.expression")
            stack.extend((child, depth + 1) for child in body)
        elif op in ("eq", "exists"):
            _closed(body, {"path", "value"}, "$.expression")
            _pointer(body["path"], "$.expression.path")
            if op == "exists" and type(body["value"]) is not bool:
                _fail("expected_boolean", "$.expression.value")
        else:
            _fail("unknown_operator", "$.expression")


def _equal(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(_equal(left[k], right[k]) for k in left)
    if type(left) is list:
        return len(left) == len(right) and all(_equal(a, b) for a, b in zip(left, right))
    return left == right


def evaluate_observation(document: dict, expression: dict, *, at: str) -> dict:
    """Evaluate all leaves with Kleene logic and sorted evidence limitations."""
    _validate(document)
    _expression(expression)
    _profile(at, "$.at")
    instant = _timestamp(at, "$.at")
    fresh_reason = None
    if instant < _timestamp(document["observed_at"], "$.observed_at"):
        fresh_reason = "not_yet_valid"
    elif instant >= _timestamp(document["valid_until"], "$.valid_until"):
        fresh_reason = "expired"
    evidence = {entry["path"]: entry for entry in document["assertions"]}
    reasons: set[str] = set()

    def visit(node: dict) -> str:
        op = next(iter(node))
        body = node[op]
        if op in ("all", "any"):
            values = [visit(child) for child in body]
            if op == "all":
                return "false" if "false" in values else "unknown" if "unknown" in values else "true"
            return "true" if "true" in values else "unknown" if "unknown" in values else "false"
        limitations: set[str] = set()
        if fresh_reason:
            limitations.add(fresh_reason)
        entry = evidence.get(body["path"])
        if entry is None:
            limitations.add("missing_evidence")
        else:
            if entry["basis"] != "observed":
                limitations.add("non_observed_evidence")
            if entry["status"] != "known":
                limitations.add(entry["status"] + "_evidence")
        reasons.update(limitations)
        if limitations:
            return "unknown"
        agrees = body["value"] if op == "exists" else _equal(entry["value"], body["value"])
        return "true" if agrees else "false"

    result = visit(expression)
    subject = document["subject"]
    return {"format": "acve-observation-result/0.1.0",
            "observation_id": document["observation_id"],
            "observation_sha256": document["integrity"]["sha256"],
            "execution_id": subject["execution_id"], "session_id": subject["session_id"],
            "configuration_epoch": subject["configuration_epoch"],
            "result": result, "reasons": sorted(reasons)}
