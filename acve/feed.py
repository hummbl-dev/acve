"""Registry feed: records/*.json -> JSONL, with schema validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .validator import validate

_SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"


def load_schema(name: str) -> dict[str, Any]:
    """Load a bundled schema by basename, e.g. 'agent-vulnerability'."""
    path = _SCHEMAS_DIR / f"{name}.schema.json"
    if not path.exists():
        raise FileNotFoundError(f"schema not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def iter_records(records_dir: str | Path) -> list[tuple[Path, dict[str, Any]]]:
    """All records/*.json sorted by filename (which is the ACVE id)."""
    out = []
    for p in sorted(Path(records_dir).glob("ACVE-*.json")):
        out.append((p, json.loads(p.read_text(encoding="utf-8"))))
    return out


def build_feed(records_dir: str | Path, validate_records: bool = True) -> list[dict[str, Any]]:
    """Return the ordered record list for the feed. Raises on invalid records."""
    schema = load_schema("agent-vulnerability") if validate_records else None
    feed = []
    for path, rec in iter_records(records_dir):
        if schema is not None:
            errors = validate(rec, schema)
            if errors:
                raise ValueError(f"{path.name}: invalid record: {errors}")
        feed.append(rec)
    return feed


def write_feed(records_dir: str | Path, out_path: str | Path) -> int:
    """Write feed.jsonl (one record per line). Returns record count."""
    feed = build_feed(records_dir)
    lines = [json.dumps(r, separators=(",", ":"), ensure_ascii=True) for r in feed]
    Path(out_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(feed)
