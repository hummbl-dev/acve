"""acve CLI: validate, hash, match, build-feed. Stdlib only.

    python -m acve validate <instance.json> <schema-name>
    python -m acve hash <lockfile.json> [--verify]
    python -m acve match <lockfile.json> <record.json | records-dir | feed.jsonl>
    python -m acve build-feed <records-dir> [-o feed.jsonl]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import lockhash, match
from .feed import iter_records, load_schema, write_feed
from .validator import validate


def _load_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _load_records(target: str) -> list[dict]:
    """A records dir, a .jsonl feed, or a single record .json."""
    p = Path(target)
    if p.is_dir():
        return [rec for _, rec in iter_records(p)]
    if p.suffix == ".jsonl":
        return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [_load_json(target)]


def cmd_validate(args) -> int:
    inst = _load_json(args.instance)
    schema = load_schema(args.schema) if not args.schema.endswith(".json") else _load_json(args.schema)
    errors = validate(inst, schema)
    for e in errors:
        print(e)
    print(f"{'VALID' if not errors else 'INVALID'}: {args.instance}")
    return 0 if not errors else 1


def cmd_hash(args) -> int:
    doc = _load_json(args.lockfile)
    computed = lockhash.config_sha256(doc)
    print(computed)
    if args.verify:
        ok = lockhash.verify(doc)
        print(f"{'VERIFIED' if ok else 'MISMATCH'}: claimed provenance.config_sha256")
        return 0 if ok else 1
    return 0


def cmd_match(args) -> int:
    lock = _load_json(args.lockfile)
    hits = match.scan(lock, _load_records(args.records))
    if not hits:
        print("no affected records")
        return 0
    for rid, entries in hits.items():
        print(f"AFFECTED: {rid}")
        for e in entries:
            unit = e.get("unit")
            label = e.get("component", {}).get("name") if unit == "component" else "configuration"
            print(f"  - unit={unit} target={label}")
    return 2  # nonzero = affected, for shell/CI gating


def cmd_build_feed(args) -> int:
    n = write_feed(args.records_dir, args.out)
    print(f"wrote {n} records -> {args.out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="acve", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("validate", help="validate a JSON instance against a schema")
    v.add_argument("instance")
    v.add_argument("schema", help="schema name (agent-lock | agent-vulnerability) or path")
    v.set_defaults(fn=cmd_validate)

    h = sub.add_parser("hash", help="compute config_sha256 for a lockfile")
    h.add_argument("lockfile")
    h.add_argument("--verify", action="store_true", help="compare against provenance.config_sha256")
    h.set_defaults(fn=cmd_hash)

    m = sub.add_parser("match", help="match a lockfile against AVR records")
    m.add_argument("lockfile")
    m.add_argument("records", help="records dir, feed.jsonl, or a single record file")
    m.set_defaults(fn=cmd_match)

    b = sub.add_parser("build-feed", help="build feed.jsonl from records/")
    b.add_argument("records_dir")
    b.add_argument("-o", "--out", default="feed.jsonl")
    b.set_defaults(fn=cmd_build_feed)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
