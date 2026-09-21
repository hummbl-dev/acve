"""Tests for acve: schema validation, unit identity, and affected-matching.

Zero-dependency: runs via `python -m unittest discover -s tests -v`
(and under pytest if available).
"""

import copy
import json
import unittest
from pathlib import Path

import acve

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
RECORDS = ROOT / "records"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _example_lock() -> dict:
    return _load(EXAMPLES / "agent-lock.example.json")


def _feed_records() -> list[dict]:
    return [json.loads(l) for l in (EXAMPLES / "feed.example.jsonl").read_text().splitlines() if l.strip()]


class TestSchemaValidation(unittest.TestCase):
    def test_lock_example_valid(self):
        errors = acve.validate(_example_lock(), acve.load_schema("agent-lock"))
        self.assertEqual(errors, [])

    def test_seed_record_valid(self):
        rec = _load(RECORDS / "ACVE-2026-00001.json")
        errors = acve.validate(rec, acve.load_schema("agent-vulnerability"))
        self.assertEqual(errors, [])

    def test_feed_records_valid(self):
        schema = acve.load_schema("agent-vulnerability")
        for rec in _feed_records():
            self.assertEqual(acve.validate(rec, schema), [], rec["id"])

    def test_lock_missing_model_invalid(self):
        doc = _example_lock()
        del doc["model"]
        self.assertTrue(acve.validate(doc, acve.load_schema("agent-lock")))

    def test_record_bad_id_invalid(self):
        rec = _load(RECORDS / "ACVE-2026-00001.json")
        rec["id"] = "CVE-2026-1234"  # CVE- is MITRE's namespace
        errors = acve.validate(rec, acve.load_schema("agent-vulnerability"))
        self.assertTrue(any("id" in e for e in errors))


class TestUnitIdentity(unittest.TestCase):
    def test_example_hash_verifies(self):
        self.assertTrue(acve.verify(_example_lock()))

    def test_tamper_detected(self):
        doc = _example_lock()
        doc["model"]["parameters"]["temperature"] = 0.9
        self.assertFalse(acve.verify(doc))


class TestMatching(unittest.TestCase):
    def test_component_match(self):
        """Example lockfile runs fs-mcp@1.4.0; ACVE-2026-01001 affects <=1.4.0."""
        lock, recs = _example_lock(), _feed_records()
        hits = acve.scan(lock, recs)
        self.assertIn("ACVE-2026-01001", hits)
        self.assertEqual(hits["ACVE-2026-01001"][0]["unit"], "component")

    def test_configuration_match_negative(self):
        """pin=snapshot keeps the example out of ACVE-2026-01002's window."""
        hits = acve.scan(_example_lock(), _feed_records())
        self.assertNotIn("ACVE-2026-01002", hits)

    def test_configuration_match_positive(self):
        lock = _example_lock()
        lock["model"]["pin"] = "alias"
        hits = acve.scan(lock, _feed_records())
        self.assertIn("ACVE-2026-01002", hits)

    def test_seed_record_pinned_not_affected(self):
        """Example's MCP tool IS schema-pinned -> not affected by ACVE-2026-00001."""
        seed = _load(RECORDS / "ACVE-2026-00001.json")
        self.assertEqual(acve.match_lockfile(_example_lock(), seed), [])

    def test_seed_record_unpinned_affected(self):
        """Drop the schema_sha256 pin and the same deployment IS affected."""
        lock = copy.deepcopy(_example_lock())
        for t in lock["tools"]:
            t.pop("schema_sha256", None)
        seed = _load(RECORDS / "ACVE-2026-00001.json")
        hits = acve.match_lockfile(lock, seed)
        self.assertEqual(len(hits), 1)

    def test_component_version_out_of_range(self):
        lock = _example_lock()
        lock["tools"][1]["version"] = "1.4.1"  # fixed version
        hits = acve.scan(lock, _feed_records())
        self.assertNotIn("ACVE-2026-01001", hits)


class TestFeed(unittest.TestCase):
    def test_build_feed(self):
        feed = acve.build_feed(RECORDS)
        self.assertEqual(len(feed), len(list(RECORDS.glob("ACVE-*.json"))))
        self.assertTrue(all(r["id"].startswith("ACVE-") for r in feed))


if __name__ == "__main__":
    unittest.main()
