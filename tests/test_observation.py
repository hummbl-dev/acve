"""Synthetic contract, negative, and boundary tests; stdlib unittest only."""

import copy
import hashlib
import itertools
import json
from pathlib import Path
import unittest

from acve import observation as obs
from acve.validator import validate


ROOT = Path(__file__).resolve().parents[1]
AT = "2026-01-01T12:30:00Z"


def unsigned():
    return {
        "format": obs.FORMAT, "observation_id": "synthetic-1",
        "observed_at": "2026-01-01T12:00:00Z", "valid_until": "2026-01-01T13:00:00Z",
        "subject": {"agent": "example", "host": "example-host", "surface": "example-cli",
                    "session_id": "session-1", "execution_id": "execution-1", "configuration_epoch": 0},
        "source": {"repository": "example/repo", "revision": "a" * 40, "path": "fixtures/source.json"},
        "assertions": [assertion("/value", True)],
        "links": [{"rel": "objective", "namespace": "example/objectives", "id": "one", "revision": "1"}],
        "receipts": {"invocation": "succeeded", "transport": "unknown", "durability": "failed", "evaluation": "not_attempted"},
    }


def assertion(path, value=None, status="known", basis="observed"):
    result = {"path": path, "status": status, "basis": basis, "evidence_ref": "synthetic:receipt"}
    if status == "known":
        result["value"] = value
    return result


def eq(path="/value", value=True):
    return {"eq": {"path": path, "value": value}}


def wire(document):
    return json.dumps(document, ensure_ascii=True, separators=(",", ":")).encode("ascii")


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.base = unsigned()
        self.document = obs.seal_observation(self.base)

    def evaluate(self, expression=None, document=None, at=AT):
        return obs.evaluate_observation(self.document if document is None else document,
                                        eq() if expression is None else expression, at=at)

    def rejects_document(self, document):
        with self.assertRaises(obs.ObservationError):
            obs.seal_observation(document)
        self.assertTrue(obs.validate_observation(document))

    def test_seal_is_deep_copy_and_roundtrip(self):
        original = copy.deepcopy(self.base)
        sealed = obs.seal_observation(self.base)
        self.assertEqual(self.base, original)
        self.assertEqual(obs.validate_observation(sealed), [])
        self.assertEqual(obs.load_observation(wire(sealed)), sealed)
        self.assertEqual(obs.seal_observation(sealed), sealed)
        sealed["assertions"][0]["value"] = None
        self.assertEqual(self.base, original)

    def test_digest_external_oracle_and_unicode_key_order(self):
        # U+10000 sorts after U+E000 by scalar order (unlike UTF-16/JCS).
        self.base["assertions"][0]["value"] = {"\U00010000": "café", "\ue000": [None, -1, False]}
        canonical = json.dumps(self.base, sort_keys=True, ensure_ascii=True,
                               separators=(",", ":"), allow_nan=False).encode("ascii")
        sealed = obs.seal_observation(self.base)
        self.assertEqual(sealed["integrity"]["sha256"], hashlib.sha256(canonical).hexdigest())
        reversed_document = dict(reversed(list(self.base.items())))
        self.assertEqual(obs.seal_observation(reversed_document), sealed)

    def test_digest_binds_every_root_field(self):
        for key in self.base:
            with self.subTest(key=key):
                bad = copy.deepcopy(self.document)
                del bad[key]
                self.assertTrue(obs.validate_observation(bad))
        for field, value in (("observed_at", "2026-01-01T12:00:01Z"),
                             ("observation_id", "synthetic-2"),
                             ("valid_until", "2026-01-01T13:00:01Z")):
            changed = copy.deepcopy(self.document)
            changed[field] = value
            with self.assertRaises(obs.ObservationError) as caught:
                self.evaluate(document=changed)
            self.assertEqual(caught.exception.code, "digest_mismatch")
            self.assertNotEqual(obs.seal_observation(changed)["integrity"], self.document["integrity"])

    def test_result_identity_and_receipts_are_independent(self):
        result = self.evaluate()
        self.assertEqual(result, {
            "format": "acve-observation-result/0.1.0", "observation_id": "synthetic-1",
            "observation_sha256": self.document["integrity"]["sha256"],
            "execution_id": "execution-1", "session_id": "session-1", "configuration_epoch": 0,
            "result": "true", "reasons": [],
        })
        other = copy.deepcopy(self.base)
        other["subject"].update(session_id="session-2", execution_id="execution-2", configuration_epoch=1)
        other["receipts"] = {k: "failed" for k in other["receipts"]}
        result = self.evaluate(document=obs.seal_observation(other))
        self.assertEqual(result["result"], "true")
        self.assertEqual(result["session_id"], "session-2")
        self.assertEqual(result["configuration_epoch"], 1)

    def test_all_status_basis_combinations(self):
        for status, basis in itertools.product(("known", "unknown", "invalid", "unavailable"),
                                              ("observed", "configured", "inferred")):
            with self.subTest(status=status, basis=basis):
                self.base["assertions"] = [assertion("/value", True, status, basis)]
                result = self.evaluate(document=obs.seal_observation(self.base))
                reasons = []
                if status != "known":
                    reasons.append(status + "_evidence")
                if basis != "observed":
                    reasons.append("non_observed_evidence")
                self.assertEqual(result["reasons"], sorted(reasons))
                self.assertEqual(result["result"], "unknown" if reasons else "true")

    def test_missing_null_and_exists_false(self):
        self.base["assertions"] = [assertion("/null", None)]
        sealed = obs.seal_observation(self.base)
        for value, expected in ((True, "true"), (False, "false")):
            self.assertEqual(self.evaluate({"exists": {"path": "/null", "value": value}}, sealed)["result"], expected)
            result = self.evaluate({"exists": {"path": "/missing", "value": value}}, sealed)
            self.assertEqual(result["result"], "unknown")
            self.assertEqual(result["reasons"], ["missing_evidence"])
        self.assertEqual(self.evaluate(eq("/null", None), sealed)["result"], "true")

    def test_nested_type_aware_equality(self):
        pairs = [(True, 1, False), (False, 0, False), ([True], [1], False),
                 ({"nested": [True]}, {"nested": [1]}, False),
                 ({"a": 1, "b": None}, {"b": None, "a": 1}, True),
                 ([1, 2], [2, 1], False), ([], {}, False), (None, False, False),
                 ("1", 1, False), (0, 0, True)]
        for left, right, expected in pairs:
            with self.subTest(left=left, right=right):
                self.base["assertions"] = [assertion("/value", left)]
                result = self.evaluate(eq(value=right), obs.seal_observation(self.base))
                self.assertEqual(result["result"], str(expected).lower())

    def test_complete_kleene_truth_tables(self):
        expressions = {"true": eq(), "false": eq(value=False), "unknown": eq("/missing")}
        for op, left, right in itertools.product(("all", "any"), expressions, expressions):
            with self.subTest(op=op, left=left, right=right):
                values = (left, right)
                if op == "all":
                    expected = "false" if "false" in values else "unknown" if "unknown" in values else "true"
                else:
                    expected = "true" if "true" in values else "unknown" if "unknown" in values else "false"
                result = self.evaluate({op: [expressions[left], expressions[right]]})
                self.assertEqual(result["result"], expected)
                self.assertEqual(result["reasons"], ["missing_evidence"] if "unknown" in values else [])

    def test_reasons_deduplicated_sorted_and_not_short_circuited(self):
        self.base["assertions"].extend([assertion("/bad", status="invalid", basis="configured"),
                                        assertion("/offline", status="unavailable")])
        expression = {"any": [eq(), {"all": [eq("/bad"), eq("/offline"), eq("/missing"), eq("/missing")]}]}
        result = self.evaluate(expression, obs.seal_observation(self.base))
        self.assertEqual(result["result"], "true")
        self.assertEqual(result["reasons"], ["invalid_evidence", "missing_evidence", "non_observed_evidence", "unavailable_evidence"])
        result = self.evaluate(expression, obs.seal_observation(self.base), at="2026-01-01T13:00:00Z")
        self.assertEqual(result["result"], "unknown")
        self.assertIn("expired", result["reasons"])
        self.assertIn("missing_evidence", result["reasons"])

    def test_freshness_boundaries_and_offsets(self):
        for at, expected, reasons in [
            ("2026-01-01T11:59:59.999999999Z", "unknown", ["not_yet_valid"]),
            ("2026-01-01T12:00:00Z", "true", []),
            ("2026-01-01T07:00:00-05:00", "true", []),
            ("2026-01-01T13:00:00+01:00", "true", []),
            ("2026-01-01T12:59:59.999999999Z", "true", []),
            ("2026-01-01T13:00:00Z", "unknown", ["expired"]),
            ("2026-01-01T14:00:00+01:00", "unknown", ["expired"]),
            ("2026-01-01t12:30:00z", "true", []),
        ]:
            with self.subTest(at=at):
                result = self.evaluate(at=at)
                self.assertEqual((result["result"], result["reasons"]), (expected, reasons))

    def test_submicrosecond_precision(self):
        self.base["observed_at"] = "2026-01-01T12:00:00.000000001Z"
        self.base["valid_until"] = "2026-01-01T12:00:00.000000002Z"
        sealed = obs.seal_observation(self.base)
        self.assertEqual(self.evaluate(document=sealed, at=self.base["observed_at"])["result"], "true")
        self.assertEqual(self.evaluate(document=sealed, at=self.base["valid_until"])["reasons"], ["expired"])
        self.base["valid_until"] = "2026-01-01T12:00:00.0000000010Z"
        self.rejects_document(self.base)

    def test_invalid_timestamps_and_intervals(self):
        invalid = [None, True, 1, "", "2026-01-01", "2026-01-01T12:00:00",
                   "2026-02-29T12:00:00Z", "2026-01-01T24:00:00Z",
                   "2026-01-01T12:00:00+24:00", "2026-01-01T12:00:00+01:60",
                   "2026-01-01 12:00:00Z", "2026-01-01T12:00:00Z\n",
                   "2026-01-01T12:00:00. Z", "2026-01-01T12:00:00+0000"]
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(obs.ObservationError):
                    self.evaluate(at=value)
        for value in ("2026-01-01T12:00:00Z", "2026-01-01T11:00:00Z", "2026-01-01T13:00:00+01:00"):
            bad = copy.deepcopy(self.base)
            bad["valid_until"] = value
            self.rejects_document(bad)

    def test_exact_pointers_not_traversal(self):
        self.base["assertions"] = [assertion("", "root"), assertion("/a~1b/~0x", 7),
                                   assertion("/parent", {"child": True}), assertion("/", None)]
        sealed = obs.seal_observation(self.base)
        self.assertEqual(self.evaluate(eq("/a~1b/~0x", 7), sealed)["result"], "true")
        self.assertEqual(self.evaluate(eq("", "root"), sealed)["result"], "true")
        self.assertEqual(self.evaluate(eq("/parent/child"), sealed)["result"], "unknown")
        self.assertEqual(self.evaluate(eq("/", None), sealed)["result"], "true")

    def test_bad_pointers_and_duplicates(self):
        for path in (None, [], "not/a/pointer", "#/a", "/a~", "/a~2", "/tools/*", "/tools[0]", "/[?x]"):
            with self.subTest(path=path):
                self.base["assertions"] = [assertion(path)]
                self.rejects_document(self.base)
                with self.assertRaises(obs.ObservationError):
                    self.evaluate(eq(path))
        self.base["assertions"] = [assertion("/a"), assertion("/a")]
        self.rejects_document(self.base)

    def test_closed_envelopes_missing_and_extra_fields(self):
        paths = [(), ("subject",), ("source",), ("assertions", 0), ("links", 0), ("receipts",), ("integrity",)]
        for path in paths:
            container = self.document
            for part in path:
                container = container[part]
            for key in container:
                if key == "value":
                    continue
                bad = copy.deepcopy(self.document)
                target = bad
                for part in path:
                    target = target[part]
                del target[key]
                with self.subTest(path=path, missing=key):
                    self.assertTrue(obs.validate_observation(bad))
            bad = copy.deepcopy(self.document)
            target = bad
            for part in path:
                target = target[part]
            target["unexpected"] = True
            with self.subTest(path=path, extra=True):
                self.rejects_document(bad)

    def test_all_envelope_type_errors_are_structured(self):
        for field in self.document:
            for value in (None, [], {}, True, 1):
                if field in ("links", "assertions") and value == []:
                    continue
                with self.subTest(field=field, value=value):
                    bad = copy.deepcopy(self.document)
                    bad[field] = value
                    self.rejects_document(bad)
        for value in (None, [], 1, True, "string"):
            self.rejects_document(value)

    def test_status_requires_value_iff_known(self):
        for status in ("unknown", "invalid", "unavailable"):
            self.base["assertions"] = [assertion("/value", status=status)]
            self.base["assertions"][0]["value"] = None
            self.rejects_document(self.base)
        self.base["assertions"] = [assertion("/value")]
        del self.base["assertions"][0]["value"]
        self.rejects_document(self.base)

    def test_strict_source_paths_and_revision(self):
        for value in ("../outside", "/absolute", "C:/drive", "a\\b", "a/../b", "a//b", "./a", "a/", "a\x00b"):
            self.base["source"]["path"] = value
            with self.subTest(path=value):
                self.rejects_document(self.base)
        self.base["source"]["path"] = "folder/source.json"
        for value in ("A" * 40, "a" * 39, "a" * 41, "a" * 40 + "\n"):
            self.base["source"]["revision"] = value
            self.rejects_document(self.base)
        self.base["source"]["revision"] = "a" * 40
        self.base["source"]["repository"] = "urn:synthetic:repository"
        self.assertEqual(obs.validate_observation(obs.seal_observation(self.base)), [])

    def test_empty_identity_fields_and_invalid_enums(self):
        for field in ("agent", "host", "surface", "session_id", "execution_id"):
            bad = copy.deepcopy(self.base)
            bad["subject"][field] = ""
            self.rejects_document(bad)
        for field in ("status", "basis", "evidence_ref"):
            bad = copy.deepcopy(self.base)
            bad["assertions"][0][field] = ""
            self.rejects_document(bad)
        for epoch in (-1, True, False, 0.0, "0", obs.SAFE_INTEGER + 1):
            bad = copy.deepcopy(self.base)
            bad["subject"]["configuration_epoch"] = epoch
            self.rejects_document(bad)

    def test_integrity_shape_algorithm_and_hash(self):
        for integrity in (None, {}, {"algorithm": "wrong", "sha256": "0" * 64},
                          {"algorithm": obs.ALGORITHM, "sha256": "A" * 64},
                          {"algorithm": obs.ALGORITHM, "sha256": "0" * 64, "extra": True}):
            bad = copy.deepcopy(self.base)
            bad["integrity"] = integrity
            self.rejects_document(bad)
        self.document["integrity"]["sha256"] = "0" * 64
        with self.assertRaises(obs.ObservationError):
            obs.load_observation(wire(self.document))

    def test_mutation_invalidates_prior_validation(self):
        self.assertEqual(obs.validate_observation(self.document), [])
        self.document["assertions"][0]["value"] = False
        with self.assertRaises(obs.ObservationError):
            self.evaluate()

    def test_parser_duplicate_keys_at_every_depth(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":{"a":1,"a":2}}',
                    b'{"x":[{"a":1,"\\u0061":2}]}'):
            with self.assertRaises(obs.ObservationError) as caught:
                obs.load_observation(raw)
            self.assertEqual(caught.exception.code, "duplicate_key")

    def test_parser_invalid_encoding_syntax_and_numbers(self):
        for raw in (b"", b"\xff", b"\xef\xbb\xbf{}", b"{} trailing", b"{}{}", b'{"a":01}',
                    b'{"a":1.0}', b'{"a":1e0}', b'{"a":NaN}', b'{"a":Infinity}',
                    b'{"a":-Infinity}', b'{"a":9007199254740992}',
                    b'{"a":' + b"9" * 5000 + b"}", b'{"a":"\\ud800"}',
                    b'{"\\udfff":1}', b'{"a":"\x01"}'):
            with self.subTest(raw=raw[:40]):
                with self.assertRaises(obs.ObservationError):
                    obs.load_observation(raw)
        for raw in ("{}", bytearray(b"{}"), None):
            with self.assertRaises(obs.ObservationError):
                obs.load_observation(raw)

    def test_parser_strings_do_not_count_as_nesting(self):
        self.base["assertions"][0]["value"] = "[" * 100 + '"\\' + "]" * 100
        sealed = obs.seal_observation(self.base)
        self.assertEqual(obs.load_observation(wire(sealed)), sealed)
        with self.assertRaises(obs.ObservationError) as caught:
            obs.load_observation(b"[" * 100000 + b"]" * 100000)
        self.assertEqual(caught.exception.code, "depth_limit")

    def test_json_profile_negatives_and_safe_endpoints(self):
        for value in (1.0, float("nan"), float("inf"), (), set(), b"bytes", {1: "bad"},
                      "\ud800", {"\udfff": None}, obs.SAFE_INTEGER + 1, -obs.SAFE_INTEGER - 1):
            self.base["assertions"][0]["value"] = value
            self.rejects_document(self.base)
        for value in (obs.SAFE_INTEGER, -obs.SAFE_INTEGER, "\U0001f600"):
            self.base["assertions"][0]["value"] = value
            sealed = obs.seal_observation(self.base)
            self.assertEqual(obs.load_observation(wire(sealed)), sealed)

    def test_cycles_and_aliases(self):
        cycle = []
        cycle.append(cycle)
        self.base["assertions"][0]["value"] = cycle
        self.rejects_document(self.base)
        shared = {"a": [1, 2]}
        self.base["assertions"][0]["value"] = [shared, shared]
        sealed = obs.seal_observation(self.base)
        sealed["assertions"][0]["value"][0]["a"].append(3)
        self.assertEqual(shared, {"a": [1, 2]})

    def test_aliased_strings_are_charged_per_occurrence(self):
        large = "a" * (obs.MAX_BYTES // 2)
        self.base["assertions"][0]["value"] = [large] * 100
        self.rejects_document(self.base)

    def test_adversarial_json_mutations_raise_only_structured_errors(self):
        # Exercise bad primitive and container types at every envelope field,
        # including unhashable enum values and dict keys in value payloads.
        replacements = [None, True, False, -1, 0, "", "wrong", [], {}, [None],
                        {"x": 1}, 0.5, "\ud800", {1: None}]
        paths = []
        def fields(value, path=()):
            if type(value) is dict:
                for key, child in value.items():
                    child_path = path + (key,)
                    paths.append(child_path)
                    fields(child, child_path)
            elif type(value) is list:
                for index, child in enumerate(value):
                    fields(child, path + (index,))
        fields(self.document)
        for path, replacement in itertools.product(paths, replacements):
            bad = copy.deepcopy(self.document)
            target = bad
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = replacement
            with self.subTest(path=path, replacement_type=type(replacement).__name__):
                errors = obs.validate_observation(bad)
                self.assertIsInstance(errors, list)
                self.assertLessEqual(len(errors), 1)
                try:
                    sealed = obs.seal_observation(bad)
                except obs.ObservationError:
                    continue
                self.assertEqual(obs.validate_observation(sealed), [])
                self.assertEqual(obs.load_observation(wire(sealed)), sealed)

    def test_assertion_limit(self):
        self.base["assertions"] = [assertion(f"/{i}") for i in range(obs.MAX_ASSERTIONS)]
        self.assertEqual(obs.validate_observation(obs.seal_observation(self.base)), [])
        self.base["assertions"].append(assertion("/overflow"))
        self.rejects_document(self.base)

    def test_byte_limit_at_boundary_and_over(self):
        self.base["assertions"][0]["value"] = ""
        overhead = len(wire(obs.seal_observation(self.base)))
        self.base["assertions"][0]["value"] = "a" * (obs.MAX_BYTES - overhead)
        sealed = obs.seal_observation(self.base)
        self.assertEqual(len(wire(sealed)), obs.MAX_BYTES)
        self.assertEqual(obs.load_observation(wire(sealed)), sealed)
        with self.assertRaises(obs.ObservationError):
            obs.load_observation(wire(sealed) + b" ")
        self.base["assertions"][0]["value"] += "a"
        self.rejects_document(self.base)
        self.base["assertions"][0]["value"] = "é" * (obs.MAX_BYTES // 6)
        self.rejects_document(self.base)

    def test_depth_limit_exact_boundary(self):
        # Root(1), assertions(2), assertion(3), then 29 lists: 32 containers.
        value = None
        for _ in range(29):
            value = [value]
        self.base["assertions"][0]["value"] = value
        sealed = obs.seal_observation(self.base)
        self.assertEqual(obs.load_observation(wire(sealed)), sealed)
        self.base["assertions"][0]["value"] = [value]
        self.rejects_document(self.base)

    def test_node_limit_exact_boundary(self):
        def nodes(value):
            if type(value) is dict:
                return 1 + sum(nodes(v) for v in value.values())
            if type(value) is list:
                return 1 + sum(nodes(v) for v in value)
            return 1
        self.base["assertions"][0]["value"] = []
        overhead = nodes(obs.seal_observation(self.base))
        self.base["assertions"][0]["value"] = [None] * (obs.MAX_NODES - overhead)
        sealed = obs.seal_observation(self.base)
        self.assertEqual(nodes(sealed), obs.MAX_NODES)
        self.assertEqual(obs.load_observation(wire(sealed)), sealed)
        self.base["assertions"][0]["value"].append(None)
        self.rejects_document(self.base)

    def test_expression_shape_negatives_even_in_dominated_branch(self):
        invalid = [None, [], {}, {"not": eq()}, {"all": []}, {"any": []}, {"all": eq()},
                   {"eq": {"path": "/value"}}, {"eq": {"value": True}},
                   {"eq": {"path": "/value", "value": True, "extra": True}},
                   {"eq": {"path": "/value", "value": 1.0}},
                   {"exists": {"path": "/value", "value": 1}},
                   {"all": [eq()], "any": [eq()]}]
        for expression in invalid:
            with self.subTest(expression=expression):
                with self.assertRaises(obs.ObservationError):
                    self.evaluate({"any": [eq(), expression]})

    def test_expression_node_limit(self):
        expression = {"all": [eq() for _ in range(obs.MAX_EXPRESSION_NODES - 1)]}
        self.assertEqual(self.evaluate(expression)["result"], "true")
        expression["all"].append(eq())
        with self.assertRaises(obs.ObservationError):
            self.evaluate(expression)

    def test_expression_depth_limit(self):
        expression = eq()
        for _ in range(obs.MAX_EXPRESSION_DEPTH - 1):
            expression = {"all": [expression]}
        self.assertEqual(self.evaluate(expression)["result"], "true")
        with self.assertRaises(obs.ObservationError):
            self.evaluate({"all": [expression]})

    def test_diagnostics_do_not_echo_untrusted_values_or_keys(self):
        marker = "synthetic-sensitive-marker"
        bad = copy.deepcopy(self.document)
        bad[marker] = marker * 10000
        errors = obs.validate_observation(bad)
        self.assertEqual(len(errors), 1)
        self.assertNotIn(marker, errors[0])
        self.assertLess(len(errors[0]), 200)
        with self.assertRaises(obs.ObservationError) as caught:
            obs.load_observation(b'{"synthetic-sensitive-marker":1,"synthetic-sensitive-marker":2}')
        self.assertNotIn(marker, str(caught.exception))
        self.assertEqual(caught.exception.path, "$")

    def test_schema_uses_supported_subset_and_closed_shapes(self):
        schema = json.loads((ROOT / "schemas/observation.schema.json").read_text(encoding="utf-8"))
        supported = {"title", "description", "type", "required", "properties", "enum", "pattern",
                     "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems",
                     "items", "additionalProperties", "const", "oneOf", "anyOf"}
        def check(node):
            self.assertLessEqual(node.keys(), supported)
            for child in node.get("properties", {}).values():
                check(child)
            if "items" in node:
                check(node["items"])
            for op in ("oneOf", "anyOf"):
                for child in node.get(op, []):
                    check(child)
        check(schema)
        self.assertEqual(validate(self.document, schema), [])
        for path in ((), ("subject",), ("source",), ("assertions", 0), ("links", 0), ("receipts",), ("integrity",)):
            bad = copy.deepcopy(self.document)
            target = bad
            for part in path:
                target = target[part]
            target["extra"] = True
            self.assertTrue(validate(bad, schema), path)

    def test_shared_conformance_corpus(self):
        corpus = json.loads((ROOT / "conformance/observation-v0.1.0.json").read_text(encoding="utf-8"))
        for case in corpus["cases"]:
            with self.subTest(case=case["id"]):
                document = copy.deepcopy(corpus["base"])
                document.update(copy.deepcopy(case["changes"]))
                def run():
                    sealed = obs.seal_observation(document)
                    loaded = obs.load_observation(wire(sealed))
                    return obs.evaluate_observation(loaded, case["expression"], at=case["at"])
                if case["expected"].get("error"):
                    with self.assertRaises(obs.ObservationError):
                        run()
                else:
                    result = run()
                    for key, value in case["expected"].items():
                        self.assertEqual(result[key], value)


if __name__ == "__main__":
    unittest.main()
