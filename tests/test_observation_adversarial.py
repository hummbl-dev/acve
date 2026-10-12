"""Adversarial author-session support for the observation 0.1.0 contract.

Fixtures and digest oracle are independent of the conformance corpus and of
the enterprise implementation. Rejections must be structured, not no-hits.
"""

import copy
import hashlib
import itertools
import json
import unittest

from acve import observation as obs


AT = "2026-10-12T12:00:00Z"
BYTE_LIMIT = 1048576


def wire(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def signed(value=None):
    document = {
        "format": "acve-observation/0.1.0",
        "observation_id": "adversarial-synthetic",
        "observed_at": "2026-10-12T11:00:00Z",
        "valid_until": "2026-10-12T13:00:00Z",
        "subject": {"agent": "synthetic", "host": "synthetic",
                    "surface": "test", "session_id": "session-a",
                    "execution_id": "execution-a", "configuration_epoch": 0},
        "source": {"repository": "example/fixture", "revision": "a" * 40,
                   "path": "fixtures/observation.json"},
        "assertions": [{"path": "/value", "status": "known",
                        "basis": "observed", "evidence_ref": "fixture:one",
                        "value": value}],
        "links": [],
        "receipts": {"invocation": "failed", "transport": "unknown",
                     "durability": "not_attempted", "evaluation": "failed"},
    }
    return resign(document)


def resign(document):
    body = {key: value for key, value in document.items() if key != "integrity"}
    document["integrity"] = {"algorithm": "acve-observation-json/0.1.0",
                             "sha256": hashlib.sha256(wire(body)).hexdigest()}
    return document


def eq(value=None, path="/value"):
    return {"eq": {"path": path, "value": value}}


def node_count(value):
    if type(value) is dict:
        return 1 + sum(node_count(child) for child in value.values())
    if type(value) is list:
        return 1 + sum(node_count(child) for child in value)
    return 1


class ObservationAdversarialTests(unittest.TestCase):
    def evaluate(self, document, expression=None, at=AT):
        return obs.evaluate_observation(document, eq() if expression is None else expression, at=at)

    def assert_rejected(self, document):
        self.assertTrue(obs.validate_observation(document))
        for operation in (lambda: obs.seal_observation(document),
                          lambda: self.evaluate(document),
                          lambda: obs.load_observation(wire(document))):
            with self.assertRaises(obs.ObservationError):
                operation()

    def test_recursive_equality_full_primitive_cross_product(self):
        # Python considers False == 0 and True == 1, including inside lists.
        values = [None, False, True, 0, 1, "0", "1", [], {}]
        for left_index, right_index in itertools.product(range(len(values)), repeat=2):
            left, right = values[left_index], values[right_index]
            with self.subTest(left=left_index, right=right_index):
                document = signed({"outer": [{"inner": left}]})
                expression = eq({"outer": [{"inner": right}]})
                result = self.evaluate(document, expression)
                self.assertEqual(result["result"], "true" if left_index == right_index else "false")
                self.assertEqual(result["reasons"], [])

    def test_unicode_normalization_is_not_implicit(self):
        document = signed({"\u00e9": 1, "e\u0301": 2, "\U0001f600": 3})
        self.assertEqual(obs.load_observation(wire(document)), document)
        self.assertEqual(self.evaluate(document, eq({"\u00e9": 1, "e\u0301": 2,
                                                    "\U0001f600": 3}))["result"], "true")
        self.assertEqual(self.evaluate(signed("\u00e9"), eq("e\u0301"))["result"], "false")

    def test_duplicate_astral_key_after_json_escape_decoding(self):
        raw = ('{"\U0001f600":0,"\\ud83d\\ude00":1}').encode("utf-8")
        with self.assertRaises(obs.ObservationError) as caught:
            obs.load_observation(raw)
        self.assertEqual(caught.exception.code, "duplicate_key")

    def test_unicode_pointer_tokens_remain_distinct(self):
        document = signed()
        template = document["assertions"][0]
        paths = ["/\u00e9", "/e\u0301", "/~01", "/~1", "/0", "/00", "/\U0001f600"]
        document["assertions"] = [dict(template, path=path, value=i) for i, path in enumerate(paths)]
        resign(document)
        for i, path in enumerate(paths):
            with self.subTest(path=path):
                self.assertEqual(self.evaluate(document, eq(i, path))["result"], "true")
        self.assertEqual(self.evaluate(document, eq(0, "/e"))["reasons"], ["missing_evidence"])

    def test_whitespace_only_identifiers_rejected_at_each_reference_site(self):
        paths = [("observation_id",), ("subject", "agent"), ("subject", "host"),
                 ("subject", "surface"), ("subject", "session_id"),
                 ("subject", "execution_id"), ("assertions", 0, "evidence_ref"),
                 ("links", 0, "namespace"), ("links", 0, "id"), ("links", 0, "revision")]
        for path in paths:
            with self.subTest(path=path):
                document = signed()
                document["links"] = [{"rel": "policy", "namespace": "fixture", "id": "p", "revision": "r"}]
                target = document
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = " \t\u2003\u00a0\n"
                self.assert_rejected(resign(document))

    def test_source_namespace_and_posix_unicode_boundaries(self):
        for repository in ("a_b.c-d/R_9", "x+git.v1:synthetic:revision", "urn:\u03b1"):
            with self.subTest(repository=repository):
                document = signed()
                document["source"].update(repository=repository, path="fixtures/\u03b1 source.json")
                resign(document)
                self.assertEqual(obs.validate_observation(document), [])
                self.assertEqual(obs.load_observation(wire(document)), document)
        for repository in ("owner/repo/extra", "\u03b1/repo", "1scheme:value", "urn:",
                           "urn:with\u2003space", "owner/repo\n", " owner/repo"):
            with self.subTest(repository=repository):
                document = signed()
                document["source"]["repository"] = repository
                self.assert_rejected(resign(document))

    def test_fractional_prefix_ordering_and_trailing_zero_equivalence(self):
        document = signed()
        document.update(observed_at="2026-10-12T12:00:00.12Z",
                        valid_until="2026-10-12T12:00:00.12000000000000000001Z")
        resign(document)
        for fraction, expected in (("11999999999999999999", ["not_yet_valid"]),
                                   ("12000000000000000000", []),
                                   ("120000000000000000005", []),
                                   ("120000000000000000010", ["expired"])):
            with self.subTest(fraction=fraction):
                result = self.evaluate(document, at=f"2026-10-12T12:00:00.{fraction}Z")
                self.assertEqual(result["reasons"], expected)
                self.assertEqual(result["result"], "unknown" if expected else "true")

    def test_timezone_offsets_cross_calendar_and_leap_day(self):
        document = signed()
        document.update(observed_at="2024-03-01T00:15:00+01:00",
                        valid_until="2024-02-29T23:45:00Z")
        resign(document)
        for at, expected in (("2024-02-29T18:14:59-05:00", ["not_yet_valid"]),
                             ("2024-02-29T18:15:00-05:00", []),
                             ("2024-03-01T00:44:59.999999999+01:00", []),
                             ("2024-03-01T00:45:00+01:00", ["expired"])):
            with self.subTest(at=at):
                self.assertEqual(self.evaluate(document, at=at)["reasons"], expected)

    def test_leap_seconds_and_non_ascii_time_digits_are_structured_errors(self):
        for at in ("2016-12-31T23:59:60Z", "2026-10-12T12:00:00.\u0661Z",
                   "\uff12\uff10\uff12\uff16-10-12T12:00:00Z", "2026-10-12T12:00:00+00:60"):
            with self.subTest(at=at), self.assertRaises(obs.ObservationError):
                self.evaluate(signed(), at=at)

    def test_raw_whitespace_counts_toward_input_byte_limit(self):
        document = signed()
        raw = wire(document)
        padded = raw + b" " * (BYTE_LIMIT - len(raw))
        self.assertEqual(len(padded), BYTE_LIMIT)
        self.assertEqual(obs.load_observation(padded), document)
        with self.assertRaises(obs.ObservationError):
            obs.load_observation(padded + b" ")

    def test_astral_escape_expansion_exact_serialized_limit(self):
        document = signed("")
        budget = BYTE_LIMIT - len(wire(document))
        document["assertions"][0]["value"] = "\U0001f600" * (budget // 12) + "a" * (budget % 12)
        resign(document)
        self.assertEqual(len(wire(document)), BYTE_LIMIT)
        self.assertEqual(obs.load_observation(wire(document)), document)
        self.assertEqual(obs.seal_observation(document), document)
        document["assertions"][0]["value"] += "a"
        self.assert_rejected(resign(document))

    def test_object_keys_do_not_consume_node_budget(self):
        document = signed({})
        remaining = 10000 - node_count(document)
        document["assertions"][0]["value"] = {str(i): None for i in range(remaining)}
        resign(document)
        self.assertEqual(node_count(document), 10000)
        self.assertEqual(obs.load_observation(wire(document)), document)
        document["assertions"][0]["value"]["overflow"] = None
        self.assert_rejected(resign(document))

    def test_alias_occurrences_consume_node_budget(self):
        document = signed([])
        remaining = 10000 - node_count(document)
        shared = {"nested": None}
        document["assertions"][0]["value"] = [shared] * (remaining // 2) + [None] * (remaining % 2)
        resign(document)
        self.assertEqual(node_count(document), 10000)
        self.assertEqual(obs.seal_observation(document), document)
        document["assertions"][0]["value"].append(shared)
        self.assert_rejected(resign(document))

    def test_expression_width_and_depth_limits_in_combination(self):
        # 15 combinators plus 1009 leaves = 1024 nodes, depth exactly 16.
        expression = {"all": [eq() for _ in range(1009)]}
        for _ in range(14):
            expression = {"any": [expression]}
        self.assertEqual(self.evaluate(signed(), expression)["result"], "true")
        too_wide = copy.deepcopy(expression)
        deepest = too_wide
        for _ in range(14):
            deepest = deepest["any"][0]
        deepest["all"].append(eq())
        with self.assertRaises(obs.ObservationError):
            self.evaluate(signed(), too_wide)
        with self.assertRaises(obs.ObservationError):
            self.evaluate(signed(), {"all": [expression]})

    def test_invalid_expression_is_rejected_even_when_expired_or_dominated(self):
        malformed = [{"exists": {"path": "/value", "value": 0}},
                     {"eq": {"path": "/value", "value": float("nan")}},
                     {"any": []}, {"eq": {"path": "/value", "value": None, "extra": 0}}]
        for leaf, at in itertools.product(malformed, (AT, "2027-01-01T00:00:00Z")):
            with self.subTest(leaf=leaf, at=at), self.assertRaises(obs.ObservationError):
                self.evaluate(signed(), {"any": [eq(), leaf]}, at=at)

    def test_all_limitations_survive_dominated_and_stale_branches(self):
        document = signed()
        template = document["assertions"][0]
        for status in ("unknown", "invalid", "unavailable"):
            entry = dict(template, path="/" + status, status=status, basis="inferred")
            del entry["value"]
            document["assertions"].append(entry)
        resign(document)
        expression = {"any": [eq(), {"all": [eq(path="/missing"), eq(path="/unknown"),
                                               eq(path="/invalid"), eq(path="/unavailable")]}]}
        reasons = ["invalid_evidence", "missing_evidence", "non_observed_evidence",
                   "unavailable_evidence", "unknown_evidence"]
        fresh = self.evaluate(document, expression)
        self.assertEqual((fresh["result"], fresh["reasons"]), ("true", reasons))
        stale = self.evaluate(document, expression, "2027-01-01T00:00:00Z")
        self.assertEqual((stale["result"], stale["reasons"]), ("unknown", ["expired"] + reasons))

    def test_mutated_query_revalidated_after_success(self):
        document = signed(None)
        expression = {"exists": {"path": "/value", "value": True}}
        self.assertEqual(self.evaluate(document, expression)["result"], "true")
        expression["exists"]["value"] = 1
        with self.assertRaises(obs.ObservationError):
            self.evaluate(document, expression)

    def test_malformed_utf8_and_surrogate_sequences_never_escape_error_api(self):
        carrier = wire(signed(None))
        self.assertEqual(obs.load_observation(carrier), signed(None))
        for token in (b"\xc0\xaf", b"\xed\xa0\x80", b"\xf4\x90\x80\x80",
                      b"\\ud800\\ud800", b"\\udc00\\ud800", b"\\ud800x", b"\\udc00"):
            with self.subTest(token=token):
                with self.assertRaises(obs.ObservationError) as caught:
                    obs.load_observation(carrier.replace(b'"value":null', b'"value":"' + token + b'"'))
                expected = "lone_surrogate" if token.startswith(b"\\u") else "invalid_utf8"
                self.assertEqual(caught.exception.code, expected)

    def test_mixed_container_depth_and_escaped_delimiters(self):
        value = '\\"}][{' * 64
        # Envelope adds root, assertions list, and assertion object: 3 levels.
        for i in range(29):
            value = [value] if i % 2 else {"nested": value}
        document = signed(value)
        self.assertEqual(obs.load_observation(wire(document)), document)
        self.assertEqual(obs.seal_observation(document), document)
        document["assertions"][0]["value"] = [value]
        self.assert_rejected(resign(document))

    def test_integer_endpoints_and_boolean_epoch_are_separate(self):
        for value in (-9007199254740991, 9007199254740991):
            with self.subTest(value=value):
                document = signed(value)
                self.assertEqual(obs.load_observation(wire(document)), document)
                self.assertEqual(self.evaluate(document, eq(value))["result"], "true")
        for value in (-9007199254740992, 9007199254740992):
            with self.subTest(unsafe=value):
                self.assert_rejected(signed(value))
        for epoch in (False, True):
            with self.subTest(epoch=epoch):
                document = signed()
                document["subject"]["configuration_epoch"] = epoch
                self.assert_rejected(resign(document))

    def test_duplicate_pointer_at_assertion_limit_is_not_lost(self):
        document = signed()
        template = document["assertions"][0]
        document["assertions"] = [dict(template, path=f"/value/{i}") for i in range(512)]
        resign(document)
        self.assertEqual(obs.load_observation(wire(document)), document)
        duplicate = copy.deepcopy(document)
        duplicate["assertions"][-1]["path"] = duplicate["assertions"][0]["path"]
        self.assert_rejected(resign(duplicate))
        document["assertions"].append(dict(template, path="/overflow"))
        self.assert_rejected(resign(document))

    def test_existing_integrity_is_not_repaired_on_reseal(self):
        for metadata in ({"algorithm": "other", "sha256": "0" * 64},
                         {"algorithm": "acve-observation-json/0.1.0", "sha256": "F" * 64},
                         {"algorithm": "acve-observation-json/0.1.0", "sha256": None}):
            document = signed()
            document["integrity"] = metadata
            original = copy.deepcopy(document)
            with self.subTest(metadata=metadata), self.assertRaises(obs.ObservationError):
                obs.seal_observation(document)
            self.assertEqual(document, original)


if __name__ == "__main__":
    unittest.main()
