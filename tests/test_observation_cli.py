import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest

from acve.cli import main
from acve.observation import seal_observation


class ObservationCLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.doc = root / 'observation.json'
        self.query = root / 'query.json'
        base = json.loads((Path(__file__).resolve().parents[1] / 'conformance/observation-v0.1.0.json').read_text())['base']
        self.base = copy.deepcopy(base)
        self.doc.write_text(json.dumps(seal_observation(base)))
        self.query.write_text(json.dumps({'eq': {'path': '/model/name', 'value': 'model-a'}}))

    def invoke(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(['observation-check', str(self.doc), str(self.query), '--at', '2026-01-01T12:30:00Z'])
        return code, json.loads(output.getvalue())

    def test_true_false_unknown_have_distinct_exit_codes(self):
        self.assertEqual(self.invoke()[0], 0)
        self.query.write_text(json.dumps({'eq': {'path': '/model/name', 'value': 'model-b'}}))
        code, result = self.invoke()
        self.assertEqual((code, result['result']), (1, 'false'))
        self.query.write_text(json.dumps({'eq': {'path': '/missing', 'value': 'model-b'}}))
        code, result = self.invoke()
        self.assertEqual((code, result['result']), (3, 'unknown'))

    def test_tampering_is_error_not_false(self):
        doc = json.loads(self.doc.read_text())
        doc['observation_id'] = 'private-sentinel'
        self.doc.write_text(json.dumps(doc))
        code, result = self.invoke()
        self.assertEqual(code, 2)
        self.assertNotIn('private-sentinel', json.dumps(result))

    def test_duplicate_query_keys_and_nonfinite_rejected(self):
        for raw in ('{"eq":{},"eq":{"path":"/model/name","value":"model-a"}}',
                    '{"eq":{"path":"/model/name","value":NaN}}'):
            self.query.write_text(raw)
            self.assertEqual(self.invoke()[0], 2)

    def test_missing_file_has_redacted_error(self):
        self.doc.unlink()
        code, result = self.invoke()
        self.assertEqual(code, 2)
        self.assertNotIn(str(self.doc), json.dumps(result))

    def test_large_and_deep_query_rejected(self):
        for raw in (' ' * 1048577, '[' * 2000 + ']' * 2000):
            self.query.write_text(raw)
            self.assertEqual(self.invoke()[0], 2)


if __name__ == '__main__':
    unittest.main()
