"""Packaged resources must work without a source-tree checkout beside acve."""
import importlib.resources
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from acve.feed import load_schema


class DistributionTests(unittest.TestCase):
    def test_schema_comes_from_package_resources_when_present(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'schemas').mkdir()
            expected = {'title': 'synthetic-installed-schema'}
            (root / 'schemas/observation.schema.json').write_text(json.dumps(expected))
            with patch.object(importlib.resources, 'files', return_value=root):
                self.assertEqual(load_schema('observation'), expected)

    def test_unknown_and_escaping_schema_names_are_rejected(self):
        for name in ('../private', 'a/b', 'C:/private', '', 'observation.schema.json'):
            with self.subTest(name=name), self.assertRaises(FileNotFoundError):
                load_schema(name)


if __name__ == '__main__':
    unittest.main()
