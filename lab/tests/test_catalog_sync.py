"""lab/labcheck.py keeps its own copy of the catalog points on purpose (an independent
answer key for the engine). This test makes sure the two copies still agree, so the lab's
expected score (25 for the default lab) is the score the engine reports in the demo.

Run: python3 -m unittest discover -s lab/tests
On a Pi without the `tool` package the test is skipped, so lab/tests still runs there.
"""

import importlib.util
import pathlib
import sys
import unittest

LAB = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("labcheck", LAB / "labcheck.py")
labcheck = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("labcheck", labcheck)
_spec.loader.exec_module(labcheck)

try:
    from tool.engine.catalog import CATALOG
except ImportError:  # a Pi, or a checkout without `pip install -e .`
    CATALOG = None


@unittest.skipIf(CATALOG is None, "the tool package isn't installed")
class CatalogSyncTests(unittest.TestCase):
    def test_lab_codes_have_the_engine_severity_and_points(self):
        for code, (severity, points) in labcheck.CODES.items():
            with self.subTest(code=code):
                self.assertIn(code, CATALOG)
                self.assertEqual(severity, CATALOG[code].severity)
                self.assertEqual(points, CATALOG[code].points)

    def test_every_service_code_is_a_catalog_code(self):
        for svc in labcheck.load_services():
            for code in svc.codes:
                with self.subTest(service=svc.name, code=code):
                    self.assertIn(code, CATALOG)


if __name__ == "__main__":
    unittest.main()
