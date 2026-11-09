"""Unit tests for WSI core components."""

from __future__ import annotations

import unittest
from wsi.core.base import CollectorResult, Finding, AnalysisResult
from wsi.core.formatting import format_table, format_json, format_summary, format_size_bytes


class TestCollectorResult(unittest.TestCase):
    def test_success_property(self):
        res = CollectorResult(collector_name="test")
        self.assertFalse(res.success)
        res.data.append({"key": "val"})
        self.assertTrue(res.success)

    def test_to_dict(self):
        res = CollectorResult(collector_name="test", data=[{"a": 1}], errors=["err"])
        d = res.to_dict()
        self.assertEqual(d["collector_name"], "test")
        self.assertEqual(len(d["data"]), 1)
        self.assertEqual(len(d["errors"]), 1)


class TestFormatting(unittest.TestCase):
    def test_format_table(self):
        headers = ["Col1", "Col2"]
        rows = [["a", "b"], ["c", "d"]]
        out = format_table(headers, rows)
        self.assertIn("Col1", out)
        self.assertIn("Col2", out)
        self.assertIn("a", out)

    def test_format_json(self):
        data = {"num": 42, "str": "hello"}
        out = format_json(data)
        self.assertIn('"num": 42', out)

    def test_format_summary(self):
        items = {"Key1": "Val1", "Key2": "Val2"}
        out = format_summary("Title", items)
        self.assertIn("=== Title ===", out)
        self.assertIn("Key1", out)

    def test_format_size_bytes(self):
        self.assertEqual(format_size_bytes(None), "N/A")
        self.assertEqual(format_size_bytes(1024), "1.0 KB")
        self.assertEqual(format_size_bytes(1024**2), "1.0 MB")
        self.assertEqual(format_size_bytes(1024**3), "1.0 GB")


class TestFinding(unittest.TestCase):
    def test_finding_to_dict(self):
        f = Finding(
            severity="warning",
            category="storage",
            title="Low disk",
            description="Details",
            recommendation="Clean up",
        )
        d = f.to_dict()
        self.assertEqual(d["severity"], "warning")
        self.assertEqual(d["category"], "storage")


if __name__ == "__main__":
    unittest.main()

