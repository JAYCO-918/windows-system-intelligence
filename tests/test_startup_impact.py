"""Unit tests for StartupImpactAnalyzer."""

from __future__ import annotations

import unittest
from wsi.analyzers.startup_impact import StartupImpactAnalyzer
from wsi.core.base import CollectorResult


class TestStartupImpactAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = StartupImpactAnalyzer()

    def test_high_volume_startup(self):
        # 35 items
        data = [
            {"name": f"App{i}", "command": f"C:\\App{i}.exe", "source": "registry_run"}
            for i in range(35)
        ]
        res = CollectorResult(collector_name="startup", data=data)
        out = self.analyzer.analyze({"startup": res})
        vol_findings = [f for f in out.findings if "High startup footprint" in f.title]
        self.assertEqual(len(vol_findings), 1)
        self.assertEqual(vol_findings[0].severity, "warning")

    def test_unquoted_path_detection(self):
        data = [
            {
                "name": "UnquotedApp",
                "command": r"C:\Program Files\My App\launcher.exe --minimized",
                "source": "registry_run",
            }
        ]
        res = CollectorResult(collector_name="startup", data=data)
        out = self.analyzer.analyze({"startup": res})
        unquoted = [f for f in out.findings if "Unquoted startup path" in f.title]
        self.assertEqual(len(unquoted), 1)
        self.assertEqual(unquoted[0].severity, "info")

    def test_broken_startup_target(self):
        data = [
            {
                "name": "GhostApp",
                "command": r'"C:\NonExistentDirectory\FakeBinary.exe"',
                "source": "registry_run",
            }
        ]
        res = CollectorResult(collector_name="startup", data=data)
        out = self.analyzer.analyze({"startup": res})
        broken = [f for f in out.findings if "Broken startup target" in f.title]
        self.assertEqual(len(broken), 1)
        self.assertEqual(broken[0].severity, "warning")


if __name__ == "__main__":
    unittest.main()

