"""Unit tests for DriverSecurityAnalyzer and EventHealthAnalyzer using synthetic datasets."""

from __future__ import annotations

import unittest
from wsi.analyzers.driver_security import DriverSecurityAnalyzer
from wsi.analyzers.event_health import EventHealthAnalyzer
from wsi.core.base import CollectorResult


class TestDriverSecurityAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = DriverSecurityAnalyzer()

    def test_non_standard_driver_path(self):
        services_res = CollectorResult(
            collector_name="services",
            data=[
                {
                    "name": "SuspiciousDrv",
                    "display_name": "Suspicious Custom Driver",
                    "executable_path": r"C:\Users\User\AppData\Local\Temp\driver.sys",
                    "is_running": True,
                    "category": "driver",
                },
                {
                    "name": "StandardDrv",
                    "display_name": "Standard System Driver",
                    "executable_path": r"C:\Windows\System32\drivers\std.sys",
                    "is_running": True,
                    "category": "driver",
                },
            ],
        )
        result = self.analyzer.analyze({"services": services_res})
        warnings = [f for f in result.findings if f.severity == "warning"]
        self.assertEqual(len(warnings), 1)
        self.assertIn("Driver outside standard directory", warnings[0].title)

    def test_running_driver_without_path_is_info(self):
        services_res = CollectorResult(
            collector_name="services",
            data=[
                {
                    "name": "BuiltInKernel",
                    "display_name": "Built-in Kernel Component",
                    "executable_path": None,
                    "is_running": True,
                    "category": "driver",
                }
            ],
        )
        result = self.analyzer.analyze({"services": services_res})
        infos = [f for f in result.findings if f.severity == "info"]
        self.assertEqual(len(infos), 1)
        self.assertIn("Running kernel driver without path", infos[0].title)


class TestEventHealthAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = EventHealthAnalyzer()

    def test_bsod_detection(self):
        events_res = CollectorResult(
            collector_name="event_logs",
            data=[
                {
                    "id": 1001,
                    "category": "bsod",
                    "time_created": "2026-11-01 10:00:00",
                    "message": "The computer has rebooted from a bugcheck.",
                }
            ],
        )
        result = self.analyzer.analyze({"event_logs": events_res})
        criticals = [f for f in result.findings if f.severity == "critical"]
        self.assertEqual(len(criticals), 1)
        self.assertIn("BSOD", criticals[0].title)

    def test_multiple_unexpected_shutdowns(self):
        events_res = CollectorResult(
            collector_name="event_logs",
            data=[
                {"id": 6008, "category": "unexpected_shutdown", "time_created": "2026-11-01 09:00:00"},
                {"id": 6008, "category": "unexpected_shutdown", "time_created": "2026-11-02 14:00:00"},
            ],
        )
        result = self.analyzer.analyze({"event_logs": events_res})
        warnings = [f for f in result.findings if "unexpected shutdowns" in f.title]
        self.assertEqual(len(warnings), 1)

    def test_app_crash_loop(self):
        events_res = CollectorResult(
            collector_name="event_logs",
            data=[
                {"id": 1000, "category": "app_crash", "message": "Faulting application: bad_app.exe, version: 1.0"},
                {"id": 1000, "category": "app_crash", "message": "Faulting application: bad_app.exe, version: 1.0"},
                {"id": 1000, "category": "app_crash", "message": "Faulting application: bad_app.exe, version: 1.0"},
            ],
        )
        result = self.analyzer.analyze({"event_logs": events_res})
        loops = [f for f in result.findings if "Application crash loop" in f.title]
        self.assertEqual(len(loops), 1)
        self.assertIn("bad_app.exe", loops[0].title)


if __name__ == "__main__":
    unittest.main()

