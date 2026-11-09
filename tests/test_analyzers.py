"""Unit tests for WSI diagnostic analyzers using synthetic datasets."""

from __future__ import annotations

import unittest
from wsi.analyzers.health import HealthAnalyzer
from wsi.analyzers.software import SoftwareAnalyzer
from wsi.core.base import CollectorResult


class TestHealthAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = HealthAnalyzer()

    def test_low_disk_space_warning(self):
        storage_res = CollectorResult(
            collector_name="storage",
            data=[{
                "logical_disks": [{
                    "drive": "C:",
                    "size_gb": 100.0,
                    "free_gb": 12.0,
                    "used_gb": 88.0,
                    "usage_percent": 88.0,
                }],
            }],
        )
        result = self.analyzer.analyze({"storage": storage_res})
        warnings = [f for f in result.findings if f.severity == "warning"]
        self.assertEqual(len(warnings), 1)
        self.assertIn("Low disk space", warnings[0].title)

    def test_critically_low_disk_space(self):
        storage_res = CollectorResult(
            collector_name="storage",
            data=[{
                "logical_disks": [{
                    "drive": "C:",
                    "size_gb": 100.0,
                    "free_gb": 3.0,
                    "used_gb": 97.0,
                    "usage_percent": 97.0,
                }],
            }],
        )
        result = self.analyzer.analyze({"storage": storage_res})
        criticals = [f for f in result.findings if f.severity == "critical"]
        self.assertEqual(len(criticals), 1)
        self.assertIn("Critically low", criticals[0].title)

    def test_healthy_disk_space(self):
        storage_res = CollectorResult(
            collector_name="storage",
            data=[{
                "logical_disks": [{
                    "drive": "C:",
                    "size_gb": 500.0,
                    "free_gb": 250.0,
                    "used_gb": 250.0,
                    "usage_percent": 50.0,
                }],
            }],
        )
        result = self.analyzer.analyze({"storage": storage_res})
        storage_findings = [f for f in result.findings if f.category == "storage"]
        self.assertEqual(len(storage_findings), 0)

    def test_stopped_auto_service(self):
        services_res = CollectorResult(
            collector_name="services",
            data=[{
                "name": "CustomAppSvc",
                "display_name": "Custom Application Service",
                "start_mode": "Auto",
                "is_running": False,
                "category": "service",
            }],
        )
        result = self.analyzer.analyze({"services": services_res})
        svc_findings = [f for f in result.findings if f.category == "services"]
        self.assertEqual(len(svc_findings), 1)
        self.assertEqual(svc_findings[0].severity, "info")

    def test_missing_path_directories(self):
        env_res = CollectorResult(
            collector_name="environment",
            data=[{
                "path_analysis": {
                    "total_entries": 5,
                    "valid_directories": 3,
                    "missing_directories": 2,
                    "duplicates": 0,
                    "issues": [
                        {"issue": "directory_not_found", "path": r"C:\DeletedApp\bin"},
                        {"issue": "directory_not_found", "path": r"C:\OldRuntime"},
                    ],
                },
            }],
        )
        result = self.analyzer.analyze({"environment": env_res})
        env_findings = [f for f in result.findings if f.category == "environment"]
        self.assertEqual(len(env_findings), 1)
        self.assertEqual(env_findings[0].severity, "warning")


class TestSoftwareAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = SoftwareAnalyzer()

    def test_duplicate_version_detection(self):
        apps_res = CollectorResult(
            collector_name="installed_apps",
            data=[
                {"name": "Node.js", "version": "18.16.0", "source": "registry"},
                {"name": "Node.js", "version": "20.10.0", "source": "registry"},
            ],
        )
        result = self.analyzer.analyze({"installed_apps": apps_res})
        dupes = [f for f in result.findings if "Multiple versions" in f.title]
        self.assertEqual(len(dupes), 1)
        self.assertEqual(dupes[0].severity, "warning")

    def test_no_duplicate_when_single_version(self):
        apps_res = CollectorResult(
            collector_name="installed_apps",
            data=[
                {"name": "Git", "version": "2.43.0", "source": "registry"},
                {"name": "Python 3.12", "version": "3.12.1", "source": "registry"},
            ],
        )
        result = self.analyzer.analyze({"installed_apps": apps_res})
        dupes = [f for f in result.findings if "Multiple versions" in f.title]
        self.assertEqual(len(dupes), 0)


if __name__ == "__main__":
    unittest.main()

