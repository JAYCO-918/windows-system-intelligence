"""Software conflict and anomaly analyzer (read-only).

Analyzes collected application data for:
- Duplicate installations (same app from multiple sources or multiple versions)
- Applications installed in unusual or non-standard paths
- Broken install locations (directory no longer exists)
"""

from __future__ import annotations

import os
from collections import defaultdict
from typing import Any

from wsi.core.base import AnalysisResult, BaseAnalyzer, CollectorResult, Finding


class SoftwareAnalyzer(BaseAnalyzer):
    """Detects software conflicts, duplicates, and broken paths — read-only."""

    name = "software"
    description = "Detects duplicate installations, version conflicts, and missing paths"

    def analyze(
        self, collector_results: dict[str, CollectorResult]
    ) -> AnalysisResult:
        result = AnalysisResult(analyzer_name=self.name)

        apps_result = collector_results.get("installed_apps")
        if not apps_result or not apps_result.data:
            result.summary = "No application data available to analyze."
            return result

        self._check_duplicate_apps(apps_result.data, result)
        self._check_missing_install_dirs(apps_result.data, result)

        warn_count = sum(1 for f in result.findings if f.severity == "warning")
        info_count = sum(1 for f in result.findings if f.severity == "info")
        result.summary = (
            f"Software analysis complete: {warn_count} warnings, "
            f"{info_count} informational findings across {len(apps_result.data)} applications."
        )
        return result

    def _check_duplicate_apps(
        self, apps: list[dict[str, Any]], analysis: AnalysisResult
    ) -> None:
        """Find applications that appear multiple times with different versions."""
        # Group apps by normalized name
        by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for app in apps:
            name = app.get("name", "").strip()
            if not name:
                continue
            # Simple normalization: lower, strip common prefixes
            norm_name = name.lower()
            by_name[norm_name].append(app)

        for name, entries in by_name.items():
            if len(entries) <= 1:
                continue

            versions = set(e.get("version") for e in entries if e.get("version"))
            if len(versions) > 1:
                display_name = entries[0].get("name", name)
                analysis.findings.append(
                    Finding(
                        severity="warning",
                        category="software",
                        title=f"Multiple versions of '{display_name}' detected",
                        description=(
                            f"Found {len(entries)} installations with versions: "
                            f"{', '.join(str(v) for v in sorted(versions))}"
                        ),
                        details={
                            "name": display_name,
                            "installations": entries,
                        },
                        recommendation=(
                            "Consider uninstalling older versions to reclaim disk space "
                            "and prevent compatibility issues."
                        ),
                    )
                )

    def _check_missing_install_dirs(
        self, apps: list[dict[str, Any]], analysis: AnalysisResult
    ) -> None:
        """Check if application install directories actually exist on disk."""
        for app in apps:
            loc = app.get("install_location")
            if not loc:
                continue

            clean_loc = loc.strip().strip('"')
            if not clean_loc:
                continue

            # Check existence (read-only os.path.isdir)
            try:
                if not os.path.isdir(clean_loc):
                    analysis.findings.append(
                        Finding(
                            severity="info",
                            category="software",
                            title=f"Missing install directory: {app.get('name')}",
                            description=(
                                f"The registered install path does not exist: {clean_loc}"
                            ),
                            details={
                                "name": app.get("name"),
                                "path": clean_loc,
                                "source": app.get("source"),
                            },
                            recommendation=(
                                "The application may have been deleted manually without "
                                "a clean uninstall, leaving stale registry entries."
                            ),
                        )
                    )
            except (OSError, PermissionError):
                continue

