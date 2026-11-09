r"""Driver and kernel security analyzer (read-only).

Analyzes collected system drivers for:
- Drivers running from unusual/non-standard paths (e.g., outside System32\drivers)
- Kernel drivers with missing executable paths
- Potentially unstable or legacy driver configurations
"""

from __future__ import annotations

import os
from typing import Any

from wsi.core.base import AnalysisResult, BaseAnalyzer, CollectorResult, Finding


class DriverSecurityAnalyzer(BaseAnalyzer):
    """Analyzes system drivers for path anomalies and security posture — read-only."""

    name = "driver_security"
    description = "Checks for kernel drivers running from non-standard directories or missing binary paths"

    def analyze(
        self, collector_results: dict[str, CollectorResult]
    ) -> AnalysisResult:
        result = AnalysisResult(analyzer_name=self.name)

        services_res = collector_results.get("services")
        if not services_res or not services_res.data:
            result.summary = "No services or driver data available to analyze."
            return result

        drivers = [
            d for d in services_res.data if d.get("category") == "driver"
        ]

        standard_driver_dirs = [
            r"c:\windows\system32\drivers",
            r"c:\windows\syswow64\drivers",
            r"c:\windows\system32\driverstore",
        ]

        running_count = 0
        non_standard_count = 0

        for drv in drivers:
            is_running = drv.get("is_running", False)
            if is_running:
                running_count += 1

            path = (drv.get("executable_path") or "").strip()
            name = drv.get("name", "Unknown")
            disp_name = drv.get("display_name") or name

            if not path:
                if is_running:
                    result.findings.append(
                        Finding(
                            severity="info",
                            category="drivers",
                            title=f"Running kernel driver without path: {disp_name}",
                            description=(
                                f"Driver '{name}' is active in kernel memory but has no "
                                "ImagePath specified in its service record (built-in kernel component)."
                            ),
                            details=drv,
                            recommendation="Informational only. Built-in kernel drivers frequently omit ImagePath.",
                        )
                    )
                continue

            # Clean and expand path
            clean_path = path.strip('"')
            expanded = os.path.expandvars(clean_path).lower()

            # Check if running driver is located outside standard driver directories
            if is_running and not any(expanded.startswith(std) for std in standard_driver_dirs):
                non_standard_count += 1
                result.findings.append(
                    Finding(
                        severity="warning",
                        category="drivers",
                        title=f"Driver outside standard directory: {disp_name}",
                        description=(
                            f"Active driver '{name}' executes from a non-standard location: {clean_path}. "
                            "Third-party drivers outside System32\\drivers should be audited."
                        ),
                        details=drv,
                        recommendation="Verify the vendor and authenticity of this driver binary.",
                    )
                )

        warn_count = sum(1 for f in result.findings if f.severity == "warning")
        info_count = sum(1 for f in result.findings if f.severity == "info")
        result.summary = (
            f"Driver security review complete: {warn_count} warnings, "
            f"{info_count} informational findings across {len(drivers)} drivers ({running_count} running)."
        )
        return result

