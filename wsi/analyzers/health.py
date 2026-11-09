"""System health diagnostic analyzer (read-only).

Analyzes collected system data for:
- Low disk space conditions (<10% or <10GB free)
- Windows services set to 'Auto' start but currently stopped
- PATH configuration anomalies (missing directories, excessive duplicates)
"""

from __future__ import annotations

from typing import Any

from wsi.core.base import AnalysisResult, BaseAnalyzer, CollectorResult, Finding


class HealthAnalyzer(BaseAnalyzer):
    """Analyzes system resource health and service state."""

    name = "health"
    description = "Checks disk capacity, stopped automatic services, and environment health"

    def analyze(
        self, collector_results: dict[str, CollectorResult]
    ) -> AnalysisResult:
        result = AnalysisResult(analyzer_name=self.name)

        self._check_disk_space(collector_results.get("storage"), result)
        self._check_services(collector_results.get("services"), result)
        self._check_environment(collector_results.get("environment"), result)

        # Build summary
        crit_count = sum(1 for f in result.findings if f.severity == "critical")
        warn_count = sum(1 for f in result.findings if f.severity == "warning")
        info_count = sum(1 for f in result.findings if f.severity == "info")

        result.summary = (
            f"Health check complete: {crit_count} critical, "
            f"{warn_count} warnings, {info_count} informational findings."
        )
        return result

    def _check_disk_space(
        self, storage_result: CollectorResult | None, analysis: AnalysisResult
    ) -> None:
        if not storage_result or not storage_result.data:
            return

        storage_data = storage_result.data[0]
        for disk in storage_data.get("logical_disks", []):
            drive = disk.get("drive", "?")
            free_gb = disk.get("free_gb")
            usage_pct = disk.get("usage_percent")

            if free_gb is None or usage_pct is None:
                continue

            if usage_pct >= 95 or free_gb < 5.0:
                analysis.findings.append(
                    Finding(
                        severity="critical",
                        category="storage",
                        title=f"Critically low disk space on {drive}",
                        description=(
                            f"Drive {drive} has only {free_gb:.1f} GB free "
                            f"({usage_pct:.1f}% used)."
                        ),
                        details=disk,
                        recommendation="Free up disk space or expand the volume immediately.",
                    )
                )
            elif usage_pct >= 85 or free_gb < 15.0:
                analysis.findings.append(
                    Finding(
                        severity="warning",
                        category="storage",
                        title=f"Low disk space on {drive}",
                        description=(
                            f"Drive {drive} is {usage_pct:.1f}% full "
                            f"({free_gb:.1f} GB free)."
                        ),
                        details=disk,
                        recommendation="Consider cleaning temporary files or moving data.",
                    )
                )

    def _check_services(
        self, services_result: CollectorResult | None, analysis: AnalysisResult
    ) -> None:
        if not services_result:
            return

        # Known services that are Auto-start but often stopped legitimately (triggers)
        benign_stopped = {
            "sppsvc",        # Software Protection (starts on demand)
            "gupdate",       # Google Update (runs periodically)
            "edgeupdate",    # Edge Update
            "clr_optimization_v4.0.30319_64",
            "clr_optimization_v4.0.30319_32",
        }

        for svc in services_result.data:
            if svc.get("category") != "service":
                continue

            name = (svc.get("name") or "").lower()
            start_mode = svc.get("start_mode", "")
            is_running = svc.get("is_running", False)

            if start_mode == "Auto" and not is_running and name not in benign_stopped:
                analysis.findings.append(
                    Finding(
                        severity="info",
                        category="services",
                        title=f"Auto-start service stopped: {svc.get('display_name') or name}",
                        description=(
                            f"Service '{name}' is configured for automatic startup "
                            "but is currently not running."
                        ),
                        details={
                            "name": name,
                            "display_name": svc.get("display_name"),
                            "path": svc.get("executable_path"),
                        },
                        recommendation=(
                            f"Check Event Viewer if {name} is expected to run "
                            "continuously."
                        ),
                    )
                )

    def _check_environment(
        self, env_result: CollectorResult | None, analysis: AnalysisResult
    ) -> None:
        if not env_result or not env_result.data:
            return

        env_data = env_result.data[0]
        path_analysis = env_data.get("path_analysis", {})

        missing = path_analysis.get("missing_directories", 0)
        duplicates = path_analysis.get("duplicates", 0)

        if missing > 0:
            missing_paths = [
                issue["path"]
                for issue in path_analysis.get("issues", [])
                if issue["issue"] == "directory_not_found"
            ]
            analysis.findings.append(
                Finding(
                    severity="warning",
                    category="environment",
                    title=f"PATH contains {missing} non-existent director{'y' if missing == 1 else 'ies'}",
                    description=(
                        f"The system PATH references directories that do not exist: "
                        f"{', '.join(missing_paths[:3])}"
                        + (f" and {len(missing_paths)-3} more" if len(missing_paths) > 3 else "")
                    ),
                    details={"missing_paths": missing_paths},
                    recommendation="Remove stale directories from your system/user PATH variable.",
                )
            )

        if duplicates > 0:
            analysis.findings.append(
                Finding(
                    severity="info",
                    category="environment",
                    title=f"PATH contains {duplicates} duplicate entries",
                    description=f"Redundant PATH entries slow down command resolution.",
                    details={"duplicate_count": duplicates},
                    recommendation="Clean up duplicate entries in your PATH variable.",
                )
            )

