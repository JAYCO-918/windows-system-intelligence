"""Event log diagnostic analyzer (read-only).

Analyzes collected system and application events to detect:
- Recent BSOD / BugCheck incidents
- Repeated unexpected system shutdowns
- Application crash loops (processes failing repeatedly)
- Disk I/O warnings and controller timeouts
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from wsi.core.base import AnalysisResult, BaseAnalyzer, CollectorResult, Finding


class EventHealthAnalyzer(BaseAnalyzer):
    """Analyzes system event logs for stability patterns — read-only."""

    name = "event_health"
    description = "Detects BSOD bugchecks, unexpected shutdown patterns, and application crash loops"

    def analyze(
        self, collector_results: dict[str, CollectorResult]
    ) -> AnalysisResult:
        result = AnalysisResult(analyzer_name=self.name)

        events_res = collector_results.get("event_logs")
        if not events_res or not events_res.data:
            result.summary = "No event log data available to analyze."
            return result

        events = events_res.data

        # 1. BugCheck / BSOD events
        bsods = [e for e in events if e.get("category") == "bsod"]
        if bsods:
            latest = bsods[0]
            result.findings.append(
                Finding(
                    severity="critical",
                    category="stability",
                    title=f"Kernel BugCheck (BSOD) detected: {len(bsods)} recent incident(s)",
                    description=(
                        f"A system crash was recorded on {latest.get('time_created')}. "
                        f"Details: {latest.get('message')}"
                    ),
                    details={"incident_count": len(bsods), "latest": latest},
                    recommendation="Inspect minidump files in C:\\Windows\\Minidump with WinDbg to determine faulting driver.",
                )
            )

        # 2. Unexpected shutdowns
        shutdowns = [e for e in events if e.get("category") == "unexpected_shutdown"]
        if len(shutdowns) >= 2:
            result.findings.append(
                Finding(
                    severity="warning",
                    category="stability",
                    title=f"Multiple unexpected shutdowns detected ({len(shutdowns)} occurrences)",
                    description=(
                        f"System suffered {len(shutdowns)} improper power-off or sudden restart events. "
                        "This may indicate power supply instability, thermal throttling, or kernel deadlocks."
                    ),
                    details={"count": len(shutdowns), "records": shutdowns[:5]},
                    recommendation="Check system hardware temperatures, power supply connections, and UPS reliability.",
                )
            )

        # 3. Application crash loops
        app_crashes = [e for e in events if e.get("category") == "app_crash"]
        faulting_apps = []
        for ac in app_crashes:
            msg = ac.get("message", "")
            if "Faulting application:" in msg:
                app_name = msg.split("Faulting application:")[1].split(",")[0].strip()
                faulting_apps.append(app_name)

        crash_counts = Counter(faulting_apps)
        for app, count in crash_counts.items():
            if count >= 3:
                result.findings.append(
                    Finding(
                        severity="warning",
                        category="applications",
                        title=f"Application crash loop: {app} ({count} crashes)",
                        description=(
                            f"Application '{app}' crashed {count} times recently. "
                            "Repeated crashes suggest incompatible libraries, corrupted configuration, or memory faults."
                        ),
                        details={"application": app, "crash_count": count},
                        recommendation=f"Update or reinstall {app}, or check Event Viewer for specific error codes.",
                    )
                )

        # 4. Disk health warnings
        disk_events = [e for e in events if e.get("category") == "disk_health"]
        if disk_events:
            result.findings.append(
                Finding(
                    severity="warning",
                    category="storage",
                    title=f"Disk I/O warning events detected ({len(disk_events)} occurrences)",
                    description=(
                        f"Windows logged {len(disk_events)} disk warning or filesystem alert events. "
                        f"Example: {disk_events[0].get('message')}"
                    ),
                    details={"records": disk_events[:5]},
                    recommendation="Run chkdsk /scan on active volumes and monitor SMART health metrics.",
                )
            )

        crit_count = sum(1 for f in result.findings if f.severity == "critical")
        warn_count = sum(1 for f in result.findings if f.severity == "warning")
        result.summary = (
            f"Event stability analysis complete: {crit_count} critical, "
            f"{warn_count} warnings across {len(events)} analyzed events."
        )
        return result

