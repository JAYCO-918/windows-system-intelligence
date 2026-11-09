"""Windows Event Log diagnostic collector (read-only).

Queries recent critical system events via PowerShell Get-WinEvent:
- System crashes (BugCheck / BSOD: Event ID 1001)
- Disk I/O and NTFS corruption warnings (Event IDs 7, 51, 55, 153)
- Application crashes (Windows Error Reporting / Application Error: Event IDs 1000, 1002)
- Unexpected system shutdowns (Event ID 6008)

All queries are strictly read-only and capped to the most recent occurrences.
"""

from __future__ import annotations

from typing import Any

from wsi.core.base import BaseCollector, CollectorResult


class EventLogsCollector(BaseCollector):
    """Collects recent critical system and application events — read-only."""

    name = "event_logs"
    description = "Queries recent critical event log records (crashes, disk warnings, BSODs)"

    def collect(self) -> CollectorResult:
        result = CollectorResult(collector_name=self.name)

        # 1. System BugChecks & unexpected shutdowns
        try:
            self._collect_system_crashes(result)
        except Exception as exc:
            result.errors.append(f"Crash event collection failed: {exc}")

        # 2. Disk I/O & filesystem warnings
        try:
            self._collect_disk_events(result)
        except Exception as exc:
            result.errors.append(f"Disk event collection failed: {exc}")

        # 3. Application crashes & hangs
        try:
            self._collect_app_crashes(result)
        except Exception as exc:
            result.errors.append(f"Application crash collection failed: {exc}")

        result.data.sort(key=lambda x: x.get("time_created") or "", reverse=True)
        result.metadata["total_events"] = len(result.data)
        return result

    def _collect_system_crashes(self, result: CollectorResult) -> None:
        """Query BugCheck (BSOD) and unexpected shutdown events."""
        ps = (
            "Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001,6008} "
            "-MaxEvents 20 -ErrorAction SilentlyContinue | "
            "Select-Object Id, ProviderName, @{N='TimeCreated';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, LevelDisplayName, Message | "
            "ConvertTo-Json -Compress"
        )
        events = self._run_powershell_json(ps, timeout=30)
        if isinstance(events, dict):
            events = [events]

        for ev in events:
            ev_id = ev.get("Id")
            category = "bsod" if ev_id == 1001 else "unexpected_shutdown"
            result.data.append({
                "id": ev_id,
                "provider": ev.get("ProviderName"),
                "level": ev.get("LevelDisplayName", "Error"),
                "time_created": str(ev.get("TimeCreated")),
                "message": (ev.get("Message") or "").splitlines()[0] if ev.get("Message") else "",
                "category": category,
            })

    def _collect_disk_events(self, result: CollectorResult) -> None:
        """Query disk corruption or controller warning events."""
        ps = (
            "Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='disk','volsnap','Ntfs'; Id=7,51,55,153} "
            "-MaxEvents 20 -ErrorAction SilentlyContinue | "
            "Select-Object Id, ProviderName, @{N='TimeCreated';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, LevelDisplayName, Message | "
            "ConvertTo-Json -Compress"
        )
        events = self._run_powershell_json(ps, timeout=30)
        if isinstance(events, dict):
            events = [events]

        for ev in events:
            result.data.append({
                "id": ev.get("Id"),
                "provider": ev.get("ProviderName"),
                "level": ev.get("LevelDisplayName", "Warning"),
                "time_created": str(ev.get("TimeCreated")),
                "message": (ev.get("Message") or "").splitlines()[0] if ev.get("Message") else "",
                "category": "disk_health",
            })

    def _collect_app_crashes(self, result: CollectorResult) -> None:
        """Query application crash (Event 1000) and hang (Event 1002) records."""
        ps = (
            "Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Application Error','Application Hang'; Id=1000,1002} "
            "-MaxEvents 25 -ErrorAction SilentlyContinue | "
            "Select-Object Id, ProviderName, @{N='TimeCreated';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, LevelDisplayName, Message | "
            "ConvertTo-Json -Compress"
        )
        events = self._run_powershell_json(ps, timeout=30)
        if isinstance(events, dict):
            events = [events]

        for ev in events:
            raw_msg = ev.get("Message") or ""
            # Extract faulting application name if present
            faulting_app = "Unknown"
            for line in raw_msg.splitlines():
                if "Faulting application name:" in line:
                    faulting_app = line.split(":", 1)[1].strip()
                    break

            result.data.append({
                "id": ev.get("Id"),
                "provider": ev.get("ProviderName"),
                "level": ev.get("LevelDisplayName", "Error"),
                "time_created": str(ev.get("TimeCreated")),
                "message": f"Faulting application: {faulting_app}" if faulting_app != "Unknown" else raw_msg[:120],
                "category": "app_crash",
            })
