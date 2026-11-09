"""Windows services and drivers collector (read-only).

Uses WMI via PowerShell to enumerate all Windows services and
kernel/user-mode drivers without modifying any system state.
"""

from __future__ import annotations

from typing import Any

from wsi.core.base import BaseCollector, CollectorResult


class ServicesCollector(BaseCollector):
    """Enumerates Windows services and system drivers — read-only."""

    name = "services"
    description = "Enumerates Windows services and drivers with their configuration"

    def collect(self) -> CollectorResult:
        result = CollectorResult(collector_name=self.name)

        # 1. Windows Services
        try:
            self._collect_services(result)
        except Exception as exc:
            result.errors.append(f"Service enumeration failed: {exc}")

        # 2. Kernel / user-mode drivers
        try:
            self._collect_drivers(result)
        except Exception as exc:
            result.errors.append(f"Driver enumeration failed: {exc}")

        result.data.sort(key=lambda x: (x.get("category", ""), (x.get("name") or "").lower()))
        svc_count = sum(1 for d in result.data if d.get("category") == "service")
        drv_count = sum(1 for d in result.data if d.get("category") == "driver")
        result.metadata.update(service_count=svc_count, driver_count=drv_count)
        return result

    def _collect_services(self, result: CollectorResult) -> None:
        ps = (
            "Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | "
            "Select-Object Name, DisplayName, Description, PathName, State, "
            "StartMode, ServiceType, Started, ProcessId, StartName, "
            "DelayedAutoStart | ConvertTo-Json -Compress"
        )
        services = self._run_powershell_json(ps)
        if isinstance(services, dict):
            services = [services]

        for svc in services:
            entry: dict[str, Any] = {
                "name": svc.get("Name", ""),
                "display_name": svc.get("DisplayName", ""),
                "description": svc.get("Description"),
                "executable_path": svc.get("PathName"),
                "state": svc.get("State", "Unknown"),
                "start_mode": svc.get("StartMode", "Unknown"),
                "service_type": svc.get("ServiceType", ""),
                "is_running": bool(svc.get("Started")),
                "pid": svc.get("ProcessId"),
                "run_as_account": svc.get("StartName"),
                "delayed_auto_start": bool(svc.get("DelayedAutoStart")),
                "category": "service",
            }
            result.data.append(entry)

    def _collect_drivers(self, result: CollectorResult) -> None:
        ps = (
            "Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | "
            "Select-Object Name, DisplayName, Description, PathName, State, "
            "StartMode, ServiceType, Started | ConvertTo-Json -Compress"
        )
        drivers = self._run_powershell_json(ps)
        if isinstance(drivers, dict):
            drivers = [drivers]

        for drv in drivers:
            entry: dict[str, Any] = {
                "name": drv.get("Name", ""),
                "display_name": drv.get("DisplayName", ""),
                "description": drv.get("Description"),
                "executable_path": drv.get("PathName"),
                "state": drv.get("State", "Unknown"),
                "start_mode": drv.get("StartMode", "Unknown"),
                "service_type": drv.get("ServiceType", ""),
                "is_running": bool(drv.get("Started")),
                "pid": None,
                "run_as_account": None,
                "delayed_auto_start": False,
                "category": "driver",
            }
            result.data.append(entry)

