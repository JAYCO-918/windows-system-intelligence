"""Storage analysis collector (read-only).

Analyzes logical disks, physical drives, and volumes via WMI queries.
No disk operations (read, write, benchmark) are performed.
"""

from __future__ import annotations

from typing import Any

from wsi.core.base import BaseCollector, CollectorResult


class StorageCollector(BaseCollector):
    """Analyzes disk usage and storage volumes — read-only."""

    name = "storage"
    description = "Analyzes disk usage, volume configuration, and physical drives"

    def collect(self) -> CollectorResult:
        result = CollectorResult(collector_name=self.name)

        storage_data: dict[str, Any] = {
            "logical_disks": self._get_logical_disks(result),
            "physical_disks": self._get_physical_disks(result),
        }

        # Calculate totals
        total_cap = 0.0
        total_free = 0.0
        for disk in storage_data["logical_disks"]:
            if disk.get("size_gb"):
                total_cap += disk["size_gb"]
            if disk.get("free_gb"):
                total_free += disk["free_gb"]

        storage_data["total_capacity_gb"] = round(total_cap, 2)
        storage_data["total_free_gb"] = round(total_free, 2)
        storage_data["total_used_gb"] = round(total_cap - total_free, 2)

        result.data.append(storage_data)
        return result

    def _get_logical_disks(self, result: CollectorResult) -> list[dict[str, Any]]:
        disks: list[dict[str, Any]] = []
        ps = (
            "Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue | "
            "Select-Object DeviceID, VolumeName, FileSystem, Size, FreeSpace, "
            "DriveType | ConvertTo-Json -Compress"
        )
        try:
            raw = self._run_powershell_json(ps)
            if isinstance(raw, dict):
                raw = [raw]

            drive_type_map = {
                2: "Removable",
                3: "Fixed",
                4: "Network",
                5: "CD-ROM",
                6: "RAM Disk",
            }

            for item in raw:
                size_bytes = item.get("Size")
                free_bytes = item.get("FreeSpace")

                size_gb = round(int(size_bytes) / (1024**3), 2) if size_bytes else None
                free_gb = round(int(free_bytes) / (1024**3), 2) if free_bytes else None
                used_gb = round(size_gb - free_gb, 2) if size_gb and free_gb else None
                usage_pct = (
                    round((used_gb / size_gb) * 100, 1) if size_gb and used_gb else None
                )

                disks.append({
                    "drive": item.get("DeviceID"),
                    "label": item.get("VolumeName") or "",
                    "file_system": item.get("FileSystem"),
                    "size_gb": size_gb,
                    "free_gb": free_gb,
                    "used_gb": used_gb,
                    "usage_percent": usage_pct,
                    "drive_type": drive_type_map.get(
                        item.get("DriveType", 0), "Unknown"
                    ),
                })
        except Exception as exc:
            result.errors.append(f"Logical disk query failed: {exc}")
        return disks

    def _get_physical_disks(self, result: CollectorResult) -> list[dict[str, Any]]:
        disks: list[dict[str, Any]] = []
        ps = (
            "Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue | "
            "Select-Object Model, InterfaceType, MediaType, Size, Partitions, Status | "
            "ConvertTo-Json -Compress"
        )
        try:
            raw = self._run_powershell_json(ps)
            if isinstance(raw, dict):
                raw = [raw]
            for item in raw:
                size_bytes = item.get("Size")
                size_gb = round(int(size_bytes) / (1024**3), 2) if size_bytes else None
                disks.append({
                    "model": item.get("Model"),
                    "interface": item.get("InterfaceType"),
                    "media_type": item.get("MediaType"),
                    "size_gb": size_gb,
                    "partitions": item.get("Partitions"),
                    "status": item.get("Status"),
                })
        except Exception as exc:
            result.errors.append(f"Physical disk query failed: {exc}")
        return disks

