"""Startup programs collector (read-only).

Discovers applications configured to run at startup from:
- Registry Run / RunOnce keys
- Startup folders (user and machine)
- Scheduled tasks (active only)
"""

from __future__ import annotations

import os
import winreg
from typing import Any

from wsi.core.base import BaseCollector, CollectorResult
from wsi.core.registry import enumerate_subkeys, read_registry_value


class StartupCollector(BaseCollector):
    """Discovers programs configured to run at system startup — read-only."""

    name = "startup"
    description = "Discovers programs configured to run at system startup"

    _RUN_KEYS: list[tuple[int, str, str, str]] = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
         "registry_run", "machine"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
         "registry_runonce", "machine"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
         "registry_run", "user"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
         "registry_runonce", "user"),
    ]

    def collect(self) -> CollectorResult:
        result = CollectorResult(collector_name=self.name)

        # 1. Registry Run keys
        for hive, path, source, scope in self._RUN_KEYS:
            try:
                self._collect_run_key(hive, path, source, scope, result)
            except Exception as exc:
                result.errors.append(f"Error reading {source} ({scope}): {exc}")

        # 2. Startup folders
        try:
            self._collect_startup_folders(result)
        except Exception as exc:
            result.errors.append(f"Error scanning startup folders: {exc}")

        # 3. Scheduled tasks
        try:
            self._collect_scheduled_tasks(result)
        except Exception as exc:
            result.errors.append(f"Error enumerating scheduled tasks: {exc}")

        result.metadata["total_startup_items"] = len(result.data)
        return result

    def _collect_run_key(
        self,
        hive: int,
        path: str,
        source: str,
        scope: str,
        result: CollectorResult,
    ) -> None:
        """Read all values from a Run/RunOnce registry key."""
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(key, index)
                        entry: dict[str, Any] = {
                            "name": name,
                            "command": str(data) if data else "",
                            "source": source,
                            "location": f"{'HKLM' if hive == winreg.HKEY_LOCAL_MACHINE else 'HKCU'}\\{path}",
                            "scope": scope,
                            "enabled": True,
                        }
                        result.data.append(entry)
                        index += 1
                    except OSError:
                        break
        except FileNotFoundError:
            pass
        except PermissionError as exc:
            result.errors.append(f"Permission denied reading {path}: {exc}")

    def _collect_startup_folders(self, result: CollectorResult) -> None:
        """List files in user and machine startup folders (read-only)."""
        folders = [
            (
                os.path.join(
                    os.environ.get("APPDATA", ""),
                    r"Microsoft\Windows\Start Menu\Programs\Startup",
                ),
                "user",
            ),
            (
                os.path.join(
                    os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
                    r"Microsoft\Windows\Start Menu\Programs\Startup",
                ),
                "machine",
            ),
        ]

        for folder, scope in folders:
            if not os.path.isdir(folder):
                continue
            try:
                for entry_name in os.listdir(folder):
                    full_path = os.path.join(folder, entry_name)
                    entry: dict[str, Any] = {
                        "name": entry_name,
                        "command": full_path,
                        "source": "startup_folder",
                        "location": folder,
                        "scope": scope,
                        "enabled": True,
                    }
                    result.data.append(entry)
            except PermissionError as exc:
                result.errors.append(f"Cannot read startup folder {folder}: {exc}")

    def _collect_scheduled_tasks(self, result: CollectorResult) -> None:
        """Enumerate active scheduled tasks via PowerShell (read-only)."""
        ps = (
            "Get-ScheduledTask -ErrorAction SilentlyContinue | "
            "Where-Object { $_.State -ne 'Disabled' } | "
            "Select-Object TaskName, TaskPath, State, Description | "
            "ConvertTo-Json -Compress"
        )
        try:
            tasks = self._run_powershell_json(ps, timeout=60)
        except Exception as exc:
            result.errors.append(f"Scheduled task query failed: {exc}")
            return

        if isinstance(tasks, dict):
            tasks = [tasks]

        for task in tasks:
            entry: dict[str, Any] = {
                "name": task.get("TaskName", ""),
                "command": "",  # Full action details require deeper query
                "source": "scheduled_task",
                "location": task.get("TaskPath", ""),
                "scope": "machine",
                "enabled": task.get("State") == "Ready",
                "metadata": {
                    "state": task.get("State"),
                    "description": task.get("Description"),
                },
            }
            result.data.append(entry)

