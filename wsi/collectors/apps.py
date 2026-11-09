"""Installed applications collector (read-only).

Discovers applications from:
- Registry Uninstall keys (HKLM + HKCU, 64-bit + 32-bit)
- Appx / MSIX packages via PowerShell
- Windows Installer (MSI) database via registry
"""

from __future__ import annotations

import winreg
from typing import Any

from wsi.core.base import BaseCollector, CollectorResult
from wsi.core.registry import enumerate_subkeys, read_registry_values


class InstalledAppsCollector(BaseCollector):
    """Enumerates all installed applications — read-only."""

    name = "installed_apps"
    description = "Discovers installed applications from registry, Appx, and MSI sources"

    # Registry paths to scan for uninstall entries
    _UNINSTALL_PATHS: list[tuple[int, str, str]] = [
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "registry_64",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            "registry_32",
        ),
        (
            winreg.HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "registry_user",
        ),
    ]

    _VALUE_NAMES = [
        "DisplayName",
        "DisplayVersion",
        "Publisher",
        "InstallDate",
        "InstallLocation",
        "UninstallString",
        "EstimatedSize",
        "SystemComponent",
        "WindowsInstaller",
    ]

    def collect(self) -> CollectorResult:
        result = CollectorResult(collector_name=self.name)
        seen_names: dict[str, int] = {}  # name_lower -> index in result.data

        # 1. Registry uninstall keys
        for hive, path, source in self._UNINSTALL_PATHS:
            try:
                self._collect_registry_apps(hive, path, source, result, seen_names)
            except Exception as exc:
                result.errors.append(f"Error reading {source}: {exc}")

        # 2. Appx / MSIX packages
        try:
            self._collect_appx(result, seen_names)
        except Exception as exc:
            result.errors.append(f"Error collecting Appx packages: {exc}")

        # Sort by name
        result.data.sort(key=lambda x: (x.get("name") or "").lower())
        result.metadata["total_apps"] = len(result.data)
        return result

    def _collect_registry_apps(
        self,
        hive: int,
        path: str,
        source: str,
        result: CollectorResult,
        seen: dict[str, int],
    ) -> None:
        """Enumerate uninstall registry subkeys and extract app info."""
        for subkey_name in enumerate_subkeys(hive, path):
            subkey_path = f"{path}\\{subkey_name}"
            vals = read_registry_values(hive, subkey_path, self._VALUE_NAMES)

            display_name = vals.get("DisplayName")
            if not display_name:
                continue

            # Skip system components
            sys_comp = vals.get("SystemComponent")
            if sys_comp and int(sys_comp) == 1:
                continue

            est_size = vals.get("EstimatedSize")
            size_mb = round(est_size / 1024, 2) if est_size else None

            entry: dict[str, Any] = {
                "name": display_name,
                "version": vals.get("DisplayVersion"),
                "publisher": vals.get("Publisher"),
                "install_date": vals.get("InstallDate"),
                "install_location": vals.get("InstallLocation"),
                "source": "registry",
                "architecture": "x86" if "WOW6432Node" in path else "x64",
                "estimated_size_mb": size_mb,
                "metadata": {
                    "registry_source": source,
                    "registry_key": subkey_name,
                    "uninstall_string": vals.get("UninstallString"),
                    "is_msi": bool(vals.get("WindowsInstaller")),
                },
            }

            # Deduplication
            key = display_name.lower()
            if key in seen:
                # Merge source info into existing entry's metadata
                idx = seen[key]
                existing = result.data[idx]
                existing["metadata"].setdefault("additional_sources", []).append(source)
            else:
                seen[key] = len(result.data)
                result.data.append(entry)

    def _collect_appx(
        self,
        result: CollectorResult,
        seen: dict[str, int],
    ) -> None:
        """Collect Appx/MSIX packages via PowerShell (read-only)."""
        ps_script = (
            "Get-AppxPackage -ErrorAction SilentlyContinue | "
            "Where-Object { -not $_.IsFramework } | "
            "Select-Object Name, PackageFullName, Version, Publisher, "
            "InstallLocation, Architecture, Status | "
            "ConvertTo-Json -Compress"
        )
        try:
            packages = self._run_powershell_json(ps_script, timeout=60)
        except Exception as exc:
            result.errors.append(f"Appx enumeration failed: {exc}")
            return

        if isinstance(packages, dict):
            packages = [packages]

        for pkg in packages:
            name = pkg.get("Name", "")
            if not name:
                continue

            entry: dict[str, Any] = {
                "name": name,
                "version": pkg.get("Version"),
                "publisher": pkg.get("Publisher"),
                "install_date": None,
                "install_location": pkg.get("InstallLocation"),
                "source": "appx",
                "architecture": str(pkg.get("Architecture", "")),
                "estimated_size_mb": None,
                "metadata": {
                    "package_full_name": pkg.get("PackageFullName"),
                    "status": str(pkg.get("Status", "")),
                },
            }

            key = name.lower()
            if key not in seen:
                seen[key] = len(result.data)
                result.data.append(entry)

