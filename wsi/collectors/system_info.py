"""System information collector (read-only).

Collects OS, hardware, BIOS, and network configuration via WMI
using read-only PowerShell CIM queries.
"""

from __future__ import annotations

import os
from typing import Any

from wsi.core.base import BaseCollector, CollectorResult


class SystemInfoCollector(BaseCollector):
    """Collects system hardware and OS information — read-only."""

    name = "system_info"
    description = "Collects system hardware, OS, BIOS, and network configuration"

    def collect(self) -> CollectorResult:
        result = CollectorResult(collector_name=self.name)

        data: dict[str, Any] = {
            "os": self._get_os_info(result),
            "hardware": self._get_hardware_info(result),
            "bios": self._get_bios_info(result),
            "network": self._get_network_info(result),
            "identity": self._get_identity_info(),
        }

        result.data.append(data)
        return result

    def _get_os_info(self, result: CollectorResult) -> dict[str, Any]:
        ps = (
            "Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue | "
            "Select-Object Caption, Version, BuildNumber, OSArchitecture, "
            "InstallDate, LastBootUpTime, SystemDirectory, WindowsDirectory | "
            "ConvertTo-Json -Compress"
        )
        try:
            info = self._run_powershell_json(ps)
            if isinstance(info, list) and info:
                info = info[0]
            if isinstance(info, dict):
                return {
                    "caption": info.get("Caption"),
                    "version": info.get("Version"),
                    "build_number": info.get("BuildNumber"),
                    "architecture": info.get("OSArchitecture"),
                    "install_date": str(info.get("InstallDate")),
                    "last_boot": str(info.get("LastBootUpTime")),
                    "system_directory": info.get("SystemDirectory"),
                    "windows_directory": info.get("WindowsDirectory"),
                }
        except Exception as exc:
            result.errors.append(f"OS info query failed: {exc}")
        return {}

    def _get_hardware_info(self, result: CollectorResult) -> dict[str, Any]:
        hardware: dict[str, Any] = {}

        # Processor
        try:
            ps_cpu = (
                "Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | "
                "Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed | "
                "ConvertTo-Json -Compress"
            )
            cpu = self._run_powershell_json(ps_cpu)
            if isinstance(cpu, list) and cpu:
                cpu = cpu[0]
            if isinstance(cpu, dict):
                hardware["cpu"] = {
                    "name": cpu.get("Name"),
                    "cores": cpu.get("NumberOfCores"),
                    "threads": cpu.get("NumberOfLogicalProcessors"),
                    "max_clock_mhz": cpu.get("MaxClockSpeed"),
                }
        except Exception as exc:
            result.errors.append(f"CPU info query failed: {exc}")

        # Memory
        try:
            ps_mem = (
                "Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | "
                "Select-Object TotalPhysicalMemory | ConvertTo-Json -Compress"
            )
            cs = self._run_powershell_json(ps_mem)
            if isinstance(cs, list) and cs:
                cs = cs[0]
            if isinstance(cs, dict):
                total_bytes = cs.get("TotalPhysicalMemory")
                if total_bytes:
                    total_gb = round(int(total_bytes) / (1024**3), 2)
                    hardware["memory_total_gb"] = total_gb
        except Exception as exc:
            result.errors.append(f"Memory info query failed: {exc}")

        # Motherboard
        try:
            ps_board = (
                "Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue | "
                "Select-Object Manufacturer, Product | ConvertTo-Json -Compress"
            )
            board = self._run_powershell_json(ps_board)
            if isinstance(board, list) and board:
                board = board[0]
            if isinstance(board, dict):
                hardware["motherboard"] = {
                    "manufacturer": board.get("Manufacturer"),
                    "product": board.get("Product"),
                }
        except Exception as exc:
            result.errors.append(f"Motherboard query failed: {exc}")

        return hardware

    def _get_bios_info(self, result: CollectorResult) -> dict[str, Any]:
        ps = (
            "Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue | "
            "Select-Object Manufacturer, SMBIOSBIOSVersion, ReleaseDate | "
            "ConvertTo-Json -Compress"
        )
        try:
            info = self._run_powershell_json(ps)
            if isinstance(info, list) and info:
                info = info[0]
            if isinstance(info, dict):
                return {
                    "manufacturer": info.get("Manufacturer"),
                    "version": info.get("SMBIOSBIOSVersion"),
                    "release_date": str(info.get("ReleaseDate")),
                }
        except Exception as exc:
            result.errors.append(f"BIOS info query failed: {exc}")
        return {}

    def _get_network_info(self, result: CollectorResult) -> list[dict[str, Any]]:
        adapters: list[dict[str, Any]] = []
        ps = (
            "Get-CimInstance Win32_NetworkAdapterConfiguration "
            "-Filter 'IPEnabled = True' -ErrorAction SilentlyContinue | "
            "Select-Object Description, IPAddress, IPSubnet, DefaultIPGateway, "
            "DNSServerSearchOrder, MACAddress, DHCPEnabled | "
            "ConvertTo-Json -Compress"
        )
        try:
            raw = self._run_powershell_json(ps)
            if isinstance(raw, dict):
                raw = [raw]
            for nic in raw:
                adapters.append({
                    "description": nic.get("Description"),
                    "ip_addresses": nic.get("IPAddress", []),
                    "mac_address": nic.get("MACAddress"),
                    "dhcp_enabled": bool(nic.get("DHCPEnabled")),
                    "dns_servers": nic.get("DNSServerSearchOrder", []),
                })
        except Exception as exc:
            result.errors.append(f"Network info query failed: {exc}")
        return adapters

    def _get_identity_info(self) -> dict[str, Any]:
        return {
            "computer_name": os.environ.get("COMPUTERNAME", "Unknown"),
            "username": os.environ.get("USERNAME", "Unknown"),
            "user_domain": os.environ.get("USERDOMAIN", "Unknown"),
        }

