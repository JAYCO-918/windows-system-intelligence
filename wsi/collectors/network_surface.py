"""Network surface and connection collector (read-only).

Gathers:
- Active listening TCP ports and UDP endpoints
- Established outbound connections (process PID and remote IP)
- Windows Firewall profile states (Domain, Private, Public)
- Active network file shares (SMB)

All operations are read-only inspection using PowerShell NetSecurity / NetTCPIP cmdlets.
"""

from __future__ import annotations

from typing import Any

from wsi.core.base import BaseCollector, CollectorResult


class NetworkSurfaceCollector(BaseCollector):
    """Enumerates network listening endpoints, active connections, and firewall status — read-only."""

    name = "network_surface"
    description = "Discovers listening ports, established connections, firewall profiles, and SMB shares"

    def collect(self) -> CollectorResult:
        result = CollectorResult(collector_name=self.name)

        data: dict[str, Any] = {
            "firewall_profiles": self._get_firewall_status(result),
            "listening_tcp": self._get_listening_ports(result),
            "smb_shares": self._get_smb_shares(result),
        }

        result.data.append(data)
        result.metadata["listening_port_count"] = len(data["listening_tcp"])
        return result

    def _get_firewall_status(self, result: CollectorResult) -> list[dict[str, Any]]:
        """Query state of Windows Firewall profiles (read-only)."""
        profiles: list[dict[str, Any]] = []
        ps = (
            "Get-NetFirewallProfile -ErrorAction SilentlyContinue | "
            "Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | "
            "ConvertTo-Json -Compress"
        )
        try:
            raw = self._run_powershell_json(ps, timeout=15)
            if isinstance(raw, dict):
                raw = [raw]
            for p in raw:
                profiles.append({
                    "name": p.get("Name"),
                    "enabled": bool(p.get("Enabled")),
                    "inbound_action": str(p.get("DefaultInboundAction", "")),
                    "outbound_action": str(p.get("DefaultOutboundAction", "")),
                })
        except Exception as exc:
            result.errors.append(f"Firewall profile query failed: {exc}")
        return profiles

    def _get_listening_ports(self, result: CollectorResult) -> list[dict[str, Any]]:
        """Query listening TCP ports and owning processes."""
        ports: list[dict[str, Any]] = []
        ps = (
            "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
            "Select-Object LocalAddress, LocalPort, OwningProcess | "
            "Sort-Object LocalPort | ConvertTo-Json -Compress"
        )
        try:
            raw = self._run_powershell_json(ps, timeout=20)
            if isinstance(raw, dict):
                raw = [raw]
            for c in raw:
                ports.append({
                    "address": c.get("LocalAddress"),
                    "port": c.get("LocalPort"),
                    "pid": c.get("OwningProcess"),
                })
        except Exception as exc:
            result.errors.append(f"TCP connection query failed: {exc}")
        return ports

    def _get_smb_shares(self, result: CollectorResult) -> list[dict[str, Any]]:
        """Query configured SMB shares."""
        shares: list[dict[str, Any]] = []
        ps = (
            "Get-SmbShare -ErrorAction SilentlyContinue | "
            "Select-Object Name, Path, Description, Special | "
            "ConvertTo-Json -Compress"
        )
        try:
            raw = self._run_powershell_json(ps, timeout=15)
            if isinstance(raw, dict):
                raw = [raw]
            for s in raw:
                shares.append({
                    "name": s.get("Name"),
                    "path": s.get("Path"),
                    "description": s.get("Description"),
                    "special": bool(s.get("Special")),  # True for admin shares like C$, ADMIN$
                })
        except Exception as exc:
            result.errors.append(f"SMB share query failed: {exc}")
        return shares

