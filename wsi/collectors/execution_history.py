"""Application execution history collector (read-only).

Collects evidence of previously executed applications from Windows
forensic artifacts:
- Prefetch file listing (timestamps, counts — no binary parsing)
- UserAssist registry keys (ROT-13 decoded)
- Background Activity Moderator (BAM/DAM) registry records
- Amcache presence check

All access is strictly read-only.
"""

from __future__ import annotations

import codecs
import datetime
import os
import struct
import winreg
from typing import Any

from wsi.core.base import BaseCollector, CollectorResult
from wsi.core.registry import enumerate_subkeys, read_registry_values


def _filetime_to_iso(filetime: int) -> str | None:
    """Convert a 64-bit Windows FILETIME to an ISO timestamp."""
    if filetime <= 0:
        return None
    # FILETIME is 100-nanosecond intervals since Jan 1, 1601 UTC
    epoch_diff = 116444736000000000  # 1601 to 1970 in 100ns intervals
    try:
        us = (filetime - epoch_diff) // 10
        if us < 0:
            return None
        dt = datetime.datetime.fromtimestamp(us / 1_000_000, tz=datetime.timezone.utc)
        return dt.isoformat()
    except (OSError, OverflowError, ValueError):
        return None


class ExecutionHistoryCollector(BaseCollector):
    """Gathers application execution history from forensic artifacts — read-only."""

    name = "execution_history"
    description = "Collects application execution history from Prefetch, UserAssist, and BAM"

    def collect(self) -> CollectorResult:
        result = CollectorResult(collector_name=self.name)

        # 1. Prefetch file listing
        try:
            self._collect_prefetch(result)
        except Exception as exc:
            result.errors.append(f"Prefetch collection error: {exc}")

        # 2. UserAssist
        try:
            self._collect_userassist(result)
        except Exception as exc:
            result.errors.append(f"UserAssist collection error: {exc}")

        # 3. BAM / DAM
        try:
            self._collect_bam(result)
        except Exception as exc:
            result.errors.append(f"BAM collection error: {exc}")

        # 4. Amcache presence check
        self._check_amcache(result)

        result.data.sort(key=lambda x: x.get("last_seen") or "", reverse=True)
        result.metadata["total_execution_records"] = len(result.data)
        return result

    def _collect_prefetch(self, result: CollectorResult) -> None:
        """List Prefetch files (read-only file metadata, no content read)."""
        prefetch_dir = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"), "Prefetch"
        )
        if not os.path.isdir(prefetch_dir):
            return

        try:
            entries = os.scandir(prefetch_dir)
        except PermissionError:
            result.errors.append("Access denied to Prefetch folder (requires admin)")
            return

        with entries:
            for entry in entries:
                if not entry.name.endswith(".pf"):
                    continue
                try:
                    stat = entry.stat()
                    # Name format is usually PROGRAM-HASH.pf
                    raw_name = entry.name[:-3]
                    parts = raw_name.rsplit("-", 1)
                    app_name = parts[0]

                    created = datetime.datetime.fromtimestamp(
                        stat.st_ctime, tz=datetime.timezone.utc
                    ).isoformat()
                    modified = datetime.datetime.fromtimestamp(
                        stat.st_mtime, tz=datetime.timezone.utc
                    ).isoformat()

                    result.data.append({
                        "executable": app_name,
                        "source": "prefetch",
                        "first_seen": created,
                        "last_seen": modified,
                        "run_count": None,
                        "metadata": {
                            "file_name": entry.name,
                            "hash": parts[1] if len(parts) > 1 else None,
                        },
                    })
                except (OSError, PermissionError):
                    continue

    def _collect_userassist(self, result: CollectorResult) -> None:
        """Decode UserAssist registry entries (ROT-13)."""
        base_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        subkeys = enumerate_subkeys(winreg.HKEY_CURRENT_USER, base_path)

        for guid in subkeys:
            count_path = f"{base_path}\\{guid}\\Count"
            try:
                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER, count_path, 0, winreg.KEY_READ
                ) as key:
                    index = 0
                    while True:
                        try:
                            name, data, _ = winreg.EnumValue(key, index)
                            index += 1

                            # Decode ROT13 value name
                            decoded_name = codecs.decode(name, "rot_13")

                            # Parse binary data (Win7/10/11 format: 72 bytes)
                            run_count = None
                            last_run = None
                            if isinstance(data, bytes) and len(data) >= 68:
                                # Count is a 32-bit int at offset 4
                                (count,) = struct.unpack_from("<I", data, 4)
                                run_count = count
                                # Last execution FILETIME is at offset 60
                                (ft,) = struct.unpack_from("<Q", data, 60)
                                last_run = _filetime_to_iso(ft)

                            result.data.append({
                                "executable": decoded_name,
                                "source": "userassist",
                                "first_seen": None,
                                "last_seen": last_run,
                                "run_count": run_count,
                                "metadata": {"guid": guid},
                            })
                        except OSError:
                            break
            except (FileNotFoundError, PermissionError):
                continue

    def _collect_bam(self, result: CollectorResult) -> None:
        """Collect Background Activity Moderator records (read-only)."""
        base = r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
        sids = enumerate_subkeys(winreg.HKEY_LOCAL_MACHINE, base)

        for sid in sids:
            path = f"{base}\\{sid}"
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ
                ) as key:
                    index = 0
                    while True:
                        try:
                            name, data, _ = winreg.EnumValue(key, index)
                            index += 1

                            last_run = None
                            if isinstance(data, bytes) and len(data) >= 8:
                                (ft,) = struct.unpack_from("<Q", data, 0)
                                last_run = _filetime_to_iso(ft)

                            result.data.append({
                                "executable": name,
                                "source": "bam",
                                "first_seen": None,
                                "last_seen": last_run,
                                "run_count": None,
                                "metadata": {"sid": sid},
                            })
                        except OSError:
                            break
            except (FileNotFoundError, PermissionError):
                continue

    def _check_amcache(self, result: CollectorResult) -> None:
        """Check if Amcache.hve exists without opening or locking it."""
        amcache = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"),
            "AppCompat",
            "Programs",
            "Amcache.hve",
        )
        if os.path.isfile(amcache):
            try:
                st = os.stat(amcache)
                result.metadata["amcache_present"] = True
                result.metadata["amcache_size_bytes"] = st.st_size
                result.metadata["amcache_modified"] = datetime.datetime.fromtimestamp(
                    st.st_mtime, tz=datetime.timezone.utc
                ).isoformat()
            except PermissionError:
                result.metadata["amcache_present"] = True
                result.metadata["amcache_accessible"] = False
        else:
            result.metadata["amcache_present"] = False

