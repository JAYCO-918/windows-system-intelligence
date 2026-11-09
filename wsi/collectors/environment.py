"""Environment variables and runtime analysis collector (read-only).

Gathers:
- Complete environment variables (read-only snapshot)
- PATH analysis (identifies missing directories, duplicate entries)
- Installed development runtimes (Python, Node, Git, etc.)
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Any

from wsi.core.base import BaseCollector, CollectorResult


class EnvironmentCollector(BaseCollector):
    """Collects environment variables, PATH health, and runtime info — read-only."""

    name = "environment"
    description = "Collects environment variables, analyzes PATH, and detects runtimes"

    def collect(self) -> CollectorResult:
        result = CollectorResult(collector_name=self.name)

        env_vars = dict(os.environ)
        path_entries = self._analyze_path(env_vars.get("PATH", ""))
        detected_runtimes = self._detect_runtimes()

        data: dict[str, Any] = {
            "environment_variables": env_vars,
            "path_analysis": path_entries,
            "detected_runtimes": detected_runtimes,
        }

        result.data.append(data)
        return result

    def _analyze_path(self, raw_path: str) -> dict[str, Any]:
        """Analyze the PATH variable for issues (read-only)."""
        entries = raw_path.split(os.pathsep) if raw_path else []

        valid_entries: list[dict[str, Any]] = []
        issues: list[dict[str, str]] = []
        seen: set[str] = set()

        for raw_entry in entries:
            clean = raw_entry.strip().strip('"')
            if not clean:
                continue

            # Duplicate check
            norm = os.path.normcase(os.path.normpath(clean))
            is_dup = norm in seen
            seen.add(norm)

            # Existence check (read-only filesystem stat)
            exists = os.path.isdir(clean)

            if is_dup:
                issues.append({"issue": "duplicate", "path": clean})
            if not exists:
                issues.append({"issue": "directory_not_found", "path": clean})

            entry_info: dict[str, Any] = {
                "path": clean,
                "exists": exists,
                "is_duplicate": is_dup,
            }

            # If directory exists, count entries (read-only)
            if exists:
                try:
                    entry_info["item_count"] = len(os.listdir(clean))
                except (PermissionError, OSError):
                    entry_info["item_count"] = None

            valid_entries.append(entry_info)

        return {
            "total_entries": len(entries),
            "valid_directories": sum(1 for e in valid_entries if e["exists"]),
            "missing_directories": sum(1 for e in valid_entries if not e["exists"]),
            "duplicates": sum(1 for e in valid_entries if e["is_duplicate"]),
            "entries": valid_entries,
            "issues": issues,
        }

    def _detect_runtimes(self) -> list[dict[str, Any]]:
        """Probe for installed developer runtimes (read-only version checks)."""
        probes: list[tuple[str, list[str], str]] = [
            ("Python", ["python", "--version"], "python"),
            ("Node.js", ["node", "--version"], "node"),
            ("Git", ["git", "--version"], "git"),
            ("Java", ["java", "-version"], "java"),
            (".NET", ["dotnet", "--version"], "dotnet"),
            ("PowerShell", ["powershell", "-NoProfile", "$PSVersionTable.PSVersion.ToString()"], "powershell"),
            ("Rust", ["rustc", "--version"], "rustc"),
            ("Go", ["go", "version"], "go"),
        ]

        found: list[dict[str, Any]] = []
        for name, cmd, bin_name in probes:
            # First check if the binary exists on PATH
            bin_path = shutil.which(bin_name)
            if not bin_path:
                continue

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5,
                    shell=False,
                )
                output = (proc.stdout or proc.stderr).strip().splitlines()
                version = output[0] if output else "Unknown"
                found.append({
                    "name": name,
                    "version": version,
                    "path": bin_path,
                })
            except Exception:
                found.append({
                    "name": name,
                    "version": "Installed (version query failed)",
                    "path": bin_path,
                })

        return found

