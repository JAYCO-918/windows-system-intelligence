"""Startup and boot impact diagnostic analyzer (read-only).

Analyzes collected startup and task items for:
- Unquoted executable paths with spaces (path hijacking / parsing risk)
- Broken startup paths (target binary no longer exists on disk)
- Excessive startup volume (high boot impact)
- Duplicate startup configurations across scopes
"""

from __future__ import annotations

import os
import re
import shlex
from typing import Any

from wsi.core.base import AnalysisResult, BaseAnalyzer, CollectorResult, Finding


class StartupImpactAnalyzer(BaseAnalyzer):
    """Evaluates boot impact and startup integrity — read-only."""

    name = "startup_impact"
    description = "Analyzes startup entries for boot delays, broken paths, and unquoted binary targets"

    def analyze(
        self, collector_results: dict[str, CollectorResult]
    ) -> AnalysisResult:
        result = AnalysisResult(analyzer_name=self.name)

        startup_res = collector_results.get("startup")
        if not startup_res or not startup_res.data:
            result.summary = "No startup data available to analyze."
            return result

        items = startup_res.data
        total_items = len(items)

        # 1. Volume evaluation
        if total_items > 30:
            result.findings.append(
                Finding(
                    severity="warning",
                    category="startup",
                    title=f"High startup footprint: {total_items} items configured",
                    description=(
                        f"There are {total_items} programs and scheduled tasks configured "
                        "to run automatically at boot/login. This may significantly increase boot latency."
                    ),
                    details={"total_count": total_items},
                    recommendation="Review startup applications and disable unneeded background utilities.",
                )
            )

        # 2. Check each startup command
        seen_binaries: set[str] = set()

        for item in items:
            cmd = item.get("command", "").strip()
            name = item.get("name", "Unknown")
            source = item.get("source", "")

            if not cmd:
                continue

            # Check unquoted path vulnerability/issue
            self._check_unquoted_path(name, cmd, item, result)

            # Check target binary existence
            target_exe = self._extract_executable_path(cmd)
            if target_exe:
                # Expand environment variables like %windir%
                expanded_exe = os.path.expandvars(target_exe)
                norm_exe = expanded_exe.lower()
                if norm_exe in seen_binaries:
                    result.findings.append(
                        Finding(
                            severity="info",
                            category="startup",
                            title=f"Duplicate startup target: {name}",
                            description=f"Binary '{target_exe}' is invoked by multiple startup entries.",
                            details=item,
                            recommendation="Remove redundant startup registrations for this application.",
                        )
                    )
                else:
                    seen_binaries.add(norm_exe)

                # Check if target binary exists
                if not os.path.exists(expanded_exe):
                    result.findings.append(
                        Finding(
                            severity="warning",
                            category="startup",
                            title=f"Broken startup target: {name}",
                            description=f"Startup command points to a non-existent binary: {target_exe}",
                            details=item,
                            recommendation="Remove obsolete startup registry key or file shortcut.",
                        )
                    )

        warn_count = sum(1 for f in result.findings if f.severity == "warning")
        info_count = sum(1 for f in result.findings if f.severity == "info")
        result.summary = (
            f"Startup analysis complete: {warn_count} warnings, "
            f"{info_count} informational findings across {total_items} startup items."
        )
        return result

    def _extract_executable_path(self, cmd: str) -> str | None:
        """Attempt to extract the executable path from a command string."""
        if not cmd:
            return None

        # If quoted at start
        if cmd.startswith('"'):
            end_quote = cmd.find('"', 1)
            if end_quote != -1:
                return cmd[1:end_quote]

        # First token
        parts = cmd.split()
        if parts:
            first = parts[0]
            if first.lower().endswith((".exe", ".bat", ".cmd", ".ps1", ".vbs")):
                return first
            # Check if joining tokens creates an existing path
            candidate = ""
            for p in parts:
                candidate = f"{candidate} {p}".strip()
                if os.path.isfile(candidate):
                    return candidate

        return None

    def _check_unquoted_path(
        self, name: str, cmd: str, item: dict[str, Any], result: AnalysisResult
    ) -> None:
        """Identify commands that have unquoted paths containing spaces."""
        if cmd.startswith('"') or not (" " in cmd):
            return

        # Check if first part looks like a path with spaces missing quotes
        match = re.match(r"^([A-Za-z]:\\[^,\"]+?\.(?:exe|bat|cmd))\s+", cmd, re.IGNORECASE)
        if match:
            path = match.group(1)
            if " " in path:
                result.findings.append(
                    Finding(
                        severity="info",
                        category="startup",
                        title=f"Unquoted startup path with spaces: {name}",
                        description=(
                            f"The startup command uses an unquoted path containing spaces: {path}. "
                            "While Windows may resolve it, quoting ensures deterministic execution."
                        ),
                        details=item,
                        recommendation=f'Enclose the executable path in quotes: "{path}"',
                    )
                )
