"""Base classes for WSI collectors and analyzers.

All collectors and analyzers are strictly READ-ONLY — they must never
modify the host operating system, registry, file system, or any global
configuration.
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Collector infrastructure
# ---------------------------------------------------------------------------

@dataclass
class CollectorResult:
    """Container for data returned by a collector.

    Attributes:
        collector_name: Identifier of the collector that produced this result.
        timestamp: When the collection started.
        data: List of collected records (each record is a dict).
        errors: List of non-fatal error messages encountered during collection.
        duration_seconds: Wall-clock time the collection took.
        metadata: Optional extra metadata about the collection run.
    """

    collector_name: str
    timestamp: str = ""
    data: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        """Return *True* if at least some data was collected."""
        return len(self.data) > 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict (JSON-friendly)."""
        return asdict(self)


class BaseCollector(ABC):
    """Abstract base class for all WSI data collectors.

    Subclasses must set ``name`` and ``description`` class attributes and
    implement the :meth:`collect` method.  All collection logic **must** be
    read-only and non-destructive.
    """

    name: str = ""
    description: str = ""

    def __init__(self) -> None:
        self.logger = logging.getLogger(f"wsi.collectors.{self.name}")

    @abstractmethod
    def collect(self) -> CollectorResult:
        """Collect data from the system and return a :class:`CollectorResult`.

        This method must be entirely read-only — no writes to the registry,
        file system, or system configuration are permitted.
        """
        ...

    def safe_collect(self) -> CollectorResult:
        """Run :meth:`collect` wrapped in error handling and timing."""
        start = time.perf_counter()
        ts = datetime.now(timezone.utc).isoformat()
        try:
            result = self.collect()
        except Exception as exc:
            self.logger.exception("Collector '%s' failed", self.name)
            result = CollectorResult(
                collector_name=self.name,
                errors=[f"Unhandled exception: {exc}"],
            )
        result.timestamp = ts
        result.duration_seconds = time.perf_counter() - start
        self.logger.info(
            "Collector '%s' finished in %.2fs — %d records, %d errors",
            self.name,
            result.duration_seconds,
            len(result.data),
            len(result.errors),
        )
        return result

    # ---- helpers (read-only) ----

    def _run_command(
        self, cmd: list[str], *, timeout: int = 30
    ) -> str:
        """Run an external command and return its stdout.

        Uses ``shell=False`` for safety.  Raises on non-zero exit.
        """
        self.logger.debug("Running command: %s", cmd)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"Command {cmd} exited with code {proc.returncode}: "
                f"{proc.stderr.strip()}"
            )
        return proc.stdout

    def _run_powershell(
        self, script: str, *, timeout: int = 60
    ) -> str:
        """Execute a PowerShell snippet and return its stdout."""
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ]
        return self._run_command(cmd, timeout=timeout)

    def _run_powershell_json(
        self, script: str, *, timeout: int = 60
    ) -> Any:
        """Execute a PowerShell snippet that emits JSON and parse the result."""
        raw = self._run_powershell(script, timeout=timeout)
        if not raw.strip():
            return []
        return json.loads(raw)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"


# ---------------------------------------------------------------------------
# Analyzer infrastructure
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single diagnostic finding.

    Attributes:
        severity: One of ``"info"``, ``"warning"``, ``"critical"``.
        category: Broad category (e.g. ``"storage"``, ``"software"``).
        title: Short one-line summary.
        description: Detailed explanation.
        details: Any machine-readable context.
        recommendation: Suggested action for the user.
    """

    severity: str  # "info" | "warning" | "critical"
    category: str
    title: str
    description: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    """Container for analyzer output.

    Attributes:
        analyzer_name: Identifier of the analyzer.
        timestamp: When the analysis started.
        findings: List of diagnostic findings.
        summary: Human-readable summary.
        duration_seconds: Wall-clock time the analysis took.
    """

    analyzer_name: str
    timestamp: str = ""
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


class BaseAnalyzer(ABC):
    """Abstract base class for diagnostic analyzers.

    Analyzers consume :class:`CollectorResult` objects and produce
    :class:`AnalysisResult` objects with findings and recommendations.

    Analyzers are also strictly read-only.
    """

    name: str = ""
    description: str = ""

    def __init__(self) -> None:
        self.logger = logging.getLogger(f"wsi.analyzers.{self.name}")

    @abstractmethod
    def analyze(
        self, collector_results: dict[str, CollectorResult]
    ) -> AnalysisResult:
        """Analyze collected data and return findings."""
        ...

    def safe_analyze(
        self, collector_results: dict[str, CollectorResult]
    ) -> AnalysisResult:
        """Run :meth:`analyze` wrapped in error handling and timing."""
        start = time.perf_counter()
        ts = datetime.now(timezone.utc).isoformat()
        try:
            result = self.analyze(collector_results)
        except Exception as exc:
            self.logger.exception("Analyzer '%s' failed", self.name)
            result = AnalysisResult(
                analyzer_name=self.name,
                summary=f"Analysis failed: {exc}",
            )
        result.timestamp = ts
        result.duration_seconds = time.perf_counter() - start
        return result

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"
