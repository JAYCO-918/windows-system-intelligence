"""Diagnostic analyzers that process collected system data (read-only)."""

from __future__ import annotations

from wsi.core.base import BaseAnalyzer
from wsi.analyzers.health import HealthAnalyzer
from wsi.analyzers.software import SoftwareAnalyzer
from wsi.analyzers.startup_impact import StartupImpactAnalyzer
from wsi.analyzers.driver_security import DriverSecurityAnalyzer
from wsi.analyzers.event_health import EventHealthAnalyzer

__all__ = [
    "HealthAnalyzer",
    "SoftwareAnalyzer",
    "StartupImpactAnalyzer",
    "DriverSecurityAnalyzer",
    "EventHealthAnalyzer",
    "get_all_analyzers",
]

_ANALYZERS: list[type[BaseAnalyzer]] = [
    HealthAnalyzer,
    SoftwareAnalyzer,
    StartupImpactAnalyzer,
    DriverSecurityAnalyzer,
    EventHealthAnalyzer,
]


def get_all_analyzers() -> list[BaseAnalyzer]:
    """Instantiate and return one of each registered analyzer."""
    return [cls() for cls in _ANALYZERS]


def get_analyzer(name: str) -> BaseAnalyzer | None:
    """Find an analyzer by name."""
    for cls in _ANALYZERS:
        if cls.name == name:
            return cls()
    return None
