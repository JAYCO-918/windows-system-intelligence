"""Read-only data collectors for Windows system information."""

from __future__ import annotations

from wsi.core.base import BaseCollector
from wsi.collectors.apps import InstalledAppsCollector
from wsi.collectors.services import ServicesCollector
from wsi.collectors.startup import StartupCollector
from wsi.collectors.system_info import SystemInfoCollector
from wsi.collectors.storage import StorageCollector
from wsi.collectors.execution_history import ExecutionHistoryCollector
from wsi.collectors.environment import EnvironmentCollector
from wsi.collectors.event_logs import EventLogsCollector
from wsi.collectors.network_surface import NetworkSurfaceCollector

__all__ = [
    "InstalledAppsCollector",
    "ServicesCollector",
    "StartupCollector",
    "SystemInfoCollector",
    "StorageCollector",
    "ExecutionHistoryCollector",
    "EnvironmentCollector",
    "EventLogsCollector",
    "NetworkSurfaceCollector",
    "get_all_collectors",
]

_COLLECTORS: list[type[BaseCollector]] = [
    InstalledAppsCollector,
    ServicesCollector,
    StartupCollector,
    SystemInfoCollector,
    StorageCollector,
    ExecutionHistoryCollector,
    EnvironmentCollector,
    EventLogsCollector,
    NetworkSurfaceCollector,
]


def get_all_collectors() -> list[BaseCollector]:
    """Instantiate and return one of each registered collector."""
    return [cls() for cls in _COLLECTORS]


def get_collector(name: str) -> BaseCollector | None:
    """Find a collector by name."""
    for cls in _COLLECTORS:
        if cls.name == name:
            return cls()
    return None
