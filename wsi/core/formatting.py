"""Output formatting utilities for WSI.

Provides table, JSON, and summary formatters for displaying
collector and analyzer results.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any


def _default_serializer(obj: object) -> Any:
    """JSON serializer for objects not serializable by default."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "to_dict"):
        return obj.to_dict()  # type: ignore[union-attr]
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def format_json(data: Any, *, indent: int = 2) -> str:
    """Serialize *data* to a JSON string with datetime support."""
    return json.dumps(data, indent=indent, default=_default_serializer, ensure_ascii=False)


def truncate(text: str, max_len: int = 80) -> str:
    """Truncate *text* to *max_len* characters, adding ``…`` if shortened."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def format_table(
    headers: list[str],
    rows: list[list[str]],
    *,
    max_col_width: int = 60,
) -> str:
    """Render a simple ASCII table.

    Parameters:
        headers: Column header labels.
        rows: List of rows, each a list of cell strings.
        max_col_width: Maximum width for any column.

    Returns:
        A multi-line string containing the formatted table.
    """
    if not headers:
        return ""

    # Truncate cell values and compute column widths.
    processed_rows: list[list[str]] = []
    for row in rows:
        processed_rows.append(
            [truncate(str(cell), max_col_width) for cell in row]
        )

    col_widths = [len(h) for h in headers]
    for row in processed_rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(cell))

    def _fmt_row(cells: list[str]) -> str:
        parts = []
        for i, cell in enumerate(cells):
            w = col_widths[i] if i < len(col_widths) else len(cell)
            parts.append(cell.ljust(w))
        return "  ".join(parts)

    lines = [
        _fmt_row(headers),
        "  ".join("-" * w for w in col_widths),
    ]
    for row in processed_rows:
        lines.append(_fmt_row(row))

    return "\n".join(lines)


def format_summary(title: str, items: dict[str, Any]) -> str:
    """Render a key-value summary block.

    Example output::

        === System Info ===
        OS Name      : Windows 11 Pro
        Build        : 22631
    """
    lines = [f"=== {title} ==="]
    if not items:
        lines.append("  (no data)")
        return "\n".join(lines)

    max_key = max(len(str(k)) for k in items)
    for key, value in items.items():
        lines.append(f"  {str(key).ljust(max_key)}  : {value}")
    return "\n".join(lines)


def format_size_bytes(size_bytes: float | int | None) -> str:
    """Format a byte count as a human-readable size string."""
    if size_bytes is None:
        return "N/A"
    size = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size) < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"

