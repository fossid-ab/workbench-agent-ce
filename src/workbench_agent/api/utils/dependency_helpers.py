"""Helpers for dependency analysis result rows."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def find_dependency(
    dependencies: List[Dict[str, Any]],
    component_name: str,
    component_version: str,
) -> Optional[Dict[str, Any]]:
    """Return the first dependency row matching name and version."""
    version = str(component_version)
    for row in dependencies:
        if row.get("name") == component_name and str(row.get("version", "")) == version:
            return row
    return None


def parse_include_in_report(value: Any) -> bool:
    """Normalize Workbench include_in_report values to bool."""
    return value in (True, 1, "1")
