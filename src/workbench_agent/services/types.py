"""CE dataclasses for target resolution outcomes."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Literal, Optional


@dataclass(frozen=True)
class ResolvedScan:
    """Scan resolved by name or code, including listing metadata for reuse checks."""

    code: str
    id: int
    info: dict


@dataclass(frozen=True)
class ResolvedTargets:
    """Outcome of resolving CLI project/scan targets to Workbench codes."""

    project_code: str
    scan_code: str
    project_created: bool
    scan_is_new: bool
    scan_info: Optional[dict] = None


def target_label(
    params: argparse.Namespace,
    entity: Literal["project", "scan"],
) -> str:
    """Human-readable label for terminal output (name preferred over code)."""
    if entity == "project":
        name = getattr(params, "project_name", None)
        code = getattr(params, "project_code", None)
    else:
        name = getattr(params, "scan_name", None)
        code = getattr(params, "scan_code", None)
    if name and str(name).strip():
        return str(name).strip()
    if code and str(code).strip():
        return str(code).strip()
    return "?"
