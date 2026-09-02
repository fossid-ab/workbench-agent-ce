"""
Utilities for resolving ID reuse flags to scan API payload values.

Orchestrates CE ``ResolverService`` with terminal output and
graceful degradation when reuse sources cannot be found.
"""

from __future__ import annotations

import argparse
import logging
from typing import TYPE_CHECKING, Optional, Tuple

from workbench_agent.api.exceptions import ProjectNotFoundError, ScanNotFoundError
from workbench_agent.services.resolver_service import ResolverService

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


def resolve_id_reuse(
    client: "WorkbenchClient",
    params: argparse.Namespace,
    *,
    target_project_code: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Resolve ID reuse CLI flags to API payload values.

    Uses graceful degradation: if resolution fails, logs a warning
    and returns ``(None, None)`` so the scan can continue without reuse.

    Args:
        client: Workbench API client
        params: Parsed CLI namespace
        target_project_code: Resolved main-target project code for scan scoping

    Returns:
        Tuple of ``(identification_reuse_type, specific_code)``
    """
    id_reuse_any = getattr(params, "reuse_any_identification", False)
    id_reuse_my = getattr(params, "reuse_my_identifications", False)
    id_reuse_project_value = getattr(params, "reuse_project_ids", None)
    id_reuse_scan_value = getattr(params, "reuse_scan_ids", None)
    current_project_name = getattr(params, "project_name", None)
    current_project_code = target_project_code or getattr(params, "project_code", None)

    if id_reuse_any:
        logger.info("ID reuse: any")
        return "any", None

    if id_reuse_my:
        logger.info("ID reuse: only_me")
        return "only_me", None

    resolver = ResolverService(client.projects, client.scans)

    if id_reuse_project_value:
        return _resolve_project_id_reuse(resolver, id_reuse_project_value)

    if id_reuse_scan_value:
        return _resolve_scan_id_reuse(
            resolver,
            id_reuse_scan_value,
            current_project_name=current_project_name,
            current_project_code=current_project_code,
        )

    return None, None


def _resolve_project_id_reuse(
    resolver: ResolverService,
    value: str,
) -> Tuple[Optional[str], Optional[str]]:
    try:
        project_code = resolver.find_project(code=value)
        logger.info("ID reuse: resolved %r as project code %r", value, project_code)
        print(f"✓ Successfully validated ID reuse project '{value}'")
        return "specific_project", project_code
    except ProjectNotFoundError:
        pass
    try:
        project_code = resolver.find_project(name=value)
        logger.info("ID reuse: resolved %r as project name → %r", value, project_code)
        print(f"✓ Successfully validated ID reuse project '{value}'")
        return "specific_project", project_code
    except Exception as e:
        _handle_id_reuse_failure("project", value, e)
        return None, None


def _resolve_scan_id_reuse(
    resolver: ResolverService,
    value: str,
    *,
    current_project_name: Optional[str],
    current_project_code: Optional[str],
) -> Tuple[Optional[str], Optional[str]]:
    try:
        scan_code = resolver.find_scan(code=value).code
        logger.info("ID reuse: resolved %r as scan code %r", value, scan_code)
        print(f"✓ Successfully validated ID reuse scan '{value}'")
        return "specific_scan", scan_code
    except ScanNotFoundError:
        pass

    try:
        if current_project_code or current_project_name:
            log_project = current_project_name or current_project_code
            logger.debug(
                "Looking for ID reuse source scan %r "
                "(checking project %r first, then global if needed)",
                value,
                log_project,
            )
            try:
                resolved = resolver.find_scan(
                    name=value,
                    project_name=current_project_name,
                    project_code=current_project_code,
                )
                scan_code = resolved.code
                logger.info(
                    "Found ID reuse source scan %r in current project %r.",
                    value,
                    log_project,
                )
            except ScanNotFoundError:
                print(
                    f"Scan '{value}' not found in project "
                    f"'{log_project}'. "
                    f"Searching globally (may take a while)..."
                )
                logger.debug(
                    "Scan %r not found in project %r, trying global search...",
                    value,
                    log_project,
                )
                resolved = resolver.find_scan_globally(value)
                scan_code = resolved.code
                logger.info(
                    "Found ID reuse source scan %r via global "
                    "search (scan is in a different project)",
                )
        else:
            resolved = resolver.find_scan_globally(value)
            scan_code = resolved.code

        logger.info("ID reuse: scan %r → %r", value, scan_code)
        print(f"✓ Successfully validated ID reuse scan '{value}'")
        return "specific_scan", scan_code
    except Exception as e:
        _handle_id_reuse_failure("scan", value, e)
        return None, None


def _handle_id_reuse_failure(reuse_type: str, name: str, error: Exception) -> None:
    logger.warning(
        f"Could not find ID Reuse source: {reuse_type} '{name}' - "
        f"{type(error).__name__}: {error}. "
        "\nContinuing without ID reuse."
    )
