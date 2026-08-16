"""
Utilities for resolving ID reuse flags to scan API payload values.

Orchestrates the slim ``ResolverService`` with terminal output and
graceful degradation when reuse sources cannot be found.
"""

import argparse
import logging
from typing import TYPE_CHECKING, Optional, Tuple

from workbench_agent.api.exceptions import ScanNotFoundError

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


def resolve_id_reuse(
    client: "WorkbenchClient",
    params: argparse.Namespace,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Resolve ID reuse CLI flags to API payload values.

    Uses graceful degradation: if name resolution fails, logs a warning
    and returns ``(None, None)`` so the scan can continue without reuse.

    Returns:
        Tuple of ``(identification_reuse_type, specific_code)``
    """
    id_reuse_any = getattr(params, "reuse_any_identification", False)
    id_reuse_my = getattr(params, "reuse_my_identifications", False)
    id_reuse_project_name = getattr(params, "reuse_project_ids", None)
    id_reuse_scan_name = getattr(params, "reuse_scan_ids", None)
    current_project_name = params.project_name

    if id_reuse_any:
        logger.info("ID reuse: any")
        return "any", None

    if id_reuse_my:
        logger.info("ID reuse: only_me")
        return "only_me", None

    if id_reuse_project_name:
        return _resolve_project_id_reuse(client, id_reuse_project_name)

    if id_reuse_scan_name:
        return _resolve_scan_id_reuse(
            client,
            id_reuse_scan_name,
            current_project_name,
        )

    return None, None


def _resolve_project_id_reuse(
    client: "WorkbenchClient",
    project_name: str,
) -> Tuple[Optional[str], Optional[str]]:
    try:
        project_code = client.resolver.find_project(project_name)
        logger.info(f"ID reuse: project '{project_name}' → '{project_code}'")
        print(f"✓ Successfully validated ID reuse project '{project_name}'")
        return "specific_project", project_code
    except Exception as e:
        _handle_id_reuse_failure("project", project_name, e)
        return None, None


def _resolve_scan_id_reuse(
    client: "WorkbenchClient",
    scan_name: str,
    current_project_name: Optional[str],
) -> Tuple[Optional[str], Optional[str]]:
    try:
        if current_project_name:
            logger.debug(
                f"Looking for ID reuse source scan '{scan_name}' "
                f"(checking project '{current_project_name}' first, "
                f"then global if needed)"
            )
            try:
                resolved = client.resolver.find_scan(
                    scan_name,
                    project_name=current_project_name,
                )
                scan_code = resolved.code
                logger.info(
                    f"Found ID reuse source scan '{scan_name}' in current "
                    f"project '{current_project_name}'."
                )
            except ScanNotFoundError:
                print(
                    f"Scan '{scan_name}' not found in project "
                    f"'{current_project_name}'. "
                    f"Searching globally (may take a while)..."
                )
                logger.debug(
                    f"Scan '{scan_name}' not found in project "
                    f"'{current_project_name}', trying global search..."
                )
                resolved = client.resolver.find_scan_globally(scan_name)
                scan_code = resolved.code
                logger.info(
                    f"Found ID reuse source scan '{scan_name}' via global "
                    f"search (scan is in a different project)"
                )
        else:
            resolved = client.resolver.find_scan_globally(scan_name)
            scan_code = resolved.code

        logger.info(f"ID reuse: scan '{scan_name}' → '{scan_code}'")
        print(f"✓ Successfully validated ID reuse scan '{scan_name}'")
        return "specific_scan", scan_code
    except Exception as e:
        _handle_id_reuse_failure("scan", scan_name, e)
        return None, None


def _handle_id_reuse_failure(reuse_type: str, name: str, error: Exception) -> None:
    logger.warning(
        f"Could not find ID Reuse source: {reuse_type} '{name}' - "
        f"{type(error).__name__}: {error}. "
        "\nContinuing without ID reuse."
    )
