"""
Utilities for resolving project/scan targets before scan operations.

Orchestrates CE ``ResolverService`` with CLI parameter mapping,
compatibility checks, and terminal output.
"""

from __future__ import annotations

import argparse
import logging
from typing import TYPE_CHECKING, Optional, Tuple

from workbench_agent.api.exceptions import (
    ApiError,
    CompatibilityError,
    NetworkError,
    ProjectNotFoundError,
    ScanNotFoundError,
)
from workbench_agent.api.utils.scan_type import (
    GitTarget,
    ScanReuseIssue,
    ScanReuseIssueCode,
    ScanType,
    check_scan_reuse,
    infer_scan_type,
)
from workbench_agent.services.resolver_service import ResolverService
from workbench_agent.services.types import ResolvedTargets, target_label

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


def _strip(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    stripped = str(value).strip()
    return stripped or None


def resolve_project_and_scan(
    client: "WorkbenchClient",
    params: argparse.Namespace,
    *,
    allow_create: bool = True,
    import_from_report: bool = False,
    scan_required: bool = True,
) -> ResolvedTargets:
    """
    Resolve CLI project/scan targets to Workbench codes.

    Args:
        client: Workbench API client
        params: Parsed CLI namespace with target flags
        allow_create: When False, lookup-only (read handlers)
        import_from_report: Pass-through for SBOM import scan creation
        scan_required: When False, resolve project only (download-reports project scope)

    Returns:
        ResolvedTargets with project_code, scan_code, and creation flags
    """
    scan_data = _build_scan_create_data(params, import_from_report=import_from_report)
    resolver = ResolverService(client.projects, client.scans)

    targets = resolver.resolve_targets(
        project_name=_strip(getattr(params, "project_name", None)),
        project_code=_strip(getattr(params, "project_code", None)),
        scan_name=_strip(getattr(params, "scan_name", None)),
        scan_code=_strip(getattr(params, "scan_code", None)),
        scan_data=scan_data,
        allow_create=allow_create,
        scan_required=scan_required,
    )

    if allow_create and scan_required:
        _print_resolution_outcome(targets.project_created, targets.scan_is_new)
        if not targets.scan_is_new:
            print("Checking scan compatibility...")
            _ensure_scan_compatible(
                client,
                targets.scan_code,
                params,
                scan_info=targets.scan_info,
            )
            print("✓ Compatibility check passed")

    return targets


def find_or_create_project_and_scan(
    client: "WorkbenchClient",
    params: argparse.Namespace,
    *,
    import_from_report: bool = False,
) -> Tuple[str, str, bool]:
    """
    Find or create a project and scan for an Agent-CE write command.

    Backward-compatible wrapper returning ``(project_code, scan_code, scan_is_new)``.
    """
    targets = resolve_project_and_scan(
        client,
        params,
        allow_create=True,
        import_from_report=import_from_report,
    )
    return targets.project_code, targets.scan_code, targets.scan_is_new


def _git_target_from_params(params: argparse.Namespace) -> GitTarget:
    git_url = getattr(params, "git_url", None)
    git_branch = getattr(params, "git_branch", None)
    git_tag = getattr(params, "git_tag", None)
    git_commit = getattr(params, "git_commit", None)

    if git_tag:
        return GitTarget(url=git_url, ref_type="tag", ref_value=git_tag)
    if git_branch:
        return GitTarget(url=git_url, ref_type="branch", ref_value=git_branch)
    if git_commit:
        return GitTarget(url=git_url, ref_type="commit", ref_value=git_commit)
    return GitTarget(url=git_url)


def _reuse_constraints_from_params(
    params: argparse.Namespace,
) -> dict:
    """Map CE command params to ``check_scan_reuse`` keyword arguments."""
    command = params.command

    if command in ("scan", "blind-scan", "analyze"):
        # analyze KB-scans first-party sources (UPLOAD) then import-da.
        return {"required": ScanType.UPLOAD}
    if command == "scan-git":
        return {
            "required": ScanType.GIT,
            "git_target": _git_target_from_params(params),
        }
    if command == "import-sbom":
        return {"required": ScanType.SBOM}
    if command == "import-da":
        return {"forbidden": frozenset({ScanType.SBOM})}

    raise ValueError(f"Unknown command for scan reuse: {command!r}")


def format_reuse_issue(
    issue: ScanReuseIssue,
    scan_code: str,
    command: str,
) -> str:
    """Render a structured reuse issue as CE-specific terminal advice."""
    if issue.code == ScanReuseIssueCode.TYPE_FORBIDDEN:
        if issue.actual == ScanType.SBOM and command == "import-da":
            return (
                f"Scan '{scan_code}' was created for SBOM import and "
                f"cannot be reused for dependency analysis import."
            )

    if issue.code == ScanReuseIssueCode.TYPE_MISMATCH:
        if issue.required == ScanType.UPLOAD and issue.actual == ScanType.SBOM:
            return (
                f"Scan '{scan_code}' was created for SBOM import and "
                f"cannot be reused for code upload via --path."
            )
        if issue.required == ScanType.UPLOAD and issue.actual == ScanType.GIT:
            git_repo = issue.details.get("git_repo", "unknown")
            return (
                f"Scan '{scan_code}' was created for Git scanning "
                f"(Repo: {git_repo}) and cannot be reused for "
                f"code upload via --path."
            )
        if issue.required == ScanType.GIT and issue.actual == ScanType.SBOM:
            return (
                f"Scan '{scan_code}' was created for SBOM import and "
                f"cannot be reused for Git scanning."
            )
        if issue.required == ScanType.GIT and issue.actual == ScanType.UPLOAD:
            return (
                f"Scan '{scan_code}' was created for code upload "
                f"(using --path) and cannot be reused for Git scanning."
            )
        if issue.required == ScanType.SBOM:
            return (
                f"Scan '{scan_code}' was not created for SBOM import "
                f"and cannot be reused for SBOM import. Only scans "
                f"created with 'import-sbom' can be reused for SBOM "
                f"operations."
            )

    if issue.code == ScanReuseIssueCode.GIT_REPO_MISMATCH:
        return (
            f"Scan '{scan_code}' already exists but is configured "
            f"for a different Git repository "
            f"(Existing: '{issue.details.get('existing_repo')}', "
            f"Requested: '{issue.details.get('requested_repo')}'). "
            f"Please use a different --scan-name to create a new "
            f"scan."
        )

    if issue.code == ScanReuseIssueCode.GIT_REF_TYPE_MISMATCH:
        return (
            f"Scan '{scan_code}' exists with ref type "
            f"'{issue.details.get('existing_ref_type')}', but current command "
            f"specified ref type '{issue.details.get('requested_ref_type')}'. "
            f"Please use a different --scan-name or use a matching "
            f"ref type."
        )

    if issue.code == ScanReuseIssueCode.GIT_REF_VALUE_MISMATCH:
        return (
            f"Scan '{scan_code}' already exists for "
            f"{issue.details.get('existing_ref_type')} "
            f"'{issue.details.get('existing_ref_value')}', "
            f"but current command specified "
            f"{issue.details.get('requested_ref_type')} "
            f"'{issue.details.get('requested_ref_value')}'. "
            f"Please use a different --scan-name or use the "
            f"matching ref."
        )

    return f"Scan '{scan_code}' cannot be reused for command '{command}' " f"({issue.code.value})."


def _build_scan_create_data(
    params: argparse.Namespace,
    *,
    import_from_report: bool = False,
) -> dict:
    """Map CLI parameters to Workbench scan creation payload fields."""
    scan_data: dict = {}

    if hasattr(params, "description") and params.description:
        scan_data["description"] = params.description

    if hasattr(params, "git_url") and params.git_url:
        scan_data["git_repo_url"] = params.git_url

    if hasattr(params, "git_branch") and params.git_branch:
        scan_data["git_branch"] = params.git_branch
        scan_data["git_ref_type"] = "branch"
    elif hasattr(params, "git_tag") and params.git_tag:
        scan_data["git_branch"] = params.git_tag
        scan_data["git_ref_type"] = "tag"
    elif hasattr(params, "git_commit") and params.git_commit:
        scan_data["git_branch"] = params.git_commit
        scan_data["git_ref_type"] = "commit"

    if hasattr(params, "git_depth") and params.git_depth is not None:
        scan_data["git_depth"] = str(params.git_depth)

    if import_from_report:
        scan_data["import_from_report"] = "1"

    return scan_data


def _print_resolution_outcome(project_created: bool, scan_is_new: bool) -> None:
    """Print user-facing messages for find-or-create outcomes."""
    if project_created and scan_is_new:
        print("✓ Created new Project and Scan")
    elif scan_is_new:
        print("✓ Created New Scan in Existing Project")
    elif project_created:
        print("✓ Created New Project; Found Existing Scan")
    else:
        print("✓ Found existing Project and Scan")


def _ensure_scan_compatible(
    client: "WorkbenchClient",
    scan_code: str,
    params: argparse.Namespace,
    *,
    scan_info: Optional[dict] = None,
) -> None:
    """
    Validate an existing scan is compatible with the current command.

    Uses listing metadata from resolution when provided; otherwise falls
    back to ``scans.get_information``.
    """
    operation = params.command
    logger.debug(f"Verifying scan '{scan_code}' is compatible with operation " f"'{operation}'...")

    existing_scan_info = scan_info
    if existing_scan_info is None:
        try:
            existing_scan_info = client.scans.get_information(scan_code)
        except ScanNotFoundError:
            logger.warning(f"Scan '{scan_code}' not found during compatibility check.")
            return
        except (ApiError, NetworkError) as e:
            logger.warning(f"Error fetching scan information during compatibility " f"check: {e}")
            print(f"Warning: Could not verify scan compatibility due to API " f"error: {e}")
            return

    constraints = _reuse_constraints_from_params(params)
    issue = check_scan_reuse(existing_scan_info, **constraints)

    if issue:
        error_message = format_reuse_issue(issue, scan_code, operation)
        print("\nError: Incompatible scan usage detected.")
        logger.error(f"Compatibility check failed for scan '{scan_code}': " f"{error_message}")
        raise CompatibilityError(
            f"Incompatible usage for existing scan '{scan_code}': " f"{error_message}"
        )

    logger.info("Compatibility check passed! Proceeding...")
    scan_type = infer_scan_type(existing_scan_info)

    if operation == "scan-git" and scan_type == ScanType.GIT:
        git_repo = existing_scan_info.get("git_repo_url", existing_scan_info.get("git_url"))
        ref_type = existing_scan_info.get("git_ref_type")
        ref_value = existing_scan_info.get("git_branch")
        ref_display = f"{ref_type or 'ref'} '{ref_value}'"
        logger.debug(
            f"Reusing existing scan '{scan_code}' configured for Git "
            f"repository '{git_repo}' ({ref_display})."
        )
    elif operation in ("scan", "blind-scan") and scan_type == ScanType.UPLOAD:
        logger.debug(f"Reusing existing scan '{scan_code}' configured for code " f"upload.")
    elif operation == "import-da":
        logger.debug(f"Reusing existing scan '{scan_code}' for DA import.")
    elif operation == "import-sbom":
        logger.debug(
            f"Reusing existing scan '{scan_code}' for SBOM import "
            f"(report scan: {scan_type == ScanType.SBOM})."
        )


__all__ = [
    "find_or_create_project_and_scan",
    "format_reuse_issue",
    "resolve_project_and_scan",
    "target_label",
]
