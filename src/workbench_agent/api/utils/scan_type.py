"""
Scan type classification and reuse compatibility rules.

Pure helpers over Workbench ``scans.get_information`` metadata. Returns
structured ``ScanReuseIssue`` values; callers format human messages.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ScanType(str, Enum):
    """How a scan was created or what type an operation requires."""

    UPLOAD = "upload"
    GIT = "git"
    SBOM = "sbom"


class ScanReuseIssueCode(str, Enum):
    """Machine-readable reuse incompatibility codes."""

    TYPE_MISMATCH = "type_mismatch"
    TYPE_FORBIDDEN = "type_forbidden"
    GIT_REPO_MISMATCH = "git_repo_mismatch"
    GIT_REF_TYPE_MISMATCH = "git_ref_type_mismatch"
    GIT_REF_VALUE_MISMATCH = "git_ref_value_mismatch"


@dataclass(frozen=True)
class GitTarget:
    """Git repository and ref for scan configuration or reuse checks."""

    url: Optional[str] = None
    ref_type: Optional[str] = None
    ref_value: Optional[str] = None


@dataclass(frozen=True)
class GitTargetComparison:
    """Existing vs requested git configuration."""

    existing: GitTarget
    requested: GitTarget


@dataclass(frozen=True)
class ScanReuseIssue:
    """Structured scan reuse incompatibility."""

    code: ScanReuseIssueCode
    actual: ScanType
    required: Optional[ScanType] = None
    forbidden: Optional[frozenset[ScanType]] = None
    git: Optional[GitTargetComparison] = None
    details: dict[str, str] = field(default_factory=dict)


def infer_scan_type(scan_info: dict) -> ScanType:
    """
    Derive scan type from Workbench ``scans.get_information`` metadata.
    """
    is_from_report = scan_info.get("is_from_report", "0")
    if is_from_report in ("1", 1, True, "true"):
        return ScanType.SBOM

    git_repo = scan_info.get("git_repo_url", scan_info.get("git_url"))
    if git_repo:
        return ScanType.GIT

    return ScanType.UPLOAD


def _git_target_from_scan_info(scan_info: dict) -> GitTarget:
    return GitTarget(
        url=scan_info.get("git_repo_url", scan_info.get("git_url")),
        ref_type=scan_info.get("git_ref_type"),
        ref_value=scan_info.get("git_branch"),
    )


def check_scan_reuse(
    scan_info: dict,
    *,
    required: Optional[ScanType] = None,
    forbidden: Optional[frozenset[ScanType]] = None,
    git_target: Optional[GitTarget] = None,
) -> Optional[ScanReuseIssue]:
    """
    Return a structured issue if scan cannot be reused under the constraints.

    Specify either ``required`` (exact type match, with git checks when GIT)
    or ``forbidden`` (actual type must not be in the set).
    """
    if required is None and forbidden is None:
        raise ValueError("check_scan_reuse requires required or forbidden")
    if required is not None and forbidden is not None:
        raise ValueError("check_scan_reuse accepts required or forbidden, not both")

    actual = infer_scan_type(scan_info)

    if forbidden is not None and actual in forbidden:
        return ScanReuseIssue(
            code=ScanReuseIssueCode.TYPE_FORBIDDEN,
            actual=actual,
            forbidden=forbidden,
        )

    if required is not None and actual != required:
        details: dict[str, str] = {}
        if actual == ScanType.GIT:
            git_repo = scan_info.get(
                "git_repo_url", scan_info.get("git_url")
            )
            if git_repo:
                details["git_repo"] = str(git_repo)
        return ScanReuseIssue(
            code=ScanReuseIssueCode.TYPE_MISMATCH,
            actual=actual,
            required=required,
            details=details,
        )

    if required == ScanType.GIT and actual == ScanType.GIT:
        requested = git_target or GitTarget()
        existing = _git_target_from_scan_info(scan_info)

        if existing.url != requested.url:
            return ScanReuseIssue(
                code=ScanReuseIssueCode.GIT_REPO_MISMATCH,
                actual=actual,
                required=required,
                git=GitTargetComparison(
                    existing=existing, requested=requested
                ),
                details={
                    "existing_repo": str(existing.url or ""),
                    "requested_repo": str(requested.url or ""),
                },
            )

        if (
            requested.ref_type
            and existing.ref_type
            and existing.ref_type.lower() != requested.ref_type.lower()
        ):
            return ScanReuseIssue(
                code=ScanReuseIssueCode.GIT_REF_TYPE_MISMATCH,
                actual=actual,
                required=required,
                git=GitTargetComparison(
                    existing=existing, requested=requested
                ),
                details={
                    "existing_ref_type": str(existing.ref_type),
                    "requested_ref_type": str(requested.ref_type),
                },
            )

        if existing.ref_value != requested.ref_value:
            return ScanReuseIssue(
                code=ScanReuseIssueCode.GIT_REF_VALUE_MISMATCH,
                actual=actual,
                required=required,
                git=GitTargetComparison(
                    existing=existing, requested=requested
                ),
                details={
                    "existing_ref_type": str(existing.ref_type or "ref"),
                    "existing_ref_value": str(existing.ref_value or ""),
                    "requested_ref_type": str(requested.ref_type or "ref"),
                    "requested_ref_value": str(requested.ref_value or ""),
                },
            )

    return None
