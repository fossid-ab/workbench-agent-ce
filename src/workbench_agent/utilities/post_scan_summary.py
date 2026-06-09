"""Post-scan summary display for CE scan commands."""

import argparse
import logging
from typing import TYPE_CHECKING, Dict, Optional, Union

from workbench_agent.api.exceptions import ApiError, NetworkError
from workbench_agent.utilities.vulnerability_display import (
    print_vulnerable_component_count,
    summarize_vulnerability_rows,
)

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


def _print_workbench_link(workbench: "WorkbenchClient", scan_code: str) -> None:
    """Display a clickable Workbench link for *scan_code*."""
    try:
        links = workbench.links.get_workbench_links(scan_code)
        print("\n🔗 View this Scan in Workbench:\n")
        print(f"{links.scan['url']}")
    except Exception as e:
        logger.debug(f"Could not create link to Workbench: {e}")


def _format_duration(
    duration_seconds: Optional[Union[int, float]],
) -> str:
    """Format a duration in seconds into a human-readable string."""
    if duration_seconds is None:
        return "N/A"
    try:
        duration_seconds = round(float(duration_seconds))
    except (ValueError, TypeError):
        return "Invalid Duration"

    minutes, seconds = divmod(int(duration_seconds), 60)
    if minutes > 0 and seconds > 0:
        return f"{minutes} minutes, {seconds} seconds"
    if minutes > 0:
        return f"{minutes} minutes"
    if seconds == 1:
        return "1 second"
    return f"{seconds} seconds"


def print_scan_summary(
    workbench: "WorkbenchClient",
    params: argparse.Namespace,
    scan_code: str,
    durations: Optional[Dict[str, float]] = None,
    show_summary: bool = False,
    scan_operations: Optional[Dict[str, bool]] = None,
) -> None:
    """
    Post-scan summary for scan operations.

    When *show_summary* is ``True``, shows comprehensive operation
    details. When ``False``, only shows a link to Workbench.
    """
    durations = durations or {}

    if not show_summary:
        _print_workbench_link(workbench, scan_code)
        return

    if scan_operations is None:
        raise ValueError("scan_operations is required when show_summary=True")

    print("\n--- Post-Scan Summary ---")

    kb_scan_performed = scan_operations.get("run_kb_scan", False)
    da_requested = scan_operations.get("run_dependency_analysis", False)
    da_completed = scan_operations.get("da_completed", False)
    dependency_analysis_only = getattr(params, "dependency_analysis_only", False)

    scan_metrics = None
    kb_components = None
    kb_licenses = None
    dependencies = None
    policy_warnings = None
    vulnerabilities = None

    if kb_scan_performed:
        try:
            scan_metrics = workbench.identification.get_scan_metrics(scan_code)
        except (ApiError, NetworkError) as e:
            logger.debug(f"Could not fetch scan metrics: {e}")

    if da_completed:
        try:
            dependencies = workbench.dependencies.list_dependencies(scan_code)
        except (ApiError, NetworkError) as e:
            logger.debug(f"Could not fetch dependencies: {e}")

    try:
        policy_warnings = workbench.policy.get_policy_warnings(scan_code)
    except (ApiError, NetworkError) as e:
        logger.debug(f"Could not fetch policy warnings: {e}")

    try:
        vulnerabilities = workbench.vulnerability.list_scan_vulnerabilities(scan_code)
    except (ApiError, NetworkError) as e:
        logger.debug(f"Could not fetch vulnerabilities: {e}")

    vulnerability_summary = None
    if vulnerabilities:
        vulnerability_summary = summarize_vulnerability_rows(vulnerabilities)

    print("\nScan Operation Summary:")

    if kb_scan_performed:
        try:
            kb_components = workbench.identification.get_identified_components(scan_code)
        except (ApiError, NetworkError) as e:
            logger.debug(f"Could not fetch KB components: {e}")

        try:
            kb_licenses = workbench.identification.get_unique_identified_licenses(scan_code)
        except (ApiError, NetworkError) as e:
            logger.debug(f"Could not fetch KB licenses: {e}")

    if dependency_analysis_only or (not kb_scan_performed and da_requested):
        print("  - Signature Scanning: Skipped")
    else:
        kb_scan_status = "Yes" if kb_scan_performed else "No"
        if kb_scan_performed and durations.get("kb_scan"):
            kb_scan_status += f" ({_format_duration(durations.get('kb_scan'))})"
        print(f"  - Signature Scanning: {kb_scan_status}")

    if kb_scan_performed:
        id_reuse_enabled = any(
            [
                getattr(params, "reuse_any_identification", False),
                getattr(params, "reuse_my_identifications", False),
                getattr(params, "reuse_project_ids", None) is not None,
                getattr(params, "reuse_scan_ids", None) is not None,
            ]
        )

        if id_reuse_enabled:
            reuse_type = "N/A"
            if getattr(params, "reuse_any_identification", False):
                reuse_type = "Any Identification"
            elif getattr(params, "reuse_my_identifications", False):
                reuse_type = "My Identifications"
            elif getattr(params, "reuse_project_ids", None):
                reuse_type = f"From Project '{params.reuse_project_ids}'"
            elif getattr(params, "reuse_scan_ids", None):
                reuse_type = f"From Scan '{params.reuse_scan_ids}'"
            print(f"    - ID Reuse: {reuse_type}")
        else:
            print("    - ID Reuse: Disabled")

        autoid_pending_ids = "Yes" if getattr(params, "autoid_pending_ids", False) else "No"
        autoid_file_licenses = "Yes" if getattr(params, "autoid_file_licenses", False) else "No"
        autoid_file_copyrights = "Yes" if getattr(params, "autoid_file_copyrights", False) else "No"
        print(f"    - AutoID Pending IDs: {autoid_pending_ids}")
        print(f"    - License Extraction: {autoid_file_licenses}")
        print(f"    - Copyright Extraction: {autoid_file_copyrights}")

    if da_completed:
        da_status = "Yes"
        if durations.get("dependency_analysis"):
            da_status += f" ({_format_duration(durations.get('dependency_analysis'))})"
        print(f"  - Dependency Analysis: {da_status}")
    elif da_requested and not da_completed:
        print("  - Dependency Analysis: Requested but failed/incomplete")
    else:
        print("  - Dependency Analysis: Skipped")

    if kb_scan_performed:
        print("\nSignature Scan (Identification) Summary:")

        if scan_metrics:
            total_files = scan_metrics.get("total", "N/A")
            identified_files = scan_metrics.get("identified_files", "N/A")
            pending_files = scan_metrics.get("pending_identification", "N/A")
            no_match_files = scan_metrics.get("without_matches", "N/A")

            print(f"  - Total Files Scanned: {total_files}")
            print(f"  - Files with Identifications: {identified_files}")

            if (
                identified_files != "N/A"
                and identified_files != 0
                and (not isinstance(identified_files, str) or identified_files != "0")
            ):
                num_components = len(kb_components) if kb_components else 0
                print(f"    - Components Identified: {num_components}")

                unique_kb_licenses: set = set()
                if kb_licenses:
                    for lic in kb_licenses:
                        identifier = lic.get("identifier")
                        if identifier:
                            unique_kb_licenses.add(identifier)
                print(f"    - Unique Licenses Identified: " f"{len(unique_kb_licenses)}")

            print(f"  - Files Pending ID: {pending_files}")
            print(f"  - Files with No Matches: {no_match_files}")

            if total_files == 0 or (isinstance(total_files, str) and total_files == "0"):
                print("\n  Note: There were no files to scan.")
        else:
            print("  - Files Scanned: N/A (could not fetch metrics)")
            print("  - Files Identified: N/A")
            print("  - Files Pending ID: N/A")
            print("  - Files with No Matches: N/A")

    if da_completed:
        print("\nDependency Analysis Summary:")

        num_dependencies = len(dependencies) if dependencies else 0
        print(f"  - Dependencies Analyzed: {num_dependencies}")

        unique_da_licenses: set = set()
        if dependencies:
            for dep in dependencies:
                license_id = dep.get("license_identifier")
                if license_id and license_id != "N/A":
                    unique_da_licenses.add(license_id)
        print(f"  - Unique Licenses in Dependencies: " f"{len(unique_da_licenses)}")

    print("\nSecurity and License Risk:")

    if policy_warnings is not None:
        total_warnings = int(policy_warnings.get("policy_warnings_total", 0))
        files_with_warnings = int(policy_warnings.get("identified_files_with_warnings", 0))
        deps_with_warnings = int(policy_warnings.get("dependencies_with_warnings", 0))
        print(f"  - Policy Warnings: {total_warnings}")
        if total_warnings > 0:
            print(f"    - In Identified Files: {files_with_warnings}")
            print(f"    - In Dependencies: {deps_with_warnings}")
    else:
        print("  - Could not check Policy Warnings " "- does the Project have Policies set?")

    print_vulnerable_component_count(
        vulnerability_summary or {"total_cves": 0, "vulnerable_component_count": 0}
    )

    print("------------------------------------")

    _print_workbench_link(workbench, scan_code)
