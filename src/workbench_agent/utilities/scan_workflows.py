"""
Scan workflow orchestration and post-scan summary utilities.

This module exposes a single public entry point:
- execute_scan_workflow(): called by all scan handlers after their
  setup phase (upload, git clone, or hash generation).

Everything else is internal.
"""

import argparse
import logging
from typing import TYPE_CHECKING, Dict, Optional, Union

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


# ============================================================================
# Internal helpers
# ============================================================================


def _determine_scans_to_run(
    params: argparse.Namespace,
) -> Dict[str, bool]:
    """
    Decide which scans to run based on CLI parameters.

    Returns a dict with keys ``run_kb_scan`` and
    ``run_dependency_analysis``.
    """
    run_dependency_analysis = getattr(
        params, "run_dependency_analysis", False
    )
    dependency_analysis_only = getattr(
        params, "dependency_analysis_only", False
    )
    scan_operations: Dict[str, bool] = {
        "run_kb_scan": True,
        "run_dependency_analysis": False,
    }
    if run_dependency_analysis and dependency_analysis_only:
        logger.warning(
            "\nBoth --dependency-analysis-only and "
            "--run-dependency-analysis were specified. "
            "Using --dependency-analysis-only mode (skipping KB scan)."
        )
        scan_operations["run_kb_scan"] = False
        scan_operations["run_dependency_analysis"] = True
    elif dependency_analysis_only:
        scan_operations["run_kb_scan"] = False
        scan_operations["run_dependency_analysis"] = True
    elif run_dependency_analysis:
        scan_operations["run_kb_scan"] = True
        scan_operations["run_dependency_analysis"] = True
    logger.debug(f"Determined scan operations: {scan_operations}")
    return scan_operations


def _print_workbench_link(
    workbench: "WorkbenchClient", scan_code: str
):
    """Display a clickable Workbench link for *scan_code*."""
    try:
        links = workbench.results.get_workbench_links(scan_code)
        print("\n🔗 View this Scan in Workbench:\n")
        print(f"{links.scan['url']}")
    except Exception as e:
        logger.debug(f"Could not create link to Workbench: {e}")


def _format_duration(
    duration_seconds: Optional[Union[int, float]],
) -> str:
    """Formats a duration in seconds into a human-readable string."""
    if duration_seconds is None:
        return "N/A"
    try:
        duration_seconds = round(float(duration_seconds))
    except (ValueError, TypeError):
        return "Invalid Duration"

    minutes, seconds = divmod(int(duration_seconds), 60)
    if minutes > 0 and seconds > 0:
        return f"{minutes} minutes, {seconds} seconds"
    elif minutes > 0:
        return f"{minutes} minutes"
    elif seconds == 1:
        return "1 second"
    else:
        return f"{seconds} seconds"


# ============================================================================
# Post-scan summary
# ============================================================================


def _print_scan_summary(
    workbench: "WorkbenchClient",
    params: argparse.Namespace,
    scan_code: str,
    durations: Optional[Dict[str, float]] = None,
    show_summary: bool = False,
    scan_operations: Optional[Dict[str, bool]] = None,
):
    """
    Post-scan summary for scan operations.

    When *show_summary* is ``True``, shows comprehensive operation
    details. When ``False``, only shows a link to Workbench.
    """
    from workbench_agent.api.exceptions import ApiError, NetworkError

    durations = durations or {}

    if not show_summary:
        _print_workbench_link(workbench, scan_code)
        return

    print("\n--- Post-Scan Summary ---")

    if scan_operations is None:
        scan_operations = _determine_scans_to_run(params)
        scan_operations.setdefault("da_completed", False)

    kb_scan_performed = scan_operations.get("run_kb_scan", False)
    da_requested = scan_operations.get(
        "run_dependency_analysis", False
    )
    da_completed = scan_operations.get("da_completed", False)
    dependency_analysis_only = getattr(
        params, "dependency_analysis_only", False
    )

    scan_metrics = None
    kb_components = None
    kb_licenses = None
    dependencies = None
    policy_warnings = None
    vulnerabilities = None

    if kb_scan_performed:
        try:
            scan_metrics = workbench.results.get_scan_metrics(
                scan_code
            )
        except (ApiError, NetworkError) as e:
            logger.debug(f"Could not fetch scan metrics: {e}")

    if da_completed:
        try:
            dependencies = workbench.results.get_dependencies(
                scan_code
            )
        except (ApiError, NetworkError) as e:
            logger.debug(f"Could not fetch dependencies: {e}")

    try:
        policy_warnings = workbench.results.get_policy_warnings(
            scan_code
        )
    except (ApiError, NetworkError) as e:
        logger.debug(f"Could not fetch policy warnings: {e}")

    try:
        vulnerabilities = workbench.results.get_vulnerabilities(
            scan_code
        )
    except (ApiError, NetworkError) as e:
        logger.debug(f"Could not fetch vulnerabilities: {e}")

    # --- Requested Scan Operations ---
    print("\nScan Operation Summary:")

    if kb_scan_performed:
        try:
            kb_components = (
                workbench.results.get_identified_components(
                    scan_code
                )
            )
        except (ApiError, NetworkError) as e:
            logger.debug(f"Could not fetch KB components: {e}")

        try:
            kb_licenses = (
                workbench.results.get_unique_identified_licenses(
                    scan_code
                )
            )
        except (ApiError, NetworkError) as e:
            logger.debug(f"Could not fetch KB licenses: {e}")

    if dependency_analysis_only or (
        not kb_scan_performed and da_requested
    ):
        print("  - Signature Scanning: Skipped")
    else:
        kb_scan_status = "Yes" if kb_scan_performed else "No"
        if kb_scan_performed and durations.get("kb_scan"):
            kb_scan_status += (
                f" ({_format_duration(durations.get('kb_scan'))})"
            )
        print(f"  - Signature Scanning: {kb_scan_status}")

    if kb_scan_performed:
        id_reuse_enabled = any(
            [
                getattr(
                    params, "reuse_any_identification", False
                ),
                getattr(
                    params, "reuse_my_identifications", False
                ),
                getattr(params, "reuse_project_ids", None)
                is not None,
                getattr(params, "reuse_scan_ids", None)
                is not None,
            ]
        )

        if id_reuse_enabled:
            reuse_type = "N/A"
            if getattr(
                params, "reuse_any_identification", False
            ):
                reuse_type = "Any Identification"
            elif getattr(
                params, "reuse_my_identifications", False
            ):
                reuse_type = "My Identifications"
            elif getattr(params, "reuse_project_ids", None):
                reuse_type = (
                    f"From Project '{params.reuse_project_ids}'"
                )
            elif getattr(params, "reuse_scan_ids", None):
                reuse_type = (
                    f"From Scan '{params.reuse_scan_ids}'"
                )
            print(f"    - ID Reuse: {reuse_type}")
        else:
            print("    - ID Reuse: Disabled")

        autoid_pending_ids = (
            "Yes"
            if getattr(params, "autoid_pending_ids", False)
            else "No"
        )
        autoid_file_licenses = (
            "Yes"
            if getattr(params, "autoid_file_licenses", False)
            else "No"
        )
        autoid_file_copyrights = (
            "Yes"
            if getattr(params, "autoid_file_copyrights", False)
            else "No"
        )
        print(
            f"    - AutoID Pending IDs: "
            f"{autoid_pending_ids}"
        )
        print(
            f"    - License Extraction: "
            f"{autoid_file_licenses}"
        )
        print(
            f"    - Copyright Extraction: "
            f"{autoid_file_copyrights}"
        )

    if da_completed:
        da_status = "Yes"
        if durations.get("dependency_analysis"):
            da_status += (
                f" ({_format_duration(durations.get('dependency_analysis'))})"
            )
        print(f"  - Dependency Analysis: {da_status}")
    elif da_requested and not da_completed:
        print(
            "  - Dependency Analysis: "
            "Requested but failed/incomplete"
        )
    else:
        print("  - Dependency Analysis: Skipped")

    if kb_scan_performed:
        print("\nSignature Scan (Identification) Summary:")

        if scan_metrics:
            total_files = scan_metrics.get("total", "N/A")
            identified_files = scan_metrics.get(
                "identified_files", "N/A"
            )
            pending_files = scan_metrics.get(
                "pending_identification", "N/A"
            )
            no_match_files = scan_metrics.get(
                "without_matches", "N/A"
            )

            print(f"  - Total Files Scanned: {total_files}")
            print(
                f"  - Files with Identifications: "
                f"{identified_files}"
            )

            if (
                identified_files != "N/A"
                and identified_files != 0
                and (
                    not isinstance(identified_files, str)
                    or identified_files != "0"
                )
            ):
                num_components = (
                    len(kb_components) if kb_components else 0
                )
                print(
                    f"    - Components Identified: "
                    f"{num_components}"
                )

                unique_kb_licenses: set = set()
                if kb_licenses:
                    for lic in kb_licenses:
                        identifier = lic.get("identifier")
                        if identifier:
                            unique_kb_licenses.add(identifier)
                print(
                    f"    - Unique Licenses Identified: "
                    f"{len(unique_kb_licenses)}"
                )

            print(f"  - Files Pending ID: {pending_files}")
            print(
                f"  - Files with No Matches: {no_match_files}"
            )

            if total_files == 0 or (
                isinstance(total_files, str)
                and total_files == "0"
            ):
                print(
                    "\n  Note: There were no files to scan."
                )
        else:
            print(
                "  - Files Scanned: N/A "
                "(could not fetch metrics)"
            )
            print("  - Files Identified: N/A")
            print("  - Files Pending ID: N/A")
            print("  - Files with No Matches: N/A")

    if da_completed:
        print("\nDependency Analysis Summary:")

        num_dependencies = (
            len(dependencies) if dependencies else 0
        )
        print(
            f"  - Dependencies Analyzed: {num_dependencies}"
        )

        unique_da_licenses: set = set()
        if dependencies:
            for dep in dependencies:
                license_id = dep.get("license_identifier")
                if license_id and license_id != "N/A":
                    unique_da_licenses.add(license_id)
        print(
            f"  - Unique Licenses in Dependencies: "
            f"{len(unique_da_licenses)}"
        )

    print("\nSecurity and License Risk:")

    if policy_warnings is not None:
        total_warnings = int(
            policy_warnings.get("policy_warnings_total", 0)
        )
        files_with_warnings = int(
            policy_warnings.get(
                "identified_files_with_warnings", 0
            )
        )
        deps_with_warnings = int(
            policy_warnings.get(
                "dependencies_with_warnings", 0
            )
        )
        print(f"  - Policy Warnings: {total_warnings}")
        if total_warnings > 0:
            print(
                f"    - In Identified Files: "
                f"{files_with_warnings}"
            )
            print(
                f"    - In Dependencies: "
                f"{deps_with_warnings}"
            )
    else:
        print(
            "  - Could not check Policy Warnings "
            "- does the Project have Policies set?"
        )

    if vulnerabilities:
        unique_vulnerable_components: set = set()
        for vuln in vulnerabilities:
            comp_name = vuln.get("component_name", "Unknown")
            comp_version = vuln.get(
                "component_version", "Unknown"
            )
            unique_vulnerable_components.add(
                f"{comp_name}:{comp_version}"
            )
        num_vulnerable_components = len(
            unique_vulnerable_components
        )
        print(
            f"  - Components with CVEs: "
            f"{num_vulnerable_components}"
        )
    else:
        print(
            "  - No CVEs found for Identified "
            "Components or Dependencies."
        )

    print("------------------------------------")

    _print_workbench_link(workbench, scan_code)


# ============================================================================
# Main workflow entry point
# ============================================================================


def execute_scan_workflow(
    client: "WorkbenchClient",
    params: argparse.Namespace,
    scan_code: str,
    durations: Dict[str, float],
) -> bool:
    """
    Run scans, wait for completion, and print the summary.

    This is the single entry point that all scan handlers
    call after their respective setup phases.

    Handles DA-only mode, KB scan mode, ``--no-wait`` mode,
    ID reuse resolution, and result summary display.

    Args:
        client: The Workbench API client instance.
        params: Parsed CLI arguments.
        scan_code: The resolved scan code.
        durations: Mutable dict that will be updated with
            ``kb_scan`` and ``dependency_analysis`` timings.

    Returns:
        ``True`` when the workflow completes.  Errors propagate as
        exceptions for ``handler_error_wrapper`` to handle.
    """
    scan_operations = _determine_scans_to_run(params)
    da_completed = False

    # ------------------------------------------------------------------
    # DA-only mode
    # ------------------------------------------------------------------
    if (
        not scan_operations["run_kb_scan"]
        and scan_operations["run_dependency_analysis"]
    ):
        print(
            "\nStarting Dependency Analysis only "
            "(skipping KB scan)..."
        )
        client.scan_operations.start_da_only(scan_code)

        if getattr(params, "no_wait", False):
            print("Dependency Analysis has been started.")
            print(
                "\nExiting without waiting for completion "
                "(--no-wait mode)."
            )
            print(
                "You can check the status later using the "
                "'show-results' command."
            )
            scan_operations["da_completed"] = False
            _print_scan_summary(
                client,
                params,
                scan_code,
                durations,
                show_summary=False,
                scan_operations=scan_operations,
            )
            return True

        print("\nWaiting for Dependency Analysis to complete...")
        da_result = (
            client.status_check.check_dependency_analysis_status(
                scan_code,
                wait=True,
                wait_retry_count=params.scan_number_of_tries,
                wait_retry_interval=params.scan_wait_time,
            )
        )
        durations["dependency_analysis"] = (
            da_result.duration or 0.0
        )
        da_completed = True

    # ------------------------------------------------------------------
    # KB scan mode
    # ------------------------------------------------------------------
    if scan_operations["run_kb_scan"]:
        print("\nStarting Scan Process...")

        id_reuse_type, id_reuse_specific_code = (
            client.resolver.resolve_id_reuse(
                id_reuse_any=getattr(
                    params, "reuse_any_identification", False
                ),
                id_reuse_my=getattr(
                    params, "reuse_my_identifications", False
                ),
                id_reuse_project_name=getattr(
                    params, "reuse_project_ids", None
                ),
                id_reuse_scan_name=getattr(
                    params, "reuse_scan_ids", None
                ),
                current_project_name=params.project_name,
            )
        )

        client.scan_operations.start_scan(
            scan_code=scan_code,
            limit=params.limit,
            sensitivity=params.sensitivity,
            autoid_file_licenses=params.autoid_file_licenses,
            autoid_file_copyrights=params.autoid_file_copyrights,
            autoid_pending_ids=params.autoid_pending_ids,
            delta_scan=params.delta_scan,
            id_reuse_type=id_reuse_type,
            id_reuse_specific_code=id_reuse_specific_code,
            run_dependency_analysis=scan_operations[
                "run_dependency_analysis"
            ],
            replace_existing_identifications=getattr(
                params,
                "replace_existing_identifications",
                False,
            ),
            scan_failed_only=getattr(
                params, "scan_failed_only", False
            ),
            full_file_only=getattr(
                params, "full_file_only", False
            ),
            advanced_match_scoring=getattr(
                params, "advanced_match_scoring", True
            ),
            match_filtering_threshold=getattr(
                params, "match_filtering_threshold", None
            ),
            scan_host=getattr(params, "scan_host", None),
        )

        if getattr(params, "no_wait", False):
            print("\nKB Scan started successfully.")
            if scan_operations["run_dependency_analysis"]:
                print(
                    "Dependency Analysis will start when "
                    "KB scan completes."
                )
            print(
                "\nExiting without waiting for completion "
                "(--no-wait mode)."
            )
            scan_operations["da_completed"] = False
            _print_scan_summary(
                client,
                params,
                scan_code,
                durations,
                show_summary=False,
                scan_operations=scan_operations,
            )
            return True

        # Wait for completion
        process_types_to_wait = ["SCAN"]
        if scan_operations["run_dependency_analysis"]:
            process_types_to_wait.append("DEPENDENCY_ANALYSIS")

        process_list = ", ".join(process_types_to_wait)
        print(f"\nWaiting for {process_list} to complete...")

        try:
            kb_scan_result = (
                client.status_check.check_scan_status(
                    scan_code,
                    wait=True,
                    wait_retry_count=params.scan_number_of_tries,
                    wait_retry_interval=params.scan_wait_time,
                    should_track_files=True,
                )
            )
            durations["kb_scan"] = (
                kb_scan_result.duration or 0.0
            )

            if kb_scan_result.is_failed:
                logger.warning(
                    f"KB Scan '{scan_code}' ended in "
                    f"{kb_scan_result.status}. Attempting one "
                    f"automatic retry with scan_failed_only=True."
                )
                client.scan_operations.scan_failed_files(
                    scan_code=scan_code,
                    limit=params.limit,
                    sensitivity=params.sensitivity,
                    autoid_file_licenses=params.autoid_file_licenses,
                    autoid_file_copyrights=(
                        params.autoid_file_copyrights
                    ),
                    autoid_pending_ids=params.autoid_pending_ids,
                    delta_scan=params.delta_scan,
                    id_reuse_type=id_reuse_type,
                    id_reuse_specific_code=id_reuse_specific_code,
                    run_dependency_analysis=scan_operations[
                        "run_dependency_analysis"
                    ],
                    replace_existing_identifications=getattr(
                        params,
                        "replace_existing_identifications",
                        False,
                    ),
                    full_file_only=getattr(
                        params, "full_file_only", False
                    ),
                    advanced_match_scoring=getattr(
                        params, "advanced_match_scoring", True
                    ),
                    match_filtering_threshold=getattr(
                        params, "match_filtering_threshold", None
                    ),
                    scan_host=getattr(params, "scan_host", None),
                )
                kb_scan_result = (
                    client.status_check.check_scan_status(
                        scan_code,
                        wait=True,
                        wait_retry_count=params.scan_number_of_tries,
                        wait_retry_interval=params.scan_wait_time,
                        should_track_files=True,
                    )
                )
                durations["kb_scan"] += (
                    kb_scan_result.duration or 0.0
                )

                if kb_scan_result.is_failed:
                    logger.error(
                        f"KB Scan '{scan_code}' failed again "
                        f"after retry (status="
                        f"{kb_scan_result.status})."
                    )
                    print(
                        f"\nKB Scan still {kb_scan_result.status} "
                        f"after retry."
                    )

            if "DEPENDENCY_ANALYSIS" in process_types_to_wait:
                print(
                    "\nWaiting for Dependency Analysis "
                    "to complete..."
                )
                try:
                    da_result = (
                        client.status_check.check_dependency_analysis_status(
                            scan_code,
                            wait=True,
                            wait_retry_count=params.scan_number_of_tries,
                            wait_retry_interval=params.scan_wait_time,
                        )
                    )
                    durations["dependency_analysis"] = (
                        da_result.duration or 0.0
                    )
                    da_completed = True
                except Exception as e:
                    logger.warning(
                        f"Error in dependency analysis: {e}"
                    )
                    print(
                        f"\nWarning: Error waiting for "
                        f"dependency analysis: {e}"
                    )
                    da_completed = False
            else:
                da_completed = False

        except Exception as e:
            logger.error(
                f"Error waiting for processes: {e}",
                exc_info=True,
            )
            print(f"\nError: Process failed: {e}")
            da_completed = False

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    scan_operations["da_completed"] = da_completed
    _print_scan_summary(
        client,
        params,
        scan_code,
        durations,
        show_summary=getattr(params, "show_summary", False),
        scan_operations=scan_operations,
    )

    return True
