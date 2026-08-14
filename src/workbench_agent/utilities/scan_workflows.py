"""
Scan workflow orchestration utilities.

This module exposes a single public entry point:
- execute_scan_workflow(): called by all scan handlers after their
  setup phase (upload, git clone, or hash generation).
"""

import argparse
import logging
from typing import TYPE_CHECKING, Dict

from workbench_agent.api.utils.process_waiter import StatusResult
from workbench_agent.utilities.post_scan_summary import print_scan_summary
from workbench_agent.utilities.resolve_id_reuse import resolve_id_reuse

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


def create_scan_progress_callback(scan_code: str):
    """
    Terminal progress callback for KB scan wait loops.

    Prints detailed status on changes or periodic intervals, and dots
    between updates.
    """

    class ScanProgressTracker:
        def __init__(self):
            self.last_status = None
            self.last_state = None
            self.last_step = None

        def callback(self, status_result, attempt, max_tries):
            raw_data = status_result.raw_data
            current_state = raw_data.get("state", "")
            current_step = raw_data.get("current_step", "")
            percentage = raw_data.get("percentage_done", "")
            total_files = raw_data.get("total_files", 0)
            current_file = raw_data.get("current_file", 0)

            should_print = (
                attempt == 1
                or attempt % 10 == 0
                or status_result.status != self.last_status
                or current_state != self.last_state
                or current_step != self.last_step
            )

            if should_print:
                msg = f"\nScan '{scan_code}' status: {status_result.status}"
                if current_state:
                    msg += f" ({current_state})"
                if total_files and int(total_files) > 0:
                    msg += f" - File {current_file}/{total_files}"
                    if percentage:
                        msg += f" ({percentage})"
                elif percentage:
                    msg += f" - Progress: {percentage}"
                if current_step:
                    msg += f" - Step: {current_step}"
                msg += f". Attempt {attempt}/{max_tries}"
                print(msg, end="", flush=True)

                self.last_status = status_result.status
                self.last_state = current_state
                self.last_step = current_step
            else:
                print(".", end="", flush=True)

    tracker = ScanProgressTracker()
    return tracker.callback


def _wait_for_kb_scan(
    client: "WorkbenchClient",
    scan_code: str,
    params: argparse.Namespace,
) -> StatusResult:
    result = client.status_check.check_scan_status(
        scan_code,
        wait=True,
        wait_retry_count=params.scan_number_of_tries,
        wait_retry_interval=params.scan_wait_time,
        progress_callback=create_scan_progress_callback(scan_code),
    )
    # Progress updates are printed with end="" so dots can append;
    # finish the line before the next section starts.
    print()
    return result


def _determine_scans_to_run(
    params: argparse.Namespace,
) -> Dict[str, bool]:
    """
    Decide which scans to run based on CLI parameters.

    Returns a dict with keys ``run_kb_scan`` and
    ``run_dependency_analysis``.
    """
    run_dependency_analysis = getattr(params, "run_dependency_analysis", False)
    dependency_analysis_only = getattr(params, "dependency_analysis_only", False)
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


def _is_cancelled_scan_result(scan_result) -> bool:
    """
    Detect scans cancelled by a user, including API responses that report
    cancellation as FAILED with cancellation text in the payload.
    """
    if getattr(scan_result, "status", None) == "CANCELLED":
        return True

    raw_data = getattr(scan_result, "raw_data", {}) or {}
    cancellation_messages = [
        getattr(scan_result, "error_message", ""),
        raw_data.get("error", ""),
        raw_data.get("message", ""),
        raw_data.get("info", ""),
        raw_data.get("comment", ""),
    ]
    status_message = " ".join(str(message).lower() for message in cancellation_messages if message)
    return "cancel" in status_message


def execute_scan_workflow(
    client: "WorkbenchClient",
    params: argparse.Namespace,
    scan_code: str,
    durations: Dict[str, float],
    *,
    emit_summary: bool = True,
) -> bool:
    """
    Run scans, wait for completion, and print the summary.

    This is the single entry point that all scan handlers
    call after their respective setup phases.

    Handles DA-only mode, KB scan mode, ``--no-wait`` mode,
    ID reuse resolution, and result summary display.

    Set ``emit_summary=False`` when a caller (e.g. ``analyze``) will
    print its own combined summary after later steps.
    """
    scan_operations = _determine_scans_to_run(params)
    da_completed = False

    def _emit_summary(**kwargs) -> None:
        if emit_summary:
            print_scan_summary(**kwargs)

    if not scan_operations["run_kb_scan"] and scan_operations["run_dependency_analysis"]:
        print("Starting Dependency Analysis only " "(skipping KB scan)...")
        client.scan_operations.start_da_only(scan_code)

        if getattr(params, "no_wait", False):
            print("Dependency Analysis has been started.")
            print("\nExiting without waiting for completion " "(--no-wait mode).")
            print("You can check the status later using the " "'show-results' command.")
            scan_operations["da_completed"] = False
            _emit_summary(
                workbench=client,
                params=params,
                scan_code=scan_code,
                durations=durations,
                show_summary=False,
                scan_operations=scan_operations,
            )
            return True

        print("\nWaiting for Dependency Analysis to complete...")
        da_result = client.status_check.check_dependency_analysis_status(
            scan_code,
            wait=True,
            wait_retry_count=params.scan_number_of_tries,
            wait_retry_interval=params.scan_wait_time,
        )
        durations["dependency_analysis"] = da_result.duration or 0.0
        da_completed = True

    if scan_operations["run_kb_scan"]:
        print("Starting Scan Process...")

        id_reuse_type, id_reuse_specific_code = resolve_id_reuse(client, params)

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
            run_dependency_analysis=scan_operations["run_dependency_analysis"],
            replace_existing_identifications=getattr(
                params,
                "replace_existing_identifications",
                False,
            ),
            scan_failed_only=getattr(params, "scan_failed_only", False),
            full_file_only=getattr(params, "full_file_only", False),
            advanced_match_scoring=getattr(params, "advanced_match_scoring", True),
            match_filtering_threshold=getattr(params, "match_filtering_threshold", None),
            scan_host=getattr(params, "scan_host", None),
        )

        if getattr(params, "no_wait", False):
            print("\nKB Scan started successfully.")
            if scan_operations["run_dependency_analysis"]:
                print("Dependency Analysis will start when " "KB scan completes.")
            print("\nExiting without waiting for completion " "(--no-wait mode).")
            scan_operations["da_completed"] = False
            _emit_summary(
                workbench=client,
                params=params,
                scan_code=scan_code,
                durations=durations,
                show_summary=False,
                scan_operations=scan_operations,
            )
            return True

        process_types_to_wait = ["SCAN"]
        if scan_operations["run_dependency_analysis"]:
            process_types_to_wait.append("DEPENDENCY_ANALYSIS")

        process_list = ", ".join(process_types_to_wait)
        print(f"\nWaiting for {process_list} to complete...")

        try:
            kb_scan_result = _wait_for_kb_scan(client, scan_code, params)
            durations["kb_scan"] = kb_scan_result.duration or 0.0

            if kb_scan_result.is_failed and not _is_cancelled_scan_result(kb_scan_result):
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
                    autoid_file_copyrights=params.autoid_file_copyrights,
                    autoid_pending_ids=params.autoid_pending_ids,
                    delta_scan=params.delta_scan,
                    id_reuse_type=id_reuse_type,
                    id_reuse_specific_code=id_reuse_specific_code,
                    run_dependency_analysis=scan_operations["run_dependency_analysis"],
                    replace_existing_identifications=getattr(
                        params,
                        "replace_existing_identifications",
                        False,
                    ),
                    full_file_only=getattr(params, "full_file_only", False),
                    advanced_match_scoring=getattr(params, "advanced_match_scoring", True),
                    match_filtering_threshold=getattr(params, "match_filtering_threshold", None),
                    scan_host=getattr(params, "scan_host", None),
                )
                kb_scan_result = _wait_for_kb_scan(client, scan_code, params)
                durations["kb_scan"] += kb_scan_result.duration or 0.0

                if kb_scan_result.is_failed:
                    logger.error(
                        f"KB Scan '{scan_code}' failed again "
                        f"after retry (status="
                        f"{kb_scan_result.status})."
                    )
                    print(f"\nKB Scan still {kb_scan_result.status} " f"after retry.")

            if "DEPENDENCY_ANALYSIS" in process_types_to_wait:
                print("\nWaiting for Dependency Analysis " "to complete...")
                try:
                    da_result = client.status_check.check_dependency_analysis_status(
                        scan_code,
                        wait=True,
                        wait_retry_count=params.scan_number_of_tries,
                        wait_retry_interval=params.scan_wait_time,
                    )
                    durations["dependency_analysis"] = da_result.duration or 0.0
                    da_completed = True
                except Exception as e:
                    logger.warning(f"Error in dependency analysis: {e}")
                    print(f"\nWarning: Error waiting for " f"dependency analysis: {e}")
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

    scan_operations["da_completed"] = da_completed
    _emit_summary(
        workbench=client,
        params=params,
        scan_code=scan_code,
        durations=durations,
        show_summary=getattr(params, "show_summary", False),
        scan_operations=scan_operations,
    )

    return True
