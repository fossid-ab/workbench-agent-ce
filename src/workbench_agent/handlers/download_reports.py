# workbench_agent/handlers/download_reports.py

import argparse
import logging
import os
from typing import TYPE_CHECKING

from workbench_agent.api.exceptions import (
    ApiError,
    NetworkError,
    ProcessTimeoutError,
)
from workbench_agent.api.utils import report_definitions
from workbench_agent.exceptions import FileSystemError, ValidationError
from workbench_agent.utilities.error_handling import handler_error_wrapper
from workbench_agent.utilities.post_report_summary import print_report_summary
from workbench_agent.utilities.pre_flight_checks import (
    download_reports_pre_flight_check,
)

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


@handler_error_wrapper
def handle_download_reports(client: "WorkbenchClient", params: argparse.Namespace):
    """
    Handler for the 'download-reports' command.

    Download reports for a scan or project. Supports both synchronous and
    asynchronous reports with multiple configuration parameters.

    Args:
        client: The Workbench API client
        params: Command line parameters including:
            - report_scope: "scan" or "project"
            - report_type: Comma-separated list or "ALL"
            - report_save_path: Output directory
            - project_name: Project name (required for project scope; required
              for scan scope together with scan_name)
            - scan_name: Scan name (required for scan scope together with
              project_name)

    Returns:
        True if at least one report was successfully downloaded

    Raises:
        ValidationError: If parameters are invalid
        FileSystemError: If file operations fail
        ApiError: If API operations fail
    """
    print(f"\n--- Running {params.command.upper()} Command ---")

    report_types = client.reports.resolve_report_types(
        params.report_scope,
        params.report_type,
    )
    logger.debug(f"Resolved report types to download: {report_types}")

    # Create output directory if it doesn't exist
    output_dir = params.report_save_path
    if not os.path.exists(output_dir):
        print(f"Creating output directory: {output_dir}")
        os.makedirs(output_dir, exist_ok=True)

    # Resolve project, scan
    scope_name = params.scan_name if params.report_scope == "scan" else params.project_name
    print(
        f"\nResolving "
        f"{'scan' if params.report_scope == 'scan' else 'project'} "
        f"'{scope_name}'..."
    )

    project_code = None
    scan_code = None

    if params.report_scope == "scan":
        project_code, scan = client.resolver.find_project_and_scan(
            params.project_name,
            params.scan_name,
        )
        scan_code = scan.code
    elif params.report_scope == "project":
        project_code = client.resolver.find_project(params.project_name)

    # Check scan completion status for scan-scope reports
    if params.report_scope == "scan" and scan_code:
        download_reports_pre_flight_check(client, scan_code, params)

    # Generate and download reports based on scope
    scope_label = "project" if params.report_scope == "project" else "scan"
    print(f"\nGenerating and downloading {len(report_types)} " f"{scope_label} report(s)...")

    # Print the actual report types being downloaded
    for rt in sorted(report_types):
        print(f"- {rt}")

    # Type assertions for type checker (validated during resolution)
    if params.report_scope == "project":
        assert project_code is not None
    if params.report_scope == "scan":
        assert scan_code is not None

    # Track results for summary
    success_count = 0
    error_count = 0
    error_types = []

    # Process each report type sequentially
    max_tries = getattr(params, "scan_number_of_tries", 60)
    for report_type in sorted(report_types):
        try:
            print(f"\nGenerating {report_type} report...")

            name_component = (
                params.project_name if params.report_scope == "project" else params.scan_name
            )

            gen_kwargs: dict = {}
            if params.selection_type is not None:
                gen_kwargs["selection_type"] = params.selection_type
            if params.selection_view is not None:
                gen_kwargs["selection_view"] = params.selection_view
            if params.disclaimer is not None:
                gen_kwargs["disclaimer"] = params.disclaimer
            gen_kwargs["include_vex"] = params.include_vex

            # notices poll (not async)
            # async types poll for queue completion.
            needs_wait = (
                report_type in report_definitions.NOTICE_REPORT_TYPES
                or report_type in report_definitions.ASYNC_REPORT_TYPES
            )
            if needs_wait:
                print(f"Waiting for {report_type} report to finish generating...")

            client.reports.run_and_download_report(
                params.report_scope,
                report_type,
                output_dir,
                name_component,
                scan_code=scan_code,
                project_code=project_code,
                wait_retry_count=max_tries,
                wait_retry_interval=3,
                **gen_kwargs,
            )
            success_count += 1

        except ProcessTimeoutError as e:
            logger.error(f"Failed waiting for '{report_type}' report: {e}")
            error_count += 1
            error_types.append(report_type)

        except (
            ApiError,
            NetworkError,
            FileSystemError,
            ValidationError,
        ) as e:
            print(f"Error processing {report_type} report: " f"{getattr(e, 'message', str(e))}")
            logger.error(
                f"Failed to generate/download {report_type} report: {e}",
                exc_info=True,
            )
            error_count += 1
            error_types.append(report_type)

        except Exception as e:
            print(f"Error processing {report_type} report: " f"{getattr(e, 'message', str(e))}")
            logger.error(
                f"Unexpected failure for {report_type} report: {e}",
                exc_info=True,
            )
            error_count += 1
            error_types.append(report_type)

    # Show report summary (includes Workbench link for scan-scope reports)
    print_report_summary(
        client,
        params,
        report_types,
        success_count,
        error_count,
        error_types,
        scan_code=scan_code,
        show_summary=getattr(params, "show_summary", False),
    )

    # Return True if at least one report was successfully downloaded
    return success_count > 0
