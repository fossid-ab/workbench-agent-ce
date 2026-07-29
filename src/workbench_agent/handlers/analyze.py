"""
Handler for the ``analyze`` command.

Orchestrates FossID-DA pipeline mode (managed dependencies) plus a
KB scan of first-party Bazel sources (unmanaged code) into the same
Workbench Project/Scan. fda decides which sources belong to the target
and reports them in a sidecar; the agent only stages and scans them.

By default first-party sources are uploaded (regular scan). Pass
``--blind-scan`` to hash with FossID Toolbox instead of uploading
source content.

First pass supports Bazel only (``-e bazel``). Maven/Gradle will reuse
the same CLI surface later.
"""

from __future__ import annotations

import argparse
import logging
import shutil
from typing import TYPE_CHECKING

from workbench_agent.api.exceptions import ProcessError, ProcessTimeoutError
from workbench_agent.exceptions import ValidationError, WorkbenchAgentError
from workbench_agent.handlers.blind_scan import (
    resolve_fossid_toolbox_path,
    validate_fossid_file,
)
from workbench_agent.utilities.bazel_sources import (
    load_first_party_sources,
    stage_sources,
)
from workbench_agent.utilities.error_handling import handler_error_wrapper
from workbench_agent.utilities.fda_wrapper import resolve_fda_path, run_pipeline
from workbench_agent.utilities.post_import_summary import print_import_summary
from workbench_agent.utilities.pre_flight_checks import (
    blind_scan_pre_flight_check,
    import_da_pre_flight_check,
    scan_pre_flight_check,
)
from workbench_agent.utilities.resolve_project_scan import (
    find_or_create_project_and_scan,
)
from workbench_agent.utilities.scan_workflows import execute_scan_workflow
from workbench_agent.utilities.toolbox_wrapper import ToolboxWrapper
from workbench_agent.utilities.upload_data_prep import (
    cleanup_temp_path,
    prepare_scan_target,
)

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")

SUPPORTED_ECOSYSTEMS = {"bazel"}


def _ensure_bazel_params(params: argparse.Namespace) -> None:
    ecosystem = (getattr(params, "ecosystem", None) or "").strip().lower()
    if ecosystem not in SUPPORTED_ECOSYSTEMS:
        raise ValidationError(
            f"analyze currently supports only -e bazel "
            f"(got {ecosystem!r}). Maven/Gradle will be added later."
        )
    if not getattr(params, "bazel_target", None):
        raise ValidationError(
            "analyze with -e bazel requires --bazel-target "
            "(e.g. --bazel-target '//myapp:app')."
        )


def _force_kb_only(params: argparse.Namespace) -> None:
    """Managed deps come from fda import-da, not Workbench DA."""
    params.run_dependency_analysis = False
    params.dependency_analysis_only = False


def _run_blind_scan_sources(
    client: "WorkbenchClient",
    params: argparse.Namespace,
    scan_code: str,
    scan_is_new: bool,
    staging_dir: str,
) -> bool:
    """Hash staged sources, upload, and run the KB scan (no Workbench DA)."""
    print("\n--- Blind-scanning first-party sources ---")
    toolbox_wrapper = ToolboxWrapper(
        toolbox_path=resolve_fossid_toolbox_path(
            getattr(params, "fossid_toolbox_path", None)
        ),
        timeout=str(getattr(params, "fossid_toolbox_timeout", 300)),
    )
    version = toolbox_wrapper.get_version()
    print(f"Using {version}")
    toolbox_wrapper.validate_toolbox_version(version)

    enable_lac = not getattr(params, "skip_lac_extraction", False)
    print("\nHashing staged sources with Toolbox...")
    hash_file_path = toolbox_wrapper.generate_hashes(
        path=staging_dir,
        run_dependency_analysis=False,
        enable_lac_extraction=enable_lac,
    )
    try:
        validate_fossid_file(hash_file_path)
        print("Hash validation successful.")

        blind_scan_pre_flight_check(client, scan_code, scan_is_new, params)

        if not scan_is_new:
            print("\nClearing existing scan content...")
            try:
                client.scan_content.remove_uploaded_content(scan_code, "")
                print("Successfully cleared existing scan content.")
            except Exception as e:
                logger.warning("Failed to clear existing scan content: %s", e)
                print("Continuing with hash upload...")

        print("\nUploading hashes to Workbench...")
        client.scan_content.upload_scan_target(scan_code, hash_file_path)
        print("Hashes uploaded successfully!")

        _force_kb_only(params)
        durations = {"kb_scan": 0.0, "dependency_analysis": 0.0}
        return execute_scan_workflow(client, params, scan_code, durations)
    finally:
        cleanup_temp_path(hash_file_path)


def _run_upload_sources(
    client: "WorkbenchClient",
    params: argparse.Namespace,
    scan_code: str,
    scan_is_new: bool,
    staging_dir: str,
) -> bool:
    """Upload staged sources and run the KB scan (no Workbench DA)."""
    print("\n--- Uploading first-party sources ---")
    scan_pre_flight_check(client, scan_code, scan_is_new, params)

    if not scan_is_new:
        print("\nClearing existing scan content...")
        try:
            client.scan_content.remove_uploaded_content(scan_code, "")
            print("Successfully cleared existing scan content.")
        except Exception as e:
            logger.warning("Failed to clear existing scan content: %s", e)
            print("Continuing with upload...")

    print("\n--- Preparing Scan Target ---")
    with prepare_scan_target(staging_dir) as upload_path:
        print("\nUploading Code to Workbench...")
        client.scan_content.upload_scan_target(scan_code, upload_path)

    print("\nExtracting Uploaded Archive...")
    extraction_triggered = client.scan_content.extract_archives(
        scan_code=scan_code,
        recursively_extract_archives=getattr(
            params, "recursively_extract_archives", True
        ),
        jar_file_extraction=getattr(params, "jar_file_extraction", False),
    )

    durations: dict = {
        "kb_scan": 0.0,
        "dependency_analysis": 0.0,
        "extraction_duration": 0.0,
    }

    if extraction_triggered:
        extraction_result = client.status_check.check_extract_archives_status(
            scan_code,
            wait=True,
            wait_retry_count=params.scan_number_of_tries,
            wait_retry_interval=5,
        )
        durations["extraction_duration"] = extraction_result.duration or 0.0

        if extraction_result.status in {"FAILED", "CANCELLED"}:
            error_msg = (
                extraction_result.error_message
                or "Archive extraction failed. Scan can not continue."
            )
            raise ProcessError(
                f"Archive extraction failed for scan '{scan_code}': {error_msg}"
            )
    else:
        print("No archives to extract. Continuing with scan...")

    _force_kb_only(params)
    print("\n--- Running Scans ---")
    return execute_scan_workflow(client, params, scan_code, durations)


def _import_da_report(
    client: "WorkbenchClient",
    params: argparse.Namespace,
    scan_code: str,
    report_path: str,
) -> bool:
    """Upload analyzer-result.json and wait for import-only DA."""
    print("\n--- Importing Dependency Analysis results ---")
    # After a KB scan the scan is no longer "new"; always idle-check DA.
    import_da_pre_flight_check(client, scan_code, False, params)

    try:
        client.scan_content.upload_da_results(scan_code=scan_code, path=report_path)
        print("Dependency analysis results uploaded successfully!")
    except Exception as e:
        logger.error(
            "Failed to upload dependency analysis file for '%s': %s",
            scan_code,
            e,
            exc_info=True,
        )
        raise WorkbenchAgentError(
            f"Failed to upload dependency analysis file: {e}",
            details={"error": str(e)},
        ) from e

    try:
        client.scan_operations.start_da_import(scan_code=scan_code)
        print("Dependency analysis import initiated successfully.")
    except Exception as e:
        logger.error(
            "Failed to start dependency analysis import for '%s': %s",
            scan_code,
            e,
            exc_info=True,
        )
        raise WorkbenchAgentError(
            f"Failed to start dependency analysis import: {e}",
            details={"error": str(e)},
        ) from e

    if getattr(params, "no_wait", False):
        print("\nExiting without waiting for DA import completion (--no-wait).")
        print_import_summary(
            client, params, scan_code, False, show_summary=False
        )
        return True

    try:
        print("\nWaiting for Dependency Analysis import to complete...")
        client.status_check.check_dependency_analysis_status(
            scan_code,
            wait=True,
            wait_retry_count=params.scan_number_of_tries,
            wait_retry_interval=3,
        )
        print("Dependency Analysis import completed successfully.")
        print_import_summary(
            client,
            params,
            scan_code,
            True,
            show_summary=getattr(params, "show_summary", False),
        )
        return True
    except (ProcessTimeoutError, ProcessError):
        raise
    except Exception as e:
        raise WorkbenchAgentError(
            f"Error during dependency analysis import: {e}",
            details={"error": str(e)},
        ) from e


@handler_error_wrapper
def handle_analyze(client: "WorkbenchClient", params: argparse.Namespace) -> bool:
    """
    Handler for the ``analyze`` command.

    Workflow (Bazel):
    1. Run ``fda --pipeline --emit-source-files`` for managed dependencies
       plus the list of first-party sources feeding the target
    2. KB-scan those sources (upload by default, or ``--blind-scan``)
    3. Import the fda ``analyzer-result.json`` into the same scan
    """
    print(f"\n--- Running {params.command.upper()} Command ---")
    _ensure_bazel_params(params)

    input_path = params.input
    blind_scan = bool(getattr(params, "blind_scan", False))

    fda_bin = resolve_fda_path(getattr(params, "fda_path", None))

    pipeline_result = None
    staging_dir = None

    try:
        # --- 1. Managed deps + first-party source list via fda pipeline ---
        pipeline_result = run_pipeline(
            fda_bin=fda_bin,
            input_path=input_path,
            ecosystem=params.ecosystem,
            bazel_target=params.bazel_target,
            bazel_path=getattr(params, "bazel_path", None),
            bazel_mode=getattr(params, "bazel_mode", None),
            emit_source_files=True,
            fossid_conf_path=getattr(params, "fossid_conf_path", None),
            timeout=int(getattr(params, "fda_timeout", 3600)),
        )

        # --- 2. First-party KB scan (upload or blind) ---
        print("\n--- Project and Scan Checks ---")
        print("Checking target Project and Scan...")
        _, scan_code, scan_is_new = find_or_create_project_and_scan(client, params)

        sources = load_first_party_sources(pipeline_result.sources_path)
        if not sources:
            print(
                "\nNo first-party source files found for "
                f"{params.bazel_target}; skipping KB scan and importing "
                "the dependency graph only."
            )
        else:
            staging_dir = stage_sources(input_path, sources)
            if blind_scan:
                kb_ok = _run_blind_scan_sources(
                    client, params, scan_code, scan_is_new, staging_dir
                )
            else:
                kb_ok = _run_upload_sources(
                    client, params, scan_code, scan_is_new, staging_dir
                )
            if not kb_ok:
                return False

        # --- 3. Import fda report into the same scan ---
        return _import_da_report(
            client,
            params,
            scan_code,
            pipeline_result.report_path,
        )
    finally:
        if staging_dir:
            shutil.rmtree(staging_dir, ignore_errors=True)
        if pipeline_result:
            shutil.rmtree(pipeline_result.output_dir, ignore_errors=True)
