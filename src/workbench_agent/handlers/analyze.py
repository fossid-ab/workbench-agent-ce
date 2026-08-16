"""
Handler for the ``analyze`` command.

Orchestrates FossID Toolbox DA pipeline mode (managed dependencies)
plus a KB scan of first-party sources (unmanaged code) into the same
Workbench Project/Scan. Toolbox decides which sources belong to the
analyzed unit and reports them in a sidecar; the agent only stages and
scans them.

By default first-party sources are uploaded (regular scan). Pass
``--blind-scan`` to hash with FossID Toolbox instead of uploading
source content.

Ecosystem-specific flags live in ``utilities.analyze.ecosystem``. The
handler itself is the same for every supported ``-e``.
"""

from __future__ import annotations

import argparse
import logging
import shutil
from typing import TYPE_CHECKING

from workbench_agent.api.exceptions import ProcessError, ProcessTimeoutError
from workbench_agent.exceptions import WorkbenchAgentError
from workbench_agent.handlers.blind_scan import (
    resolve_fossid_toolbox_path,
    validate_fossid_file,
)
from workbench_agent.utilities.analyze.ecosystem import (
    da_pipeline_kwargs,
    ecosystem_scope_label,
    validate_analyze_ecosystem,
)
from workbench_agent.utilities.analyze.first_party_sources import (
    load_first_party_sources,
    stage_sources,
)
from workbench_agent.utilities.analyze.summary import print_analysis_summary
from workbench_agent.utilities.error_handling import handler_error_wrapper
from workbench_agent.utilities.section import print_section
from workbench_agent.utilities.pre_flight_checks import scan_pre_flight_check
from workbench_agent.utilities.resolve_project_scan import (
    find_or_create_project_and_scan,
)
from workbench_agent.utilities.scan_workflows import execute_scan_workflow
from workbench_agent.utilities.toolbox_wrapper import (
    MINIMUM_TOOLBOX_DA_VERSION,
    ToolboxWrapper,
)
from workbench_agent.utilities.upload_data_prep import (
    cleanup_temp_path,
    prepare_scan_target,
)

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


def _force_kb_only(params: argparse.Namespace) -> None:
    """Managed deps come from Toolbox DA import, not Workbench DA."""
    params.run_dependency_analysis = False
    params.dependency_analysis_only = False


def _run_blind_scan_sources(
    client: "WorkbenchClient",
    params: argparse.Namespace,
    scan_code: str,
    scan_is_new: bool,
    staging_dir: str,
    durations: dict,
) -> bool:
    """Hash staged sources, upload, and run the KB scan (no Workbench DA)."""
    print_section("Blind-scanning first-party sources")
    toolbox_wrapper = ToolboxWrapper(
        toolbox_path=resolve_fossid_toolbox_path(
            getattr(params, "fossid_toolbox_path", None)
        ),
        timeout=str(getattr(params, "fossid_toolbox_timeout", 300)),
    )
    version = toolbox_wrapper.get_version()
    toolbox_wrapper.validate_toolbox_version(version)

    enable_lac = not getattr(params, "skip_lac_extraction", False)
    print("Hashing staged sources with Toolbox...")
    hash_file_path = toolbox_wrapper.generate_hashes(
        path=staging_dir,
        run_dependency_analysis=False,
        enable_lac_extraction=enable_lac,
    )
    try:
        validate_fossid_file(hash_file_path)
        print("Hash validation successful.")

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
        print_section("Running Scans")
        return execute_scan_workflow(
            client, params, scan_code, durations, emit_summary=False
        )
    finally:
        cleanup_temp_path(hash_file_path)


def _run_upload_sources(
    client: "WorkbenchClient",
    params: argparse.Namespace,
    scan_code: str,
    scan_is_new: bool,
    staging_dir: str,
    durations: dict,
) -> bool:
    """Upload staged sources and run the KB scan (no Workbench DA)."""
    if not scan_is_new:
        print("\nClearing existing scan content...")
        try:
            client.scan_content.remove_uploaded_content(scan_code, "")
            print("Successfully cleared existing scan content.")
        except Exception as e:
            logger.warning("Failed to clear existing scan content: %s", e)
            print("Continuing with upload...")

    print_section("Preparing Scan Target")
    with prepare_scan_target(staging_dir) as upload_path:
        print("Uploading archive to Workbench...")
        client.scan_content.upload_scan_target(scan_code, upload_path)
        print("✓ Upload complete")

    print("Extracting uploaded archive...")
    extraction_triggered = client.scan_content.extract_archives(
        scan_code=scan_code,
        recursively_extract_archives=getattr(
            params, "recursively_extract_archives", True
        ),
        jar_file_extraction=getattr(params, "jar_file_extraction", False),
    )

    durations.setdefault("kb_scan", 0.0)
    durations.setdefault("dependency_analysis", 0.0)
    durations.setdefault("extraction_duration", 0.0)

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
        print("✓ Archive extracted")
    else:
        print("No archives to extract")

    _force_kb_only(params)
    print_section("Running Scans")
    return execute_scan_workflow(
        client, params, scan_code, durations, emit_summary=False
    )


def _import_da_report(
    client: "WorkbenchClient",
    params: argparse.Namespace,
    scan_code: str,
    report_path: str,
) -> bool:
    """Upload analyzer-result.json and wait for import-only DA."""
    print("\nImporting dependency analysis results...")
    try:
        client.scan_content.upload_da_results(scan_code=scan_code, path=report_path)
        logger.debug("Dependency analysis results uploaded for '%s'", scan_code)
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
        logger.debug("Dependency analysis import initiated for '%s'", scan_code)
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
        print("Exiting without waiting for DA import completion (--no-wait).")
        return True

    try:
        print("Waiting for Dependency Analysis import to complete...")
        client.status_check.check_dependency_analysis_status(
            scan_code,
            wait=True,
            wait_retry_count=params.scan_number_of_tries,
            wait_retry_interval=3,
        )
        print("✓ Dependency analysis imported")
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

    Workflow:
    1. Run ``fossid-toolbox da --pipeline`` (with ``--emit-source-files``
       unless ``--dependency-analysis-only``) for managed dependencies
       and, by default, the list of first-party sources for the unit
    2. KB-scan those sources (upload by default, or ``--blind-scan``)
       unless ``--dependency-analysis-only``
    3. Import the Toolbox ``analyzer-result.json`` into the same scan
    """
    print_section(f"Running {params.command.upper()} Command")
    validate_analyze_ecosystem(params)

    path = params.path
    blind_scan = bool(getattr(params, "blind_scan", False))
    da_only = bool(getattr(params, "dependency_analysis_only", False))
    if getattr(params, "run_dependency_analysis", False):
        logger.debug(
            "--run-dependency-analysis is ignored on analyze; "
            "Toolbox DA results are always imported."
        )

    toolbox_wrapper = ToolboxWrapper(
        toolbox_path=resolve_fossid_toolbox_path(
            getattr(params, "fossid_toolbox_path", None)
        ),
        timeout=str(getattr(params, "fossid_toolbox_timeout", 300)),
    )
    version = toolbox_wrapper.get_version()
    toolbox_wrapper.validate_toolbox_version(
        version,
        minimum=MINIMUM_TOOLBOX_DA_VERSION,
        purpose="analyze",
    )

    pipeline_result = None
    staging_dir = None

    try:
        # --- 1. Managed deps + first-party source list via Toolbox DA ---
        pipeline_result = toolbox_wrapper.run_da_pipeline(
            input_path=path,
            emit_source_files=not da_only,
            fossid_conf_path=getattr(params, "fossid_conf_path", None),
            timeout=int(getattr(params, "da_timeout", 3600)),
            **da_pipeline_kwargs(params),
        )

        # --- 2. First-party KB scan (upload or blind) ---
        print_section("Project and Scan Checks")
        _, scan_code, scan_is_new = find_or_create_project_and_scan(client, params)

        if not scan_is_new:
            print_section("Pre-Flight Checks")
            scan_pre_flight_check(client, scan_code, params)
        else:
            logger.debug("Skipping idle checks - new scan is guaranteed to be idle")

        durations = {
            "kb_scan": 0.0,
            "dependency_analysis": 0.0,
            "extraction_duration": 0.0,
        }
        kb_performed = False
        skip_kb_message = None

        if da_only:
            skip_kb_message = (
                "--dependency-analysis-only: skipping first-party "
                "source discovery and KB scan."
            )
        else:
            sources = load_first_party_sources(pipeline_result.sources_path)
            if not sources:
                skip_kb_message = (
                    "No first-party source files found for "
                    f"{ecosystem_scope_label(params)}; skipping KB scan and "
                    "importing the dependency graph only."
                )
            else:
                staging_dir = stage_sources(path, sources)
                if blind_scan:
                    kb_ok = _run_blind_scan_sources(
                        client, params, scan_code, scan_is_new, staging_dir, durations
                    )
                else:
                    kb_ok = _run_upload_sources(
                        client, params, scan_code, scan_is_new, staging_dir, durations
                    )
                if not kb_ok:
                    return False
                kb_performed = True

        if skip_kb_message:
            print_section("Running Scans")
            print(skip_kb_message)

        # --- 3. Import Toolbox DA report into the same scan ---
        import_ok = _import_da_report(
            client,
            params,
            scan_code,
            pipeline_result.report_path,
        )
        if not import_ok:
            return False

        print_analysis_summary(
            client,
            params,
            scan_code,
            durations,
            kb_performed=kb_performed,
            da_imported=not getattr(params, "no_wait", False),
        )
        return True
    finally:
        if staging_dir:
            shutil.rmtree(staging_dir, ignore_errors=True)
        if pipeline_result:
            shutil.rmtree(pipeline_result.output_dir, ignore_errors=True)
