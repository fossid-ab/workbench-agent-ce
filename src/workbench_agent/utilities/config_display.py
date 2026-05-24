"""
Configuration display utility to render the configuration at startup.
"""

from typing import Any, Dict


# ===== Parameter groups =====
# Each frozenset names the params owned by a single section.

_AGENT_CONFIG_PARAMS = frozenset(
    {
        "log",
        "fossid_toolbox_path",
        "fossid_toolbox_timeout",
        "scan_number_of_tries",
        "scan_wait_time",
        "no_wait",
        "show_config",
        "show_summary",
    }
)

_RESULT_DISPLAY_PARAMS = frozenset(
    {
        "show_licenses",
        "show_components",
        "show_dependencies",
        "show_scan_metrics",
        "show_policy_warnings",
        "show_vulnerabilities",
        "result_save_path",
    }
)

_IDENTIFICATION_PARAMS = frozenset(
    {
        "autoid_file_copyrights",
        "autoid_file_licenses",
        "autoid_pending_ids",
        "reuse_any_identification",
        "reuse_my_identifications",
        "reuse_project_ids",
        "reuse_scan_ids",
        "replace_existing_identifications",
    }
)

_SCAN_OPERATION_PARAMS = frozenset(
    {
        "limit",
        "sensitivity",
        "full_file_only",
        "advanced_match_scoring",
        "match_filtering_threshold",
        "delta_scan",
        "run_dependency_analysis",
        "dependency_analysis_only",
        "scan_failed_only",
    }
)

_SCAN_TARGET_PARAMS = frozenset(
    {
        "project_name",
        "scan_name",
        "path",
        "incremental_upload",
        "jar_file_extraction",
        "recursively_extract_archives",
        "git_url",
        "git_branch",
        "git_commit",
        "git_tag",
        "git_depth",
    }
)

_REPORT_GENERATION_PARAMS = frozenset(
    {
        "report_scope",
        "report_type",
        "disclaimer",
        "report_save_path",
        "selection_type",
        "selection_view",
        "include_vex",
    }
)

# Params surfaced separately (connection block) or never displayed.
_SKIPPED_PARAMS = frozenset(
    {"command", "api_url", "api_user", "api_token"}
)

_KNOWN_PARAMS = (
    _AGENT_CONFIG_PARAMS
    | _RESULT_DISPLAY_PARAMS
    | _IDENTIFICATION_PARAMS
    | _SCAN_OPERATION_PARAMS
    | _SCAN_TARGET_PARAMS
    | _REPORT_GENERATION_PARAMS
)


# ===== Rendering primitives =====


def _user_params(params: Any) -> Dict[str, Any]:
    """
    Return public params with command/connection/private keys filtered out.

    Args:
        params: Parsed command line parameters

    Returns:
        Dict of param name -> value, excluding ``command``, the connection
        params, and any attribute starting with ``_``.
    """
    return {
        k: v
        for k, v in params.__dict__.items()
        if k not in _SKIPPED_PARAMS and not k.startswith("_")
    }


def _print_section(title: str, items: Dict[str, Any]) -> None:
    """
    Render a titled key=value section. No-op when ``items`` is empty.

    Args:
        title: Section title (printed on its own line, prefixed by a blank)
        items: Dict of param name -> value to render in sorted order
    """
    if not items:
        return
    print(f"\n{title}")
    for k, v in sorted(items.items()):
        print(f"  {k:<30} = {v}")


# ===== Per-group renderers =====


def _print_agent_config(params: Any) -> None:
    """Render the Agent Configuration section."""
    items = {
        k: v
        for k, v in _user_params(params).items()
        if k in _AGENT_CONFIG_PARAMS
    }
    _print_section("⚙️  Agent Configuration:", items)


def _print_scan_target(params: Any) -> None:
    """Render the Scan Target section."""
    items = {
        k: v
        for k, v in _user_params(params).items()
        if k in _SCAN_TARGET_PARAMS
    }
    _print_section("🎯 Scan Target:", items)


def _print_scan_operation_settings(params: Any) -> None:
    """Render the Scan Operation Settings section."""
    items = {
        k: v
        for k, v in _user_params(params).items()
        if k in _SCAN_OPERATION_PARAMS
    }
    _print_section("🔬 Scan Operation Settings:", items)


def _print_identification_settings(params: Any) -> None:
    """Render the Identification Settings section."""
    items = {
        k: v
        for k, v in _user_params(params).items()
        if k in _IDENTIFICATION_PARAMS
    }
    _print_section("🔍 Identification Settings:", items)


def _print_result_display(params: Any) -> None:
    """Render the Result Display section."""
    items = {
        k: v
        for k, v in _user_params(params).items()
        if k in _RESULT_DISPLAY_PARAMS
    }
    _print_section("📊 Result Display:", items)


def _print_report_generation(params: Any) -> None:
    """Render the Report Generation section."""
    items = {
        k: v
        for k, v in _user_params(params).items()
        if k in _REPORT_GENERATION_PARAMS
    }
    _print_section("📄 Report Generation:", items)


def _print_other_parameters(params: Any) -> None:
    """Render any params not claimed by a named group."""
    items = {
        k: v
        for k, v in _user_params(params).items()
        if k not in _KNOWN_PARAMS
    }
    _print_section("📋 Other Parameters:", items)


# ===== Connection info (custom layout) =====


def _print_connection_info(params: Any, workbench_api: Any) -> None:
    """
    Print Workbench connection information including server details.

    Args:
        params: Command line parameters with connection details
        workbench_api: WorkbenchClient instance for server info
    """
    print("\n🔗 Workbench Connection Info:")

    server_name = "Unknown"
    version = "Unknown"
    status = "⚠ Could not retrieve server info"

    try:
        config_data = workbench_api.internal.get_config()
        if config_data:
            server_name = config_data.get("server_name", "Unknown")
            version = config_data.get("version", "Unknown")
            status = "✓ Connected"
    except Exception:
        # Keep defaults if API call fails
        pass

    print(f"  Server Name                : {server_name}")
    print(f"  Workbench Version          : {version}")
    print(f"  API User                   : {params.api_user}")
    print(f"  Status                     : {status}")


# ===== Orchestration =====

def print_configuration(params: Any, workbench_api: Any) -> None:
    """
    Print configuration parameters in logical groups.

    Args:
        params: Parsed command line parameters
        workbench_api: WorkbenchClient instance for connection info
    """
    print("--- Workbench Agent Configuration ---")
    print(f"Command: {params.command}")

    _print_connection_info(params, workbench_api)
    _print_agent_config(params)
    _print_scan_target(params)
    _print_scan_operation_settings(params)
    _print_identification_settings(params)
    _print_result_display(params)
    _print_report_generation(params)
    _print_other_parameters(params)

    print("------------------------------------")
