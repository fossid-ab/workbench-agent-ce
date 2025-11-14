"""
Configuration display utilities for the Workbench Agent.

This module provides functions for displaying startup configuration information
in a well-organized format, including agent settings, operation parameters,
result display options, and connection information.
"""

from typing import Any, Dict, Tuple


def _categorize_parameters(
    params: Any,
) -> Tuple[
    Dict[str, Any],
    Dict[str, Any],
    Dict[str, Any],
    Dict[str, Any],
    Dict[str, Any],
    Dict[str, Any],
    Dict[str, Any],
]:
    """
    Categorize parameters into related groups.

    Args:
        params: Parsed command line parameters

    Returns:
        Tuple of (agent_config, result_display, identification_settings,
        scan_operation_settings, scan_target, report_generation, other_params) dictionaries
    """
    # Parameters that will be skipped (handled separately in connection info)
    connection_params = {"api_url", "api_user", "api_token"}
    agent_config_params = {
        "log",
        "fossid_cli_path",
        "scan_number_of_tries",
        "scan_wait_time",
        "no_wait",
        "show_config",
    }
    result_display_params = {
        "show_licenses",
        "show_components",
        "show_dependencies",
        "show_scan_metrics",
        "show_policy_warnings",
        "show_vulnerabilities",
        "result_save_path",
    }
    identification_params = {
        "autoid_file_copyrights",
        "autoid_file_licenses",
        "autoid_pending_ids",
        "reuse_any_identification",
        "reuse_my_identifications",
        "reuse_project_ids",
        "reuse_scan_ids",
        "replace_existing_identifications",
    }
    scan_operation_params = {
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
    scan_target_params = {
        "project_name",
        "scan_name",
        "path",
        "jar_file_extraction",
        "recursively_extract_archives",
        "git_url",
        "git_branch",
        "git_commit",
        "git_tag",
        "git_depth",
    }
    report_generation_params = {
        "report_scope",
        "report_type",
        "disclaimer",
        "report_save_path",
        "selection_type",
        "selection_view",
        "include_vex",
    }

    # Separate parameters into categories
    agent_config = {}
    result_display = {}
    identification_settings = {}
    scan_operation_settings = {}
    scan_target = {}
    report_generation = {}
    other_params = {}

    for k, v in params.__dict__.items():
        # Skip command, connection params, and internal/private attributes
        if k == "command" or k in connection_params or k.startswith("_"):
            continue

        if k in agent_config_params:
            agent_config[k] = v
        elif k in result_display_params:
            result_display[k] = v
        elif k in identification_params:
            identification_settings[k] = v
        elif k in scan_operation_params:
            scan_operation_settings[k] = v
        elif k in scan_target_params:
            scan_target[k] = v
        elif k in report_generation_params:
            report_generation[k] = v
        else:
            other_params[k] = v

    return (
        agent_config,
        result_display,
        identification_settings,
        scan_operation_settings,
        scan_target,
        report_generation,
        other_params,
    )


def _print_section(title: str, params_dict: Dict[str, Any]) -> None:
    """
    Print a configuration section with a title and sorted parameters.

    Args:
        title: Section title to display
        params_dict: Dictionary of parameters to display
    """
    if params_dict:
        print(f"\n{title}")
        for k, v in sorted(params_dict.items()):
            # Skip internal/private attributes (those starting with _)
            if k.startswith("_"):
                continue
            print(f"  {k:<30} = {v}")


def _print_connection_info(params: Any, workbench_api: Any) -> None:
    """
    Print Workbench connection information including server details.

    Args:
        params: Command line parameters with connection details
        workbench_api: WorkbenchClient instance for server info
    """
    print("\n🔗 Workbench Connection Info:")

    # Get debug mode for token masking
    debug_mode = getattr(params, "log", "INFO").upper() == "DEBUG"

    # Display connection parameters
    print(f"  API URL                    : {params.api_url}")
    print(f"  API User                   : {params.api_user}")

    # Mask token unless in debug mode
    token_display = params.api_token if debug_mode else "****"
    print(f"  API Token                  : {token_display}")

    # Get and display server information
    try:
        config_data = workbench_api.internal.get_config()

        if config_data:
            server_name = config_data.get("server_name", "Unknown")
            print(f"  Server Name                : {server_name}")
            version = config_data.get("version", "Unknown")
            print(f"  Workbench Version          : {version}")
            print("  Status                     : ✓ Connected")
        else:
            print("  Server Name                : Unknown")
            print("  Workbench Version          : Unknown")
            print(
                "  Status                     : ⚠ Could not detect "
                "server info"
            )
    except Exception:
        print("  Server Name                : Unknown")
        print("  Workbench Version          : Unknown")
        print("  Status                     : ⚠ Could not fetch server info")


def _print_cli_parameters(params: Any) -> None:
    """
    Print CLI parameters organized into logical groups.

    Args:
        params: Parsed command line parameters
    """
    (
        agent_config,
        result_display,
        identification_settings,
        scan_operation_settings,
        scan_target,
        report_generation,
        other_params,
    ) = _categorize_parameters(params)

    # Print agent configuration
    _print_section("⚙️  Agent Configuration:", agent_config)

    # Print scan target settings
    _print_section("🎯 Scan Target:", scan_target)

    # Print scan operation settings
    _print_section("🔬 Scan Operation Settings:", scan_operation_settings)

    # Print identification settings
    _print_section("🔍 Identification Settings:", identification_settings)

    # Print result display settings
    _print_section("📊 Result Display:", result_display)

    # Print report generation settings
    _print_section("📄 Report Generation:", report_generation)

    # Print other parameters
    _print_section("📋 Other Parameters:", other_params)


def print_configuration(params: Any, workbench_api: Any) -> None:
    """
    Print configuration parameters in logical groups.

    Args:
        params: Parsed command line parameters
        workbench_api: WorkbenchClient instance for
                      connection info.
    """
    print("--- Workbench Agent Configuration ---")
    print(f"Command: {params.command}")

    # Print CLI parameters
    _print_cli_parameters(params)

    # Print Workbench connection information
    _print_connection_info(params, workbench_api)

    print("------------------------------------")
