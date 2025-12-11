import argparse
import logging
from typing import TYPE_CHECKING, Dict, Optional, Set

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


def _print_workbench_link(workbench: "WorkbenchClient", scan_code: str):
    """Helper to display Workbench link."""
    try:
        links = workbench.results.get_workbench_links(scan_code)
        print("\n🔗 View this Scan in Workbench:\n")
        print(f"{links.scan['url']}")
    except Exception as e:
        logger.debug(f"Could not create link to Workbench: {e}")


def _format_report_parameters(
    workbench: "WorkbenchClient",
    report_type: str,
    params: argparse.Namespace,
) -> str:
    """
    Format report parameters based on report type capabilities.
    
    Shows all applicable parameters for the report type, including
    default values when parameters are not explicitly provided.
    
    Returns a formatted string showing which parameters were used.
    """
    capabilities = workbench.reports.REPORT_TYPE_CAPABILITIES.get(
        report_type, {}
    )
    
    param_parts = []
    
    # Selection Type - defaults to "include_all_licenses" if not specified
    if capabilities.get("supports_selection_type"):
        if params.selection_type:
            param_parts.append(f"Selection Type: {params.selection_type}")
        else:
            param_parts.append("Selection Type: include_all_licenses")
    
    # Selection View - defaults to "all" if not specified
    if capabilities.get("supports_selection_view"):
        if params.selection_view:
            param_parts.append(f"Selection View: {params.selection_view}")
        else:
            param_parts.append("Selection View: all")
    
    # VEX - defaults to true if not set (for supported report types)
    if capabilities.get("supports_vex"):
        include_vex = getattr(params, "include_vex", True)
        param_parts.append(f"VEX: {'Yes' if include_vex else 'No'}")
    
    # Disclaimer - no default, only show if provided
    if capabilities.get("supports_disclaimer"):
        if params.disclaimer:
            param_parts.append("Disclaimer: Yes")
        # Don't show disclaimer if not provided (it's truly optional)
    
    # Include Dep Det Info - defaults to false if not set (for Excel reports)
    if capabilities.get("supports_dep_det_info"):
        include_dep_det_info = getattr(params, "include_dep_det_info", False)
        param_parts.append(
            f"Dependency Details: {'Yes' if include_dep_det_info else 'No'}"
        )
    
    if param_parts:
        return " (" + ", ".join(param_parts) + ")"
    return ""


def print_report_summary(
    workbench: "WorkbenchClient",
    params: argparse.Namespace,
    report_types: Set[str],
    success_count: int,
    error_count: int,
    error_types: list,
    scan_code: Optional[str] = None,
    project_code: Optional[str] = None,
    durations: Optional[Dict[str, float]] = None,
    show_summary: bool = False,
):
    """
    Post-report summary for download-reports command.
    
    When show_summary is True, shows comprehensive report generation details
    including report types, parameters, and results. When False, only shows
    the Workbench link (for scan-scope reports). The link is always displayed
    for scan-scope reports.
    
    Args:
        workbench: WorkbenchClient instance
        params: Command line parameters
        report_types: Set of report types that were requested
        success_count: Number of successfully downloaded reports
        error_count: Number of failed reports
        error_types: List of report types that failed
        scan_code: Scan code (for scan-scope reports)
        project_code: Project code (for project-scope reports)
        durations: Dictionary containing operation durations in seconds
        show_summary: Whether to show the full summary (True) or just the link (False)
    """
    durations = durations or {}
    
    # Only show detailed summary if requested
    if not show_summary:
        # For scan-scope reports, show Workbench link
        if params.report_scope == "scan" and scan_code:
            _print_workbench_link(workbench, scan_code)
        return
    
    print("\n--- Post-Report Summary ---")
    
    # Report Scope
    scope_label = (
        "Project" if params.report_scope == "project" else "Scan"
    )
    scope_name = (
        params.project_name
        if params.report_scope == "project"
        else params.scan_name
    )
    print(f"\nReport Scope: {scope_label} '{scope_name}'")
    
    # Output Directory
    output_dir = getattr(params, "report_save_path", ".")
    print(f"Output Directory: {output_dir}")
    
    # Report Generation Summary
    print("\nReport Generation Summary:")
    print(f"  - Total Reports Requested: {len(report_types)}")
    print(f"  - Successfully Generated: {success_count}")
    if error_count > 0:
        print(f"  - Failed: {error_count}")
    
    # Report Types and Parameters
    print("\nReport Types Generated:")
    for report_type in sorted(report_types):
        status = "✓" if report_type not in error_types else "✗"
        param_str = _format_report_parameters(workbench, report_type, params)
        
        print(f"  {status} {report_type}{param_str}")
    
    # Show failed report types if any
    if error_types:
        print("\nFailed Report Types:")
        for error_type in error_types:
            print(f"  - {error_type}")
    
    print("------------------------------------")
    
    # Always show Workbench link for scan-scope reports
    if params.report_scope == "scan" and scan_code:
        _print_workbench_link(workbench, scan_code)

