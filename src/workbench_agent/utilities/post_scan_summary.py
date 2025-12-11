"""
Post-scan summary utilities for displaying scan operation results.

This module provides functions for formatting and displaying comprehensive
post-scan summaries including operation details, identification metrics,
components/licenses, and security risks.
"""

import argparse
import logging
from typing import TYPE_CHECKING, Dict, Optional, Union

from workbench_agent.utilities.scan_workflows import determine_scans_to_run

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


# --- Formatting and Summaries ---

def format_duration(duration_seconds: Optional[Union[int, float]]) -> str:
    """Formats a duration in seconds into a 'X minutes, Y seconds' string."""
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


def _print_workbench_link(workbench: "WorkbenchClient", scan_code: str):
    """Helper to display Workbench link."""
    try:
        links = workbench.results.get_workbench_links(scan_code)
        print("\n🔗 View this Scan in Workbench:\n")
        print(f"{links.scan['url']}")
    except Exception as e:
        logger.debug(f"Could not create link to Workbench: {e}")


def print_scan_summary(
    workbench: "WorkbenchClient",
    params: argparse.Namespace,
    scan_code: str,
    durations: Optional[Dict[str, float]] = None,
    show_summary: bool = False,
    scan_operations: Optional[Dict[str, bool]] = None,
):
    """
    Post-scan summary for scan operations (scan, scan-git, blind-scan).
    
    When show_summary is True, shows comprehensive operation details, identification
    metrics, components/licenses, and security risks. When False, only shows the
    Workbench link. The link is always displayed.
    
    Args:
        workbench: WorkbenchClient instance
        params: Command line parameters
        scan_code: Scan code to fetch results from
        durations: Dictionary containing operation durations in seconds
        show_summary: Whether to show the full summary (True) or just the link (False)
        scan_operations: Optional dict with 'run_kb_scan', 'run_dependency_analysis',
            and 'da_completed' keys. If not provided, will be determined from params.
            'da_completed' indicates whether dependency analysis actually completed
            successfully (not just requested).
    """
    from workbench_agent.api.exceptions import ApiError, NetworkError
    
    durations = durations or {}
    
    # Only show detailed summary if requested
    if not show_summary:
        _print_workbench_link(workbench, scan_code)
        return
    
    print("\n--- Post-Scan Summary ---")
    
    # Determine what scans were actually performed
    if scan_operations is None:
        scan_operations = determine_scans_to_run(params)
        # Default da_completed to False if not provided
        scan_operations.setdefault("da_completed", False)
    
    kb_scan_performed = scan_operations.get("run_kb_scan", False)
    da_requested = scan_operations.get("run_dependency_analysis", False)
    da_completed = scan_operations.get("da_completed", False)
    dependency_analysis_only = getattr(params, "dependency_analysis_only", False)
    
    # Fetch all required data (with error handling)
    scan_metrics = None
    kb_components = None
    kb_licenses = None
    dependencies = None
    policy_warnings = None
    vulnerabilities = None
    
    # Fetch scan metrics (only if KB scan was performed)
    if kb_scan_performed:
        try:
            scan_metrics = workbench.results.get_scan_metrics(scan_code)
        except (ApiError, NetworkError) as e:
            logger.debug(f"Could not fetch scan metrics: {e}")
    
    # Fetch dependencies (if DA was performed)
    if da_completed:
        try:
            dependencies = workbench.results.get_dependencies(scan_code)
        except (ApiError, NetworkError) as e:
            logger.debug(f"Could not fetch dependencies: {e}")
    
    # Fetch policy warnings
    try:
        policy_warnings = workbench.results.get_policy_warnings(scan_code)
    except (ApiError, NetworkError) as e:
        logger.debug(f"Could not fetch policy warnings: {e}")
    
    # Fetch vulnerabilities
    try:
        vulnerabilities = workbench.results.get_vulnerabilities(scan_code)
    except (ApiError, NetworkError) as e:
        logger.debug(f"Could not fetch vulnerabilities: {e}")
    
    # --- Requested Scan Operations ---
    print("\nScan Operation Summary:")
    
    # Only fetch KB data if KB scanning was performed
    if kb_scan_performed:
        # Fetch KB components
        try:
            kb_components = workbench.results.get_identified_components(scan_code)
        except (ApiError, NetworkError) as e:
            logger.debug(f"Could not fetch KB components: {e}")
        
        # Fetch KB licenses
        try:
            kb_licenses = workbench.results.get_unique_identified_licenses(scan_code)
        except (ApiError, NetworkError) as e:
            logger.debug(f"Could not fetch KB licenses: {e}")
    
    # Show "Skipped" if dependency-analysis-only was used, otherwise Yes/No
    if dependency_analysis_only or (not kb_scan_performed and da_requested):
        print("  - Signature Scanning: Skipped")
    else:
        kb_scan_status = "Yes" if kb_scan_performed else "No"
        if kb_scan_performed and durations.get("kb_scan"):
            kb_scan_status += f" ({format_duration(durations.get('kb_scan'))})"
        print(f"  - Signature Scanning: {kb_scan_status}")
    
    # Show sub-items only if KB scanning was performed
    if kb_scan_performed:
        # Identification Reuse details
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
        
        print(
            f"    - AutoID Pending IDs: {'Yes' if getattr(params, 'autoid_pending_ids', False) else 'No'}"
        )
        
        print(
            f"    - License Extraction: {'Yes' if getattr(params, 'autoid_file_licenses', False) else 'No'}"
        )
        print(
            f"    - Copyright Extraction: {'Yes' if getattr(params, 'autoid_file_copyrights', False) else 'No'}"
        )
    
    if da_completed:
        da_status = "Yes"
        if durations.get("dependency_analysis"):
            da_status += f" ({format_duration(durations.get('dependency_analysis'))})"
        print(f"  - Dependency Analysis: {da_status}")
    elif da_requested and not da_completed:
        print("  - Dependency Analysis: Requested but failed/incomplete")
    else:
        print("  - Dependency Analysis: Skipped")
    
    # --- Signature Scan (Identification) Summary ---
    # Only show this section if KB scanning was performed
    if kb_scan_performed:
        print("\nSignature Scan (Identification) Summary:")
        
        if scan_metrics:
            total_files = scan_metrics.get("total", "N/A")
            identified_files = scan_metrics.get("identified_files", "N/A")
            pending_files = scan_metrics.get("pending_identification", "N/A")
            no_match_files = scan_metrics.get("without_matches", "N/A")
            
            print(f"  - Total Files Scanned: {total_files}")
            print(f"  - Files with Identifications: {identified_files}")
            
            # Show components and licenses under Files with Identifications
            # Only show if there are files with identifications
            if identified_files != "N/A" and identified_files != 0 and (
                not isinstance(identified_files, str) or identified_files != "0"
            ):
                # Count components identified
                num_components = len(kb_components) if kb_components else 0
                print(f"    - Components Identified: {num_components}")
                
                # Count unique licenses in identified components
                unique_kb_licenses = set()
                if kb_licenses:
                    for lic in kb_licenses:
                        identifier = lic.get("identifier")
                        if identifier:
                            unique_kb_licenses.add(identifier)
                print(f"    - Unique Licenses Identified: {len(unique_kb_licenses)}")
            
            print(f"  - Files Pending ID: {pending_files}")
            print(f"  - Files with No Matches: {no_match_files}")
            
            # Check if signature scanning scanned 0 files
            if total_files == 0 or (isinstance(total_files, str) and total_files == "0"):
                print(
                    "\n  Note: There were no files to scan."
                )
        else:
            print("  - Files Scanned: N/A (could not fetch metrics)")
            print("  - Files Identified: N/A")
            print("  - Files Pending ID: N/A")
            print("  - Files with No Matches: N/A")
    
    # --- Dependency Analysis Summary ---
    # Only show this section if dependency analysis was performed
    if da_completed:
        print("\nDependency Analysis Summary:")
        
        # Count dependencies
        num_dependencies = len(dependencies) if dependencies else 0
        print(f"  - Dependencies Analyzed: {num_dependencies}")
        
        # Count unique licenses in dependencies
        unique_da_licenses = set()
        if dependencies:
            for dep in dependencies:
                license_id = dep.get("license_identifier")
                if license_id and license_id != "N/A":
                    unique_da_licenses.add(license_id)
        print(f"  - Unique Licenses in Dependencies: {len(unique_da_licenses)}")
    
    # --- Summary of Security and License Risk ---
    print("\nSecurity and License Risk:")
    
    # Policy warnings count
    if policy_warnings is not None:
        total_warnings = int(policy_warnings.get("policy_warnings_total", 0))
        files_with_warnings = int(
            policy_warnings.get("identified_files_with_warnings", 0)
        )
        deps_with_warnings = int(
            policy_warnings.get("dependencies_with_warnings", 0)
        )
        print(f"  - Policy Warnings: {total_warnings}")
        if total_warnings > 0:
            print(f"    - In Identified Files: {files_with_warnings}")
            print(f"    - In Dependencies: {deps_with_warnings}")
    else:
        print("  - Could not check Policy Warnings - does the Project have Policies set?")
    
    # Vulnerable components count
    if vulnerabilities:
        unique_vulnerable_components = set()
        for vuln in vulnerabilities:
            comp_name = vuln.get("component_name", "Unknown")
            comp_version = vuln.get("component_version", "Unknown")
            unique_vulnerable_components.add(f"{comp_name}:{comp_version}")
        num_vulnerable_components = len(unique_vulnerable_components)
        print(f"  - Components with CVEs: {num_vulnerable_components}")
    else:
        print("  - No CVEs found for Identified Components or Dependencies.")
    
    print("------------------------------------")
    
    # Always show Workbench link
    _print_workbench_link(workbench, scan_code)
