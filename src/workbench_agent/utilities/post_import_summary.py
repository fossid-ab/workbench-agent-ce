import argparse
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


def print_import_summary(
    workbench: "WorkbenchClient",
    params: argparse.Namespace,
    scan_code: str,
    import_completed: bool,
    show_summary: bool = False,
):
    """
    Post-import summary for import operations (import-da, import-sbom).
    
    When show_summary is True, shows comprehensive dependency analysis summary
    and security/license risk information. For SBOM imports, also shows identified
    components and licenses. When False, only shows the Workbench link.
    The link is always displayed.
    
    Args:
        workbench: WorkbenchClient instance
        params: Command line parameters
        scan_code: Scan code to fetch results from
        import_completed: Whether the import completed successfully
        show_summary: Whether to show the full summary (True) or just the link (False)
    """
    from workbench_agent.api.exceptions import ApiError, NetworkError
    
    # Only show detailed summary if requested
    if not show_summary:
        # Just show the link and return
        try:
            links = workbench.results.get_workbench_links(scan_code)
            print("\n🔗 View this Scan in Workbench:\n")
            print(f"{links.scan['url']}")
        except Exception as e:
            logger.debug(f"Could not create link to Workbench: {e}")
        return
    
    print("\n--- Post-Import Summary ---")
    
    # Determine import type
    is_sbom_import = getattr(params, "command", None) == "import-sbom"
    
    # Fetch all required data (with error handling)
    dependencies = None
    kb_components = None
    kb_licenses = None
    policy_warnings = None
    vulnerabilities = None
    
    # Fetch dependencies (if import was completed)
    if import_completed:
        try:
            dependencies = workbench.results.get_dependencies(scan_code)
        except (ApiError, NetworkError) as e:
            logger.debug(f"Could not fetch dependencies: {e}")
    
    # Fetch KB components and licenses for SBOM imports
    if is_sbom_import and import_completed:
        try:
            kb_components = workbench.results.get_identified_components(scan_code)
        except (ApiError, NetworkError) as e:
            logger.debug(f"Could not fetch KB components: {e}")
        
        try:
            kb_licenses = workbench.results.get_unique_identified_licenses(scan_code)
        except (ApiError, NetworkError) as e:
            logger.debug(f"Could not fetch KB licenses: {e}")
    
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
    
    # --- Identified Components Summary (SBOM imports only) ---
    if is_sbom_import and import_completed:
        print("\nImported Identifications:")
        
        # Count components identified
        num_components = len(kb_components) if kb_components else 0
        print(f"  - Component Identifications Imported: {num_components}")
        
        # Count unique licenses in identified components
        unique_kb_licenses = set()
        if kb_licenses:
            for lic in kb_licenses:
                identifier = lic.get("identifier")
                if identifier:
                    unique_kb_licenses.add(identifier)
        print(f"  - Unique Licenses Imported: {len(unique_kb_licenses)}")
    
    # --- Dependency Analysis Summary ---
    # Only show this section if import was completed
    if import_completed:
        print("\nDependencies Imported:")
        
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
        print("  - No CVEs found for Components or Dependencies.")
    
    print("------------------------------------")
    
    # Always show Workbench link
    try:
        links = workbench.results.get_workbench_links(scan_code)
        print("\n🔗 View this Scan in Workbench:\n")
        print(f"{links.scan['url']}")
    except Exception as e:
        logger.debug(f"Could not create link to Workbench: {e}")
        # Don't fail if link generation fails

