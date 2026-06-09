import argparse
import logging
from typing import TYPE_CHECKING

from workbench_agent.api.exceptions import ApiError, NetworkError
from workbench_agent.utilities.vulnerability_display import (
    print_vulnerable_component_count,
    summarize_vulnerability_rows,
)

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

    When show_summary is True, shows dependency analysis summary
    and security/license risk information. For SBOM imports, shows identified
    components and licenses. When False, only shows the Workbench link.

    Args:
        workbench: WorkbenchClient instance
        params: Command line parameters
        scan_code: Scan code to fetch results from
        import_completed: Whether the import completed successfully
        show_summary: Whether to show a summary (True) or just a link (False)
    """

    # Only show detailed summary if requested
    if not show_summary:
        # Just show the link and return
        try:
            links = workbench.links.get_workbench_links(scan_code)
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
            dependencies = workbench.dependencies.list_dependencies(scan_code)
        except (ApiError, NetworkError) as e:
            logger.debug(f"Could not fetch dependencies: {e}")

    # Fetch KB components and licenses for SBOM imports
    if is_sbom_import and import_completed:
        try:
            kb_components = workbench.identification.get_identified_components(scan_code)
        except (ApiError, NetworkError) as e:
            logger.debug(f"Could not fetch KB components: {e}")

        try:
            kb_licenses = workbench.identification.get_unique_identified_licenses(scan_code)
        except (ApiError, NetworkError) as e:
            logger.debug(f"Could not fetch KB licenses: {e}")

    # Fetch policy warnings
    try:
        policy_warnings = workbench.policy.get_policy_warnings(scan_code)
    except (ApiError, NetworkError) as e:
        logger.debug(f"Could not fetch policy warnings: {e}")

    # Fetch vulnerabilities
    try:
        vulnerabilities = workbench.vulnerability.list_scan_vulnerabilities(scan_code)
    except (ApiError, NetworkError) as e:
        logger.debug(f"Could not fetch vulnerabilities: {e}")

    vulnerability_summary = None
    if vulnerabilities:
        vulnerability_summary = summarize_vulnerability_rows(vulnerabilities)

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
        print(f"  - Unique Dependency Licenses: {len(unique_da_licenses)}")

    # --- Summary of Security and License Risk ---
    print("\nSecurity and License Risk:")

    # Policy warnings count
    if policy_warnings is not None:
        total_warnings = int(policy_warnings.get("policy_warnings_total", 0))
        files_with_warnings = int(policy_warnings.get("identified_files_with_warnings", 0))
        deps_with_warnings = int(policy_warnings.get("dependencies_with_warnings", 0))
        print(f"  - Policy Warnings: {total_warnings}")
        if total_warnings > 0:
            print(f"    - In Identified Files: {files_with_warnings}")
            print(f"    - In Dependencies: {deps_with_warnings}")
    else:
        print("  - Could not check Policy Warnings - are Policies set?")

    print_vulnerable_component_count(
        vulnerability_summary or {"total_cves": 0, "vulnerable_component_count": 0},
        empty_message=("  - No CVEs found for Components or Dependencies."),
    )

    print("------------------------------------")

    # Always show Workbench link
    try:
        links = workbench.links.get_workbench_links(scan_code)
        print("\n🔗 View this Scan in Workbench:\n")
        print(f"{links.scan['url']}")
    except Exception as e:
        logger.debug(f"Could not create link to Workbench: {e}")
        # Don't fail if link generation fails
