"""
Result utilities for fetching, displaying, and saving scan results.

This module provides functions for the show-results command to fetch,
display, and save scan results based on --show-* flags.
"""

import argparse
import json
import logging
import os
from typing import TYPE_CHECKING, Any, Dict

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

logger = logging.getLogger("workbench-agent")


def fetch_results(
    workbench: "WorkbenchClient",
    params: argparse.Namespace,
    scan_code: str,
) -> Dict[str, Any]:
    """
    Fetches requested scan results based on --show-* flags.

    This function delegates to ResultsService.fetch_results() which orchestrates
    fetching multiple result types. It handles errors gracefully, allowing partial
    results to be returned even if some fetches fail.

    Args:
        workbench: WorkbenchClient instance
        params: Command-line parameters with --show-* flags
        scan_code: Scan code to fetch results from

    Returns:
        Dictionary containing requested results:
        - dependency_analysis: List of dependencies (if requested)
        - kb_licenses: List of licenses (if requested)
        - kb_components: List of components (if requested)
        - scan_metrics: Metrics dictionary (if requested)
        - policy_warnings: Warnings dictionary (if requested)
        - vulnerabilities: List of vulnerabilities (if requested)
    """
    # Check if any results are requested
    should_fetch_licenses = getattr(params, "show_licenses", False)
    should_fetch_components = getattr(params, "show_components", False)
    should_fetch_dependencies = getattr(params, "show_dependencies", False)
    should_fetch_metrics = getattr(params, "show_scan_metrics", False)
    should_fetch_policy = getattr(params, "show_policy_warnings", False)
    should_fetch_vulnerabilities = getattr(
        params, "show_vulnerabilities", False
    )

    if not any(
        [
            should_fetch_licenses,
            should_fetch_components,
            should_fetch_dependencies,
            should_fetch_metrics,
            should_fetch_policy,
            should_fetch_vulnerabilities,
        ]
    ):
        print("\n=== No Results Requested ===")
        print(
            "Add flags like --show-licenses, --show-vulnerabilities, etc. to see results."
        )
        return {}

    # Delegate to ResultsService.fetch_results() which handles all the fetching logic
    return workbench.results.fetch_results(scan_code, params)


def display_results(
    collected_results: Dict[str, Any], params: argparse.Namespace
) -> bool:
    """
    Displays scan results based on the collected data and user preferences.
    """
    should_fetch_licenses = getattr(params, "show_licenses", False)
    should_fetch_components = getattr(params, "show_components", False)
    should_fetch_dependencies = getattr(params, "show_dependencies", False)
    should_fetch_metrics = getattr(params, "show_scan_metrics", False)
    should_fetch_policy = getattr(params, "show_policy_warnings", False)
    should_fetch_vulnerabilities = getattr(
        params, "show_vulnerabilities", False
    )

    da_results_data = collected_results.get("dependency_analysis")
    kb_licenses_data = collected_results.get("kb_licenses")
    kb_components_data = collected_results.get("kb_components")
    scan_metrics_data = collected_results.get("scan_metrics")
    policy_warnings_data = collected_results.get("policy_warnings")
    vulnerabilities_data = collected_results.get("vulnerabilities")

    print("\n--- Results Summary ---")
    displayed_something = False

    # Display Scan Metrics
    if should_fetch_metrics:
        print("\n=== Scan File Metrics ===")
        displayed_something = True
        if scan_metrics_data:
            total = scan_metrics_data.get("total", "N/A")
            pending = scan_metrics_data.get(
                "pending_identification", "N/A"
            )
            identified = scan_metrics_data.get("identified_files", "N/A")
            no_match = scan_metrics_data.get("without_matches", "N/A")
            print(f"  - Total Files Scanned: {total}")
            print(f"  - Files Pending Identification: {pending}")
            print(f"  - Files Identified: {identified}")
            print(f"  - Files Without Matches: {no_match}")
            print("-" * 25)
        else:
            print("Scan metrics data could not be fetched or was empty.")

    # Display Licenses
    if should_fetch_licenses:
        print("\n=== Identified Licenses ===")
        displayed_something = True
        kb_licenses_found = bool(kb_licenses_data)
        da_licenses_found = False

        if kb_licenses_found:
            print("Unique Licenses in Identified Components):")
            for lic in kb_licenses_data:
                identifier = lic.get("identifier", "N/A")
                name = lic.get("name", "N/A")
                print(f"  - {identifier}:{name}")
            print("-" * 25)

        if da_results_data:
            da_lic_names = sorted(
                list(
                    set(
                        comp.get("license_identifier", "N/A")
                        for comp in da_results_data
                        if comp.get("license_identifier")
                    )
                )
            )
            # Check if any valid licenses were found in DA data
            if da_lic_names and any(lic != "N/A" for lic in da_lic_names):
                print("Unique Licenses in Dependencies:")
                da_licenses_found = True
                for lic_name in da_lic_names:
                    if lic_name and lic_name != "N/A":
                        print(f"  - {lic_name}")
                print("-" * 25)

        if not kb_licenses_found and not da_licenses_found:
            print("No Licenses to report.")

    # Display KB Components
    if should_fetch_components:
        print("\n=== Identified Components ===")
        displayed_something = True
        if kb_components_data:
            print("From Signature Scanning:")
            for comp in kb_components_data:
                print(
                    f"  - {comp.get('name', 'N/A')} : {comp.get('version', 'N/A')}"
                )
            print("-" * 25)
        else:
            print("No KB Scan Components found to report.")

    # Display Dependencies
    if should_fetch_dependencies:
        print("\n=== Dependency Analysis Results ===")
        displayed_something = True
        if da_results_data:
            print(
                "Component, Version, Scope, and License of Dependencies:"
            )
            da_results_data.sort(
                key=lambda x: (
                    x.get("name", "").lower(),
                    x.get("version", ""),
                )
            )
            for comp in da_results_data:
                scopes_display = "N/A"
                scopes_str = comp.get("projects_and_scopes")
                if scopes_str:
                    try:
                        scopes_data = json.loads(scopes_str)
                        scopes_set = set()
                        for p_info in scopes_data.values():
                            if isinstance(p_info, dict):
                                scope = p_info.get("scope")
                                if scope:
                                    scopes_set.add(scope)
                        scopes_list = sorted(scopes_set)
                        if scopes_list:
                            scopes_display = ", ".join(scopes_list)
                    except (
                        json.JSONDecodeError,
                        AttributeError,
                        TypeError,
                    ) as scope_err:
                        logger.debug(
                            f"Could not parse scopes for DA component {comp.get('name')}: {scope_err}"
                        )
                print(
                    f"  - {comp.get('name', 'N/A')} : {comp.get('version', 'N/A')} "
                    f"(Scope: {scopes_display}, License: {comp.get('license_identifier', 'N/A')})"
                )
            print("-" * 25)
        else:
            print("No Components found through Dependency Analysis.")

    # Display Policy Warnings
    if should_fetch_policy:
        print("\n=== Policy Warnings Summary ===")
        displayed_something = True
        if policy_warnings_data is not None:
            # Check if we have real data with non-zero values
            total_warnings = int(
                policy_warnings_data.get("policy_warnings_total", 0)
            )
            files_with_warnings = int(
                policy_warnings_data.get(
                    "identified_files_with_warnings", 0
                )
            )
            deps_with_warnings = int(
                policy_warnings_data.get("dependencies_with_warnings", 0)
            )

            if total_warnings > 0:
                print(
                    f"There are {total_warnings} policy warnings: "
                    f"{files_with_warnings} in Identified Files, and "
                    f"{deps_with_warnings} in Dependencies."
                )
            else:
                print("No policy warnings found.")
        else:
            print(
                "Policy warnings counter data could not be fetched or was empty."
            )
        print("-" * 25)

    # Display Vulnerability Summary
    if should_fetch_vulnerabilities:
        print("\n=== Vulnerability Summary ===")
        displayed_something = True
        if vulnerabilities_data:
            num_cves = len(vulnerabilities_data)
            unique_components = set()
            severity_counts = {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "UNKNOWN": 0,
            }

            for vuln in vulnerabilities_data:
                comp_name = vuln.get("component_name", "Unknown")
                comp_version = vuln.get("component_version", "Unknown")
                unique_components.add(f"{comp_name}:{comp_version}")
                severity = vuln.get("severity", "UNKNOWN").upper()
                severity_counts[severity] = (
                    severity_counts.get(severity, 0) + 1
                )

            num_unique_components = len(unique_components)
            print(
                f"There are {num_cves} vulnerabilities affecting {num_unique_components} components."
            )
            print(
                f"By CVSS Score, "
                f"{severity_counts['CRITICAL']} are Critical, "
                f"{severity_counts['HIGH']} are High, "
                f"{severity_counts['MEDIUM']} are Medium, and "
                f"{severity_counts['LOW']} are Low."
            )

            if severity_counts["UNKNOWN"] > 0:
                print(f"  - Unknown:  {severity_counts['UNKNOWN']}")

        if vulnerabilities_data:
            print("\n=== Top Vulnerable Components ===")
            components_vulns = {}
            # Group vulnerabilities by component:version
            for vuln in vulnerabilities_data:
                comp_name = vuln.get("component_name", "UnknownComponent")
                comp_version = vuln.get(
                    "component_version", "UnknownVersion"
                )
                comp_key = f"{comp_name}:{comp_version}"
                if comp_key not in components_vulns:
                    components_vulns[comp_key] = []
                components_vulns[comp_key].append(vuln)

            # Sort components by the number of vulnerabilities (descending)
            sorted_components = sorted(
                components_vulns.items(),
                key=lambda item: len(item[1]),
                reverse=True,
            )

            # Define severity order for sorting vulnerabilities within each component
            severity_order = {
                "CRITICAL": 4,
                "HIGH": 3,
                "MEDIUM": 2,
                "LOW": 1,
                "UNKNOWN": 0,
            }

            for comp_key, vulns_list in sorted_components:
                print(f"\n{comp_key} - {len(vulns_list)} vulnerabilities")

                # Sort vulnerabilities within this component by severity
                sorted_vulns_list = sorted(
                    vulns_list,
                    key=lambda v: severity_order.get(
                        v.get("severity", "UNKNOWN").upper(), 0
                    ),
                    reverse=True,
                )

                # Display top 5 vulnerabilities for each component
                for vuln in sorted_vulns_list[:5]:
                    severity = vuln.get("severity", "UNKNOWN").upper()
                    cve = vuln.get("cve", "NO_CVE_ID")
                    print(f"  - [{severity}] {cve}")
                if len(sorted_vulns_list) > 5:
                    print(f"  ... and {len(sorted_vulns_list) - 5} more.")
        else:
            print("No vulnerabilities found.")
        print("-" * 25)

    if not displayed_something:
        print(
            "No results were successfully fetched or displayed for the specified flags."
        )
    print("------------------------------------")

    return displayed_something


def save_results_to_file(filepath: str, results: Dict):
    """Helper to save collected results dictionary to a JSON file."""
    output_dir = os.path.dirname(filepath) or "."
    try:
        os.makedirs(output_dir, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"Saved results to: {filepath}")
    except OSError as e:
        print(f"\nWarning: Failed to save results to {filepath}: {e}")


def fetch_display_save_results(
    workbench: "WorkbenchClient",
    params: argparse.Namespace,
    scan_code: str,
):
    """
    Orchestrates fetching, displaying, and saving scan results.

    Args:
        workbench: WorkbenchClient instance from apiv2
        params: Command line parameters
        scan_code: Scan code to fetch results for
    """
    any_results_requested = any(
        getattr(params, flag, False)
        for flag in [
            "show_licenses",
            "show_components",
            "show_dependencies",
            "show_scan_metrics",
            "show_policy_warnings",
            "show_vulnerabilities",
        ]
    )

    collected_results = fetch_results(workbench, params, scan_code)

    if any_results_requested:
        display_results(collected_results, params)

    save_path = getattr(params, "result_save_path", None)
    if save_path:
        if collected_results:
            print(f"\nSaving collected results to '{save_path}'...")
            save_results_to_file(save_path, collected_results)
        else:
            print(
                "\nNo results were successfully collected, skipping save."
            )

