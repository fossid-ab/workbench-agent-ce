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

from workbench_agent.api.exceptions import ApiError, NetworkError
from workbench_agent.utilities.vulnerability_display import (
    print_vulnerability_results,
)

logger = logging.getLogger("workbench-agent")


def fetch_results(
    workbench: "WorkbenchClient",
    params: argparse.Namespace,
    scan_code: str,
) -> Dict[str, Any]:
    """
    Fetches requested scan results based on --show-* flags.

    Orchestrates domain services on the Workbench client. Partial
    results are returned even if some fetches fail.

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
    should_fetch_vulnerabilities = getattr(params, "show_vulnerabilities", False)

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
        print("Add flags like --show-licenses, --show-vulnerabilities, etc. to see results.")
        return {}

    logger.debug(
        "Fetching requested results for scan '%s' based on --show-* flags",
        scan_code,
    )
    collected_results: Dict[str, Any] = {}

    if should_fetch_licenses or should_fetch_dependencies:
        try:
            da_results = workbench.dependencies.list_dependencies(scan_code)
            if da_results:
                collected_results["dependency_analysis"] = da_results
                logger.info(
                    "Fetched %d dependency analysis results",
                    len(da_results),
                )
        except (ApiError, NetworkError) as e:
            logger.warning("Could not fetch Dependency Analysis results: %s", e)
            print(f"Warning: Could not fetch Dependency Analysis results: {e}")

    if should_fetch_licenses:
        try:
            kb_licenses = workbench.identification.get_unique_identified_licenses(scan_code)
            if kb_licenses:
                collected_results["kb_licenses"] = sorted(
                    kb_licenses,
                    key=lambda x: x.get("identifier", "").lower(),
                )
                logger.info("Fetched %d KB licenses", len(kb_licenses))
        except (ApiError, NetworkError) as e:
            logger.warning("Could not fetch KB Identified Licenses: %s", e)
            print(f"Warning: Could not fetch KB Identified Licenses: {e}")

    if should_fetch_components:
        try:
            kb_components = workbench.identification.get_identified_components(scan_code)
            if kb_components:
                collected_results["kb_components"] = sorted(
                    kb_components,
                    key=lambda x: (
                        x.get("name", "").lower(),
                        x.get("version", ""),
                    ),
                )
                logger.info("Fetched %d KB components", len(kb_components))
        except (ApiError, NetworkError) as e:
            logger.warning("Could not fetch KB Identified Scan Components: %s", e)
            print("Warning: Could not fetch KB Identified Scan Components: " f"{e}")

    if should_fetch_metrics:
        try:
            metrics = workbench.identification.get_scan_metrics(scan_code)
            if metrics:
                collected_results["scan_metrics"] = metrics
                logger.info("Fetched scan metrics")
        except (ApiError, NetworkError) as e:
            logger.warning("Could not fetch Scan File Metrics: %s", e)
            print(f"Warning: Could not fetch Scan File Metrics: {e}")

    if should_fetch_policy:
        try:
            warnings = workbench.policy.get_policy_warnings(scan_code)
            if warnings:
                collected_results["policy_warnings"] = warnings
                logger.info("Fetched policy warnings counter")
        except (ApiError, NetworkError) as e:
            logger.warning("Could not fetch Scan Policy Warnings: %s", e)
            print(f"Warning: Could not fetch Scan Policy Warnings: {e}")

    if should_fetch_vulnerabilities:
        try:
            vulnerabilities = workbench.vulnerability.list_scan_vulnerabilities(scan_code)
            if vulnerabilities:
                collected_results["vulnerabilities"] = vulnerabilities
                logger.info("Fetched %d vulnerabilities", len(vulnerabilities))
        except (ApiError, NetworkError) as e:
            logger.warning("Could not fetch Vulnerabilities: %s", e)
            print(f"Warning: Could not fetch Vulnerabilities: {e}")

    return collected_results


def display_results(collected_results: Dict[str, Any], params: argparse.Namespace) -> bool:
    """
    Displays results based on the collected data.
    """
    should_fetch_licenses = getattr(params, "show_licenses", False)
    should_fetch_components = getattr(params, "show_components", False)
    should_fetch_dependencies = getattr(params, "show_dependencies", False)
    should_fetch_metrics = getattr(params, "show_scan_metrics", False)
    should_fetch_policy = getattr(params, "show_policy_warnings", False)
    should_fetch_vulnerabilities = getattr(params, "show_vulnerabilities", False)

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
            pending = scan_metrics_data.get("pending_identification", "N/A")
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
                print(f"  - {comp.get('name', 'N/A')} : {comp.get('version', 'N/A')}")
            print("-" * 25)
        else:
            print("No KB Scan Components found to report.")

    # Display Dependencies
    if should_fetch_dependencies:
        print("\n=== Dependency Analysis Results ===")
        displayed_something = True
        if da_results_data:
            print("Component, Version, Scope, and License of Dependencies:")
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
                        logger.debug(f"Could not parse scope for {comp.get('name')}: {scope_err}")
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
            total_warnings = int(policy_warnings_data.get("policy_warnings_total", 0))
            files_with_warnings = int(policy_warnings_data.get("identified_files_with_warnings", 0))
            deps_with_warnings = int(policy_warnings_data.get("dependencies_with_warnings", 0))

            if total_warnings > 0:
                print(
                    f"There are {total_warnings} policy warnings: "
                    f"{files_with_warnings} in Identified Files, and "
                    f"{deps_with_warnings} in Dependencies."
                )
            else:
                print("No policy warnings found.")
        else:
            print("Policy warnings counter could not be fetched.")
        print("-" * 25)

    # Display Vulnerability Summary
    if should_fetch_vulnerabilities:
        displayed_something = True
        print_vulnerability_results(vulnerabilities_data)

    if not displayed_something:
        print("No results were successfully fetched.")
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
            print("\nNo results were successfully collected, skipping save.")
