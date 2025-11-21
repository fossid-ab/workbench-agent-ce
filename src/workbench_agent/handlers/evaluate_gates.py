# workbench_agent/handlers/evaluate_gates.py

import argparse
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Optional

from workbench_agent.api.exceptions import (
    ApiError,
    NetworkError,
    ProcessTimeoutError,
)
from workbench_agent.utilities.error_handling import handler_error_wrapper

logger = logging.getLogger("workbench-agent")

if TYPE_CHECKING:
    from workbench_agent.api import WorkbenchClient

# Constants
SEVERITY_ORDER = ["critical", "high", "medium", "low"]


@dataclass
class GateResult:
    """Data class to represent the result of a gate check."""

    passed: bool
    count: int
    message: str
    link_key: Optional[str] = None


@dataclass
class GateResults:
    """Container for all gate check results."""

    pending_files: GateResult
    policy_warnings: GateResult
    vulnerabilities: GateResult

    @property
    def all_passed(self) -> bool:
        return (
            self.pending_files.passed
            and self.policy_warnings.passed
            and self.vulnerabilities.passed
        )


def _extract_policy_count(policy_data: Any) -> int:
    """
    Extract policy warning count from API response, handling different
    response formats.

    Args:
        policy_data: The API response data

    Returns:
        int: The policy warning count
    """
    if not isinstance(policy_data, dict):
        logger.warning(f"Unexpected policy warnings data format: {policy_data}")
        return 0

    # Handle nested data structure
    if "data" in policy_data and isinstance(policy_data["data"], dict):
        return int(policy_data["data"].get("policy_warnings_total", 0))

    # Handle flat structure with fallback
    return int(
        policy_data.get("policy_warnings_total", policy_data.get("total", 0))
    )


def _display_vulnerability_breakdown(vuln_counts: Dict[str, int]) -> None:
    """
    Display vulnerability counts by severity.

    Args:
        vuln_counts: Dictionary of severity levels to counts
    """
    total_vulns = sum(vuln_counts.values())
    print(f"\n⚠️ Warning: Found {total_vulns} vulnerabilities. By CVSS Score:")

    for severity in SEVERITY_ORDER:
        if vuln_counts[severity] > 0:
            print(f" - {severity.upper()}: {vuln_counts[severity]}")


def _check_pending_files_gate(
    client: "WorkbenchClient", scan_code: str, params: "argparse.Namespace"
) -> GateResult:
    """
    Check the pending files gate.

    Args:
        client: The Workbench API client
        scan_code: The scan identifier
        params: Command line parameters

    Returns:
        GateResult: The result of the pending files check
    """
    print("\nChecking for pending files...")
    pending_files = {}
    count = 0

    try:
        pending_files = client.scans.get_pending_files(scan_code)
        count = len(pending_files)
    except (ApiError, NetworkError) as e:
        print(f"\n⚠️ Warning: Failed to check for pending files: {e}")
        logger.warning(
            f"Error checking pending files for scan '{scan_code}': {e}"
        )

        if params.fail_on_pending:
            return GateResult(
                passed=False,
                count=0,
                message=(
                    "❌ Gate Failed: Unable to verify pending files "
                    "status due to API error"
                ),
            )

    # Determine gate result
    if count > 0:
        print(f"\n⚠️ Warning: {count} files with " f"pending identifications.")
        if params.fail_on_pending:
            return GateResult(
                passed=False,
                count=count,
                message=(
                    f"❌ Gate Failed: {count} files with "
                    f"pending identifications."
                ),
                link_key="pending",
            )
        else:
            print(
                "\nNote: Gate is not set to fail "
                "(--fail-on-pending not specified)."
            )
            return GateResult(
                passed=True,
                count=count,
                message=f"Found {count} pending files",
                link_key="pending",
            )
    else:
        print("\n✅ No pending files found - all files have been identified.")
        return GateResult(
            passed=True, count=0, message="No pending files found"
        )


def _check_policy_warnings_gate(
    client: "WorkbenchClient", scan_code: str, params: "argparse.Namespace"
) -> GateResult:
    """
    Check the policy warnings gate.

    Args:
        client: The Workbench API client
        scan_code: The scan identifier
        params: Command line parameters

    Returns:
        GateResult: The result of the policy warnings check
    """
    print("\nChecking for license policy warnings...")

    try:
        policy_data = client.scans.get_policy_warnings_counter(scan_code)
        count = _extract_policy_count(policy_data)

        if count > 0:
            print(f"\n⚠️ Warning: Found {count} license policy warnings.")
            if params.fail_on_policy:
                return GateResult(
                    passed=False,
                    count=count,
                    message=f"❌ Gate Failed: Found {count} policy warnings.",
                    link_key="policy",
                )
            else:
                print(
                    "Note: Gate is not set to fail "
                    "(--fail-on-policy not specified)."
                )
                return GateResult(
                    passed=True,
                    count=count,
                    message=f"Found {count} policy warnings",
                    link_key="policy",
                )
        else:
            print("\n✅ No policy warnings found.")
            return GateResult(
                passed=True, count=0, message="No policy warnings found"
            )

    except (ApiError, NetworkError) as e:
        print(f"\n⚠️ Warning: Failed to check for policy warnings: {e}")
        logger.warning(
            f"Error checking policy warnings for scan '{scan_code}': {e}"
        )

        if params.fail_on_policy:
            return GateResult(
                passed=False,
                count=0,
                message=(
                    "❌ Gate Failed: Unable to verify policy warnings "
                    "status due to API error"
                ),
            )
        else:
            return GateResult(
                passed=True, count=0, message="Policy check failed"
            )


def _check_vulnerabilities_gate(
    client: "WorkbenchClient", scan_code: str, params: "argparse.Namespace"
) -> GateResult:
    """
    Check the vulnerabilities gate.

    Args:
        client: The Workbench API client
        scan_code: The scan identifier
        params: Command line parameters

    Returns:
        GateResult: The result of the vulnerabilities check
    """
    print("\nChecking for vulnerabilities...")

    try:
        vulnerabilities = client.vulnerabilities.list_vulnerabilities(scan_code)

        # Count vulnerabilities by severity
        vuln_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "other": 0,
        }

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "").lower()
            if severity in vuln_counts:
                vuln_counts[severity] += 1
            else:
                vuln_counts["other"] += 1

        total_vulns = sum(vuln_counts.values())

        if total_vulns > 0:
            # Check if we should fail based on severity threshold
            if params.fail_on_vuln_severity:
                threshold_idx = SEVERITY_ORDER.index(
                    params.fail_on_vuln_severity
                )

                for severity in SEVERITY_ORDER[: threshold_idx + 1]:
                    if vuln_counts[severity] > 0:
                        _display_vulnerability_breakdown(vuln_counts)
                        return GateResult(
                            passed=False,
                            count=total_vulns,
                            message=(
                                f"❌ Gate Failed: Found vulnerabilities with "
                                f"severity {severity.upper()} (threshold: "
                                f"{params.fail_on_vuln_severity.upper()})"
                            ),
                            link_key="vulnerabilities",
                        )

                print(
                    f"\n✅ No vulnerabilities found with severity "
                    f"{params.fail_on_vuln_severity.upper()} or higher."
                )

                return GateResult(
                    passed=True,
                    count=total_vulns,
                    message=(
                        f"Found {total_vulns} vulnerabilities below threshold"
                    ),
                )
            else:
                _display_vulnerability_breakdown(vuln_counts)
                print(
                    "\nNote: Gate is not set to fail "
                    "(--fail-on-vuln-severity not specified)."
                )
                return GateResult(
                    passed=True,
                    count=total_vulns,
                    message=f"Found {total_vulns} vulnerabilities",
                )
        else:
            print("\n✅ No vulnerabilities found.")
            return GateResult(
                passed=True, count=0, message="No vulnerabilities found"
            )

    except (ApiError, NetworkError) as e:
        print(f"\n⚠️ Warning: Failed to check for vulnerabilities: {e}")
        logger.warning(
            f"Error checking vulnerabilities for scan '{scan_code}': {e}"
        )

        if params.fail_on_vuln_severity:
            return GateResult(
                passed=False,
                count=0,
                message=(
                    "❌ Gate Failed: Unable to verify vulnerabilities "
                    "status due to API error"
                ),
            )
        else:
            return GateResult(
                passed=True, count=0, message="Vulnerability check failed"
            )


def _print_next_steps(
    workbench_links,
    params: "argparse.Namespace",
    results: GateResults,
) -> None:
    """
    Print Next Steps section with Workbench links based on failed gates.

    Args:
        workbench_links: WorkbenchLinks object from ResultsService
        params: Command line parameters
        results: The gate results containing link information
    """
    if not workbench_links:
        return

    # Collect links for failed gates or actionable items
    next_steps = []

    # Check pending files gate - show link if gate failed or if there are pending files
    if not results.pending_files.passed or results.pending_files.count > 0:
        next_steps.append(workbench_links.pending)

    # Check policy warnings gate - show link if gate failed
    if not results.policy_warnings.passed:
        next_steps.append(workbench_links.policy)

    # Check vulnerabilities gate - show link if gate failed
    if not results.vulnerabilities.passed:
        # Use vulnerable link for vulnerabilities to direct users to Vulnerable Tab
        next_steps.append(workbench_links.vulnerabilities)

    # Only show Next Steps if there are failed gates or actionable items
    if next_steps:
        print("\nNext Steps:")
        print("=" * 50)
        for link_info in next_steps:
            print(f"\n🔗 {link_info['message']}:")
            print(f"{link_info['url']}\n")
        print("=" * 50)


def _print_gate_summary(
    params: "argparse.Namespace", results: GateResults
) -> None:
    """
    Print the final gate evaluation summary.

    Args:
        params: Command line parameters
        results: The gate results
    """
    print("\n" + "=" * 50)
    print("\nGate Evaluation Summary:")
    print("=" * 50)

    # Pending files summary
    if params.fail_on_pending:
        status = "✅ PASSED" if results.pending_files.passed else "❌ FAILED"
        print(
            f"Pending Files Gate: {status} "
            f"({results.pending_files.count} pending files)"
        )
    else:
        icon = "✅" if results.pending_files.count == 0 else "⚠️"
        print(f"Pending Files: {results.pending_files.count} files {icon}")

    # Policy warnings summary
    if params.fail_on_policy:
        status = "✅ PASSED" if results.policy_warnings.passed else "❌ FAILED"
        print(
            f"Policy Warnings Gate: {status} "
            f"({results.policy_warnings.count} warnings)"
        )
    else:
        icon = "✅" if results.policy_warnings.count == 0 else "⚠️"
        print(
            f"Policy Warnings: {results.policy_warnings.count} "
            f"warnings {icon}"
        )

    # Vulnerabilities summary
    if params.fail_on_vuln_severity:
        status = "✅ PASSED" if results.vulnerabilities.passed else "❌ FAILED"
        print(
            f"Vulnerability Gate: {status} "
            f"(Threshold: {params.fail_on_vuln_severity.upper()})"
        )
    else:
        icon = "✅" if results.vulnerabilities.count == 0 else "⚠️"
        print(f"Vulnerabilities: {results.vulnerabilities.count} {icon}")

    print("=" * 50)
    status = "✅ PASSED" if results.all_passed else "❌ FAILED"
    print(f"Overall Gate Status: {status}")
    print("=" * 50)


@handler_error_wrapper
def handle_evaluate_gates(
    client: "WorkbenchClient", params: "argparse.Namespace"
) -> bool:
    """
    Handler for the 'evaluate-gates' command.

    Evaluates quality gates for a scan including:
    - Pending files (unidentified files)
    - License policy warnings
    - Security vulnerabilities (with severity thresholds)

    Gates can be configured to pass/fail based on command line flags,
    making this useful for CI/CD integration.

    Args:
        client: The Workbench API client
        params: Command line parameters including:
            - project_name: Name of the project
            - scan_name: Name of the scan
            - fail_on_pending: Fail if pending files exist
            - fail_on_policy: Fail if policy warnings exist
            - fail_on_vuln_severity: Severity threshold for vulnerabilities

    Returns:
        bool: True if all gates passed, False if any gate failed

    Raises:
        Various exceptions based on errors that occur during the process
    """
    print(f"\n--- Running {params.command.upper()} Command ---")

    # Resolve project and scan (find only - don't create)
    print("\nResolving scan for gate evaluation...")
    scan_code, scan_id = client.resolver.find_scan(
        scan_name=params.scan_name,
        project_name=params.project_name,
    )

    # Ensure scan processes are idle before evaluating gates
    print("\nEnsuring scans finished before evaluating gates...")
    try:
        scan_status = client.status_check.check_scan_status(scan_code)
        if scan_status.status == "RUNNING":
            print(
                "KB Scan is still in progress, " "waiting for it to complete..."
            )

        client.waiting.wait_for_scan(
            scan_code,
            max_tries=params.scan_number_of_tries,
            wait_interval=params.scan_wait_time,
        )

        da_status = client.status_check.check_dependency_analysis_status(
            scan_code
        )
        if da_status.status == "RUNNING":
            print(
                "Dependency Analysis is still in progress, "
                "waiting for it to complete..."
            )

        client.waiting.wait_for_da(
            scan_code,
            max_tries=params.scan_number_of_tries,
            wait_interval=params.scan_wait_time,
        )

        logging.info("Verified all Scan processes are idle. Checking gates...")
    except (ProcessTimeoutError, ApiError, NetworkError) as e:
        print(
            f"\n❌ Gate Evaluation Failed: Could not verify scan "
            f"completion: {e}"
        )
        return False

    # Generate all Workbench links once for use throughout the handler
    workbench_links = None
    try:
        workbench_links = client.results.links(scan_id)
    except Exception as e:
        logger.debug(f"Failed to generate Workbench links: {e}")

    # Run all gate checks
    results = GateResults(
        pending_files=_check_pending_files_gate(client, scan_code, params),
        policy_warnings=_check_policy_warnings_gate(client, scan_code, params),
        vulnerabilities=_check_vulnerabilities_gate(client, scan_code, params),
    )

    # Print final summary
    _print_gate_summary(params, results)

    # Show Next Steps section with relevant Workbench links
    _print_next_steps(workbench_links, params, results)

    return results.all_passed
