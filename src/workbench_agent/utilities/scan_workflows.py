import argparse
import logging
from typing import Dict

logger = logging.getLogger("workbench-agent")

# --- Scan Configuration and Execution ---


def determine_scans_to_run(params: argparse.Namespace) -> Dict[str, bool]:
    """
    Determines which scan processes to run based on the provided parameters.

    Args:
        params: Command-line parameters with scan configuration flags

    Returns:
        Dictionary with two keys:
        - run_kb_scan: Whether to run knowledge base scan
        - run_dependency_analysis: Whether to run dependency analysis
    """
    run_dependency_analysis = getattr(params, "run_dependency_analysis", False)
    dependency_analysis_only = getattr(
        params, "dependency_analysis_only", False
    )
    scan_operations = {"run_kb_scan": True, "run_dependency_analysis": False}
    if run_dependency_analysis and dependency_analysis_only:
        print(
            "\nWARNING: Both --dependency-analysis-only and --run-dependency-analysis were specified. Using --dependency-analysis-only mode (skipping KB scan)."
        )
        scan_operations["run_kb_scan"] = False
        scan_operations["run_dependency_analysis"] = True
    elif dependency_analysis_only:
        scan_operations["run_kb_scan"] = False
        scan_operations["run_dependency_analysis"] = True
    elif run_dependency_analysis:
        scan_operations["run_kb_scan"] = True
        scan_operations["run_dependency_analysis"] = True
    logger.debug(f"Determined scan operations: {scan_operations}")
    return scan_operations
