"""Unit tests for result_utilities."""

from argparse import Namespace
from unittest.mock import MagicMock

from workbench_agent.utilities.result_utilities import fetch_results


def test_fetch_results_show_matches():
    workbench = MagicMock()
    workbench.scans.get_results.return_value = [
        {
            "local_path": "src/main.c",
            "artifact": "curl",
            "version": "7.88.0",
            "match_type": "full",
        }
    ]
    params = Namespace(
        show_licenses=False,
        show_components=False,
        show_matches=True,
        show_dependencies=False,
        show_scan_metrics=False,
        show_policy_warnings=False,
        show_vulnerabilities=False,
    )

    results = fetch_results(workbench, params, "scan_code")

    assert "kb_matches" in results
    assert len(results["kb_matches"]) == 1
    workbench.scans.get_results.assert_called_once_with("scan_code")
