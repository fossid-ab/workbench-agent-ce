"""Unit tests for result_utilities."""

from argparse import Namespace
from unittest.mock import MagicMock

from workbench_agent.utilities.result_utilities import fetch_results


def _base_params(**overrides):
    params = Namespace(
        show_licenses=False,
        show_components=False,
        show_matches=False,
        show_dependencies=False,
        show_scan_metrics=False,
        show_policy_warnings=False,
        show_project_policy_warnings=False,
        show_vulnerabilities=False,
    )
    for key, value in overrides.items():
        setattr(params, key, value)
    return params


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
    params = _base_params(show_matches=True)

    results = fetch_results(workbench, params, "scan_code")

    assert "kb_matches" in results
    assert len(results["kb_matches"]) == 1
    workbench.scans.get_results.assert_called_once_with("scan_code")


def test_fetch_results_show_project_policy_warnings():
    workbench = MagicMock()
    workbench.policy.get_project_identification_policy_warnings.return_value = {
        "scans_with_warnings": 1,
        "warnings_counter": 3,
        "scans_list": [{"scan_name": "Test Scan", "scan_code": "TEST_SCAN"}],
    }
    params = _base_params(show_project_policy_warnings=True)

    results = fetch_results(
        workbench,
        params,
        "scan_code",
        project_code="PROJECT_CODE",
    )

    assert "project_policy_warnings" in results
    workbench.policy.get_project_identification_policy_warnings.assert_called_once_with(
        "PROJECT_CODE"
    )


def test_fetch_results_show_project_policy_warnings_requires_project_code():
    workbench = MagicMock()
    params = _base_params(show_project_policy_warnings=True)

    results = fetch_results(workbench, params, "scan_code")

    assert "project_policy_warnings" not in results
    workbench.policy.get_project_identification_policy_warnings.assert_not_called()
