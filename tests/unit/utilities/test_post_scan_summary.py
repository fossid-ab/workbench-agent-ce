"""Tests for post_scan_summary utilities."""

import argparse
from unittest.mock import MagicMock

import pytest

from workbench_agent.utilities.post_scan_summary import print_scan_summary


@pytest.fixture
def mock_params():
    return argparse.Namespace(
        dependency_analysis_only=False,
        reuse_any_identification=False,
        reuse_my_identifications=False,
        reuse_project_ids=None,
        reuse_scan_ids=None,
        autoid_pending_ids=True,
        autoid_file_licenses=True,
        autoid_file_copyrights=False,
    )


@pytest.fixture
def mock_client(mocker):
    client = mocker.MagicMock()
    client.links.get_workbench_links.return_value = MagicMock(
        scan={"url": "https://workbench.example/scan/1"}
    )
    return client


def test_print_scan_summary_link_only(mock_client, mock_params, capsys):
    print_scan_summary(
        mock_client,
        mock_params,
        "SCAN1",
        show_summary=False,
        scan_operations={"run_kb_scan": True, "run_dependency_analysis": False},
    )

    output = capsys.readouterr().out
    assert "View this Scan in Workbench" in output
    assert "https://workbench.example/scan/1" in output
    mock_client.identification.get_scan_metrics.assert_not_called()


def test_print_scan_summary_requires_scan_operations(mock_client, mock_params):
    with pytest.raises(ValueError, match="scan_operations is required"):
        print_scan_summary(
            mock_client,
            mock_params,
            "SCAN1",
            show_summary=True,
            scan_operations=None,
        )


def test_print_scan_summary_full(mock_client, mock_params, mocker, capsys):
    mock_client.identification.get_scan_metrics.return_value = {
        "total": 10,
        "identified_files": 5,
        "pending_identification": 2,
        "without_matches": 3,
    }
    mock_client.identification.get_identified_components.return_value = [{"name": "openssl"}]
    mock_client.identification.get_unique_identified_licenses.return_value = [{"identifier": "MIT"}]
    mock_client.policy.get_policy_warnings.return_value = {
        "policy_warnings_total": 0,
        "identified_files_with_warnings": 0,
        "dependencies_with_warnings": 0,
    }
    mock_client.vulnerability.list_scan_vulnerabilities.return_value = []

    print_scan_summary(
        mock_client,
        mock_params,
        "SCAN1",
        durations={"kb_scan": 65.0},
        show_summary=True,
        scan_operations={
            "run_kb_scan": True,
            "run_dependency_analysis": False,
            "da_completed": False,
        },
    )

    output = capsys.readouterr().out
    assert "Post-Scan Summary" in output
    assert "Signature Scanning: Yes (1 minutes, 5 seconds)" in output
    assert "Total Files Scanned: 10" in output
