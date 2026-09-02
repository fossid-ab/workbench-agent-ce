"""Tests for the analyze command's combined post-analysis summary."""

import argparse

from workbench_agent.utilities.analyze.summary import print_analysis_summary


def _params(**overrides):
    ns = argparse.Namespace(
        no_wait=False,
        show_summary=True,
        dependency_analysis_only=False,
        reuse_any_identification=False,
        reuse_my_identifications=False,
        reuse_project_ids=None,
        reuse_scan_ids=None,
        autoid_pending_ids=False,
        autoid_file_licenses=False,
        autoid_file_copyrights=False,
    )
    for key, value in overrides.items():
        setattr(ns, key, value)
    return ns


def test_print_analysis_summary_combines_kb_and_da(mocker, capsys):
    client = mocker.MagicMock()
    client.links.get_workbench_links.return_value = mocker.MagicMock(
        scan={"url": "https://workbench.example/scan/1"}
    )
    client.identification.get_scan_metrics.return_value = {
        "total": 1,
        "identified_files": 0,
        "pending_identification": 0,
        "without_matches": 1,
    }
    client.identification.get_identified_components.return_value = []
    client.identification.get_unique_identified_licenses.return_value = []
    client.dependencies.list_dependencies.return_value = [
        {"license_identifier": "MIT"},
        {"license_identifier": "MIT"},
        {"license_identifier": "Apache-2.0"},
    ]
    client.policy.get_policy_warnings.return_value = {
        "policy_warnings_total": 0,
        "identified_files_with_warnings": 0,
        "dependencies_with_warnings": 0,
    }
    client.vulnerability.list_scan_vulnerabilities.return_value = []

    print_analysis_summary(
        client,
        _params(),
        "SCAN1",
        durations={"kb_scan": 7.0},
        kb_performed=True,
        da_imported=True,
    )

    output = capsys.readouterr().out
    assert "Post-Analysis Summary" in output
    assert "Post-Scan Summary" not in output
    assert "Post-Import Summary" not in output
    assert "Signature Scanning: Yes (7 seconds)" in output
    assert "Dependency Analysis: Yes" in output
    assert "Dependency Analysis: Skipped" not in output
    assert "Total Files Scanned: 1" in output
    assert "Dependencies Analyzed: 3" in output
    assert output.count("View this Scan in Workbench") == 1


def test_print_analysis_summary_no_wait_is_link_only(mocker, capsys):
    client = mocker.MagicMock()
    client.links.get_workbench_links.return_value = mocker.MagicMock(
        scan={"url": "https://workbench.example/scan/1"}
    )

    print_analysis_summary(
        client,
        _params(no_wait=True, show_summary=True),
        "SCAN1",
        kb_performed=True,
        da_imported=False,
    )

    output = capsys.readouterr().out
    assert "View this Scan in Workbench" in output
    assert "Post-Analysis Summary" not in output
    client.identification.get_scan_metrics.assert_not_called()
