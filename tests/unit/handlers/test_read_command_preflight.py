"""Handlers abort when read-command pre-flight cannot confirm idle."""

import argparse
from unittest.mock import MagicMock, patch

import pytest

from workbench_agent.api.exceptions import ProcessTimeoutError
from workbench_agent.handlers.download_reports import handle_download_reports
from workbench_agent.handlers.evaluate_gates import handle_evaluate_gates
from workbench_agent.handlers.show_results import handle_show_results
from workbench_agent.services.types import ResolvedTargets


def _targets():
    return ResolvedTargets(
        project_code="PROJ",
        scan_code="SCAN",
        project_created=False,
        scan_is_new=False,
        scan_info={"id": 1, "code": "SCAN", "name": "Scan"},
    )


@pytest.fixture
def show_params():
    return argparse.Namespace(
        command="show-results",
        project_name="Proj",
        scan_name="Scan",
        scan_number_of_tries=5,
        scan_wait_time=1,
        show_components=True,
    )


@pytest.fixture
def report_params(tmp_path):
    return argparse.Namespace(
        command="download-reports",
        report_scope="scan",
        report_type="xlsx",
        report_save_path=str(tmp_path),
        project_name="Proj",
        scan_name="Scan",
        scan_number_of_tries=5,
        scan_wait_time=1,
        selection_type=None,
        selection_view=None,
        disclaimer=None,
        include_vex=True,
        show_summary=False,
    )


@pytest.fixture
def gates_params():
    return argparse.Namespace(
        command="evaluate-gates",
        project_name="Proj",
        scan_name="Scan",
        scan_number_of_tries=5,
        scan_wait_time=1,
        fail_on_pending=False,
        fail_on_policy=False,
        fail_on_vuln_severity=None,
    )


@patch(
    "workbench_agent.handlers.show_results.resolve_project_and_scan",
    return_value=_targets(),
)
@patch(
    "workbench_agent.handlers.show_results.show_results_pre_flight_check",
    side_effect=ProcessTimeoutError("KB timed out"),
)
@patch("workbench_agent.handlers.show_results.fetch_display_save_results")
def test_show_results_aborts_when_preflight_times_out(
    mock_fetch,
    _mock_preflight,
    _mock_resolve,
    show_params,
):
    with pytest.raises(ProcessTimeoutError, match="KB timed out"):
        handle_show_results(MagicMock(), show_params)

    mock_fetch.assert_not_called()


@patch(
    "workbench_agent.handlers.download_reports.resolve_project_and_scan",
    return_value=_targets(),
)
@patch(
    "workbench_agent.handlers.download_reports.download_reports_pre_flight_check",
    side_effect=ProcessTimeoutError("KB timed out"),
)
def test_download_reports_aborts_when_preflight_times_out(
    _mock_preflight,
    _mock_resolve,
    report_params,
):
    client = MagicMock()
    client.reports.resolve_report_types.return_value = ["xlsx"]

    with pytest.raises(ProcessTimeoutError, match="KB timed out"):
        handle_download_reports(client, report_params)

    client.reports.run_and_download_report.assert_not_called()


@patch(
    "workbench_agent.handlers.evaluate_gates.resolve_project_and_scan",
    return_value=_targets(),
)
@patch(
    "workbench_agent.handlers.evaluate_gates.evaluate_gates_pre_flight_check",
    side_effect=ProcessTimeoutError("KB timed out"),
)
def test_evaluate_gates_returns_false_when_preflight_times_out(
    _mock_preflight,
    _mock_resolve,
    gates_params,
):
    assert handle_evaluate_gates(MagicMock(), gates_params) is False
