"""Unit tests for per-handler pre-flight conflict sets."""

import argparse
from unittest.mock import MagicMock

import pytest

from workbench_agent.api.exceptions import ProcessTimeoutError
from workbench_agent.api.utils.process_waiter import StatusResult
from workbench_agent.utilities.pre_flight_checks import (
    blind_scan_pre_flight_check,
    download_reports_pre_flight_check,
    evaluate_gates_pre_flight_check,
    import_da_pre_flight_check,
    import_sbom_pre_flight_check,
    scan_git_pre_flight_check,
    scan_pre_flight_check,
    show_results_pre_flight_check,
)


def _params():
    return argparse.Namespace(scan_number_of_tries=5, scan_wait_time=2)


def _idle():
    return StatusResult(status="NEW", raw_data={})


def _active():
    return StatusResult(status="RUNNING", raw_data={})


def _client():
    client = MagicMock()
    status = client.status_check
    status.check_extract_archives_status.return_value = _idle()
    status.check_scan_status.return_value = _idle()
    status.check_dependency_analysis_status.return_value = _idle()
    status.check_git_clone_status.return_value = _idle()
    status.check_report_import_status.return_value = _idle()
    return client


def _wait_kwargs(mock):
    waited = [call for call in mock.call_args_list if call.kwargs.get("wait") is True]
    assert waited, f"expected a wait=True call, got {mock.call_args_list}"
    return waited[-1].kwargs


class TestConflictSets:
    def test_scan_probes_extract_kb_and_da(self):
        client = _client()
        scan_pre_flight_check(client, "SCAN", _params())

        status = client.status_check
        status.check_extract_archives_status.assert_called_once_with("SCAN")
        status.check_scan_status.assert_called_once_with("SCAN")
        status.check_dependency_analysis_status.assert_called_once_with("SCAN")
        status.check_git_clone_status.assert_not_called()
        status.check_report_import_status.assert_not_called()

    def test_scan_git_probes_git_kb_and_da(self):
        client = _client()
        scan_git_pre_flight_check(client, "SCAN", _params())

        status = client.status_check
        status.check_git_clone_status.assert_called_once_with("SCAN")
        status.check_scan_status.assert_called_once_with("SCAN")
        status.check_dependency_analysis_status.assert_called_once_with("SCAN")
        status.check_extract_archives_status.assert_not_called()
        status.check_report_import_status.assert_not_called()

    def test_blind_scan_probes_kb_and_da(self):
        client = _client()
        blind_scan_pre_flight_check(client, "SCAN", _params())

        status = client.status_check
        status.check_scan_status.assert_called_once_with("SCAN")
        status.check_dependency_analysis_status.assert_called_once_with("SCAN")
        status.check_extract_archives_status.assert_not_called()
        status.check_git_clone_status.assert_not_called()

    def test_import_da_probes_da_only(self):
        client = _client()
        import_da_pre_flight_check(client, "SCAN", _params())

        status = client.status_check
        status.check_dependency_analysis_status.assert_called_once_with("SCAN")
        status.check_scan_status.assert_not_called()
        status.check_report_import_status.assert_not_called()

    def test_import_sbom_probes_report_import_only(self):
        client = _client()
        import_sbom_pre_flight_check(client, "SCAN", _params())

        status = client.status_check
        status.check_report_import_status.assert_called_once_with("SCAN")
        status.check_scan_status.assert_not_called()
        status.check_dependency_analysis_status.assert_not_called()


class TestWaitIfActive:
    def test_scan_waits_when_extract_is_active(self):
        client = _client()
        client.status_check.check_extract_archives_status.side_effect = [
            _active(),
            _idle(),
        ]

        scan_pre_flight_check(client, "SCAN", _params())

        kwargs = _wait_kwargs(client.status_check.check_extract_archives_status)
        assert kwargs["wait_retry_count"] == 5
        assert kwargs["wait_retry_interval"] == 2

    def test_idle_process_does_not_wait(self):
        client = _client()
        scan_pre_flight_check(client, "SCAN", _params())

        for mock in (
            client.status_check.check_extract_archives_status,
            client.status_check.check_scan_status,
            client.status_check.check_dependency_analysis_status,
        ):
            assert all(not call.kwargs.get("wait") for call in mock.call_args_list)


class TestErrorPolicy:
    def test_scan_swallows_probe_errors_and_continues(self):
        client = _client()
        client.status_check.check_extract_archives_status.side_effect = RuntimeError(
            "extract down"
        )
        client.status_check.check_scan_status.return_value = _idle()
        client.status_check.check_dependency_analysis_status.return_value = _idle()

        scan_pre_flight_check(client, "SCAN", _params())

        client.status_check.check_scan_status.assert_called_once()
        client.status_check.check_dependency_analysis_status.assert_called_once()

    def test_evaluate_gates_propagates_timeout(self):
        client = _client()
        client.status_check.check_scan_status.side_effect = ProcessTimeoutError(
            "KB timed out"
        )

        with pytest.raises(ProcessTimeoutError, match="KB timed out"):
            evaluate_gates_pre_flight_check(client, "SCAN", _params())

    def test_show_results_swallows_errors(self):
        client = _client()
        client.status_check.check_scan_status.side_effect = RuntimeError("no status")
        client.status_check.check_dependency_analysis_status.side_effect = RuntimeError(
            "no da"
        )

        show_results_pre_flight_check(client, "SCAN", _params())

    def test_download_reports_swallows_errors(self):
        client = _client()
        client.status_check.check_scan_status.side_effect = RuntimeError("no status")
        client.status_check.check_dependency_analysis_status.side_effect = RuntimeError(
            "no da"
        )

        download_reports_pre_flight_check(client, "SCAN", _params())


class TestImportDaQuiet:
    def test_quiet_skips_banner(self, capsys):
        client = _client()
        import_da_pre_flight_check(client, "SCAN", _params(), quiet=True)

        assert capsys.readouterr().out == ""
        client.status_check.check_dependency_analysis_status.assert_called_once()
