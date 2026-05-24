"""
Test suite for scan_workflows.py utilities.

This module contains tests for scan workflow configuration functions.
"""

import argparse

import pytest

from workbench_agent.api.utils.process_waiter import StatusResult
from workbench_agent.utilities.scan_workflows import (
    _determine_scans_to_run,
    execute_scan_workflow,
)

# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def mock_params(mocker):
    """Create a mock argparse.Namespace with common default values."""
    params = mocker.MagicMock(spec=argparse.Namespace)

    # Analysis flags
    params.run_dependency_analysis = False
    params.dependency_analysis_only = False

    return params


@pytest.fixture
def scan_workflow_params():
    """Create params for running the KB scan workflow."""
    return argparse.Namespace(
        run_dependency_analysis=False,
        dependency_analysis_only=False,
        no_wait=False,
        project_name="Test Project",
        limit=10,
        sensitivity=6,
        autoid_file_licenses=True,
        autoid_file_copyrights=True,
        autoid_pending_ids=True,
        delta_scan=False,
        scan_number_of_tries=3,
        scan_wait_time=1,
        show_summary=False,
    )


@pytest.fixture
def mock_client(mocker):
    """Create a mock Workbench client for scan workflow tests."""
    client = mocker.MagicMock()
    client.resolver.resolve_id_reuse.return_value = (None, None)
    return client


# ============================================================================
# SCAN CONFIGURATION TESTS
# ============================================================================


class TestDetermineScansToRun:
    """Test cases for the _determine_scans_to_run function."""

    def test_default_configuration(self, mock_params):
        """Test default behavior - only KB scan."""
        mock_params.run_dependency_analysis = False
        mock_params.dependency_analysis_only = False

        result = _determine_scans_to_run(mock_params)

        assert result == {
            "run_kb_scan": True,
            "run_dependency_analysis": False,
        }

    def test_with_dependency_analysis(self, mock_params):
        """Test with dependency analysis enabled."""
        mock_params.run_dependency_analysis = True
        mock_params.dependency_analysis_only = False

        result = _determine_scans_to_run(mock_params)
        assert result == {
            "run_kb_scan": True,
            "run_dependency_analysis": True,
        }

    def test_dependency_analysis_only(self, mock_params):
        """Test with dependency analysis only."""
        mock_params.run_dependency_analysis = False
        mock_params.dependency_analysis_only = True

        result = _determine_scans_to_run(mock_params)
        assert result == {
            "run_kb_scan": False,
            "run_dependency_analysis": True,
        }

    def test_conflicting_flags_resolved(self, mock_params):
        """Test that DA only takes precedence."""
        mock_params.run_dependency_analysis = True
        mock_params.dependency_analysis_only = True

        result = _determine_scans_to_run(mock_params)
        assert result == {
            "run_kb_scan": False,
            "run_dependency_analysis": True,
        }


# ============================================================================
# SCAN WORKFLOW TESTS
# ============================================================================


class TestExecuteScanWorkflow:
    """Test cases for the execute_scan_workflow function."""

    def test_kb_scan_success_does_not_retry(
        self,
        mocker,
        mock_client,
        scan_workflow_params,
    ):
        """Successful KB scan should run once."""
        mocker.patch(
            "workbench_agent.utilities.scan_workflows._print_scan_summary"
        )
        mock_client.status_check.check_scan_status.return_value = (
            StatusResult(
                status="FINISHED",
                raw_data={},
                duration=12.0,
            )
        )

        result = execute_scan_workflow(
            mock_client,
            scan_workflow_params,
            "SCAN123",
            {},
        )

        assert result is True
        assert mock_client.scan_operations.start_scan.call_count == 1
        assert (
            mock_client.scan_operations.start_scan.call_args.kwargs[
                "scan_failed_only"
            ]
            is False
        )
        mock_client.scan_operations.scan_failed_files.assert_not_called()

    def test_kb_scan_failure_retries_failed_files_once(
        self,
        mocker,
        mock_client,
        scan_workflow_params,
    ):
        """Failed KB scan should retry once with scan_failed_only."""
        mocker.patch(
            "workbench_agent.utilities.scan_workflows._print_scan_summary"
        )
        mock_client.status_check.check_scan_status.side_effect = [
            StatusResult(
                status="FAILED",
                raw_data={},
                duration=12.0,
            ),
            StatusResult(
                status="FINISHED",
                raw_data={},
                duration=8.0,
            ),
        ]
        durations: dict[str, float] = {}

        result = execute_scan_workflow(
            mock_client,
            scan_workflow_params,
            "SCAN123",
            durations,
        )

        assert result is True
        assert mock_client.scan_operations.start_scan.call_count == 1
        first_call = mock_client.scan_operations.start_scan.call_args
        assert first_call.kwargs["scan_failed_only"] is False
        mock_client.scan_operations.scan_failed_files.assert_called_once()
        retry_kwargs = (
            mock_client.scan_operations.scan_failed_files.call_args.kwargs
        )
        assert retry_kwargs["scan_code"] == "SCAN123"
        assert durations["kb_scan"] == 20.0

    def test_kb_scan_cancelled_failure_does_not_retry(
        self,
        mocker,
        mock_client,
        scan_workflow_params,
    ):
        """User-cancelled KB scan should not trigger failed-file retry."""
        mocker.patch(
            "workbench_agent.utilities.scan_workflows._print_scan_summary"
        )
        mock_client.status_check.check_scan_status.return_value = (
            StatusResult(
                status="FAILED",
                raw_data={
                    "status": "FAILED",
                    "state": "FAILED",
                    "info": "The process was cancelled",
                    "comment": "The process was cancelled",
                },
                duration=12.0,
            )
        )

        result = execute_scan_workflow(
            mock_client,
            scan_workflow_params,
            "SCAN123",
            {},
        )

        assert result is True
        assert mock_client.scan_operations.start_scan.call_count == 1
        mock_client.scan_operations.scan_failed_files.assert_not_called()

    def test_kb_scan_failure_retries_only_once_when_retry_fails(
        self,
        mocker,
        mock_client,
        scan_workflow_params,
    ):
        """Failed retry should not trigger a third KB scan run."""
        mocker.patch(
            "workbench_agent.utilities.scan_workflows._print_scan_summary"
        )
        mock_client.status_check.check_scan_status.side_effect = [
            StatusResult(
                status="FAILED",
                raw_data={},
                duration=12.0,
            ),
            StatusResult(
                status="FAILED",
                raw_data={},
                duration=8.0,
            ),
        ]

        result = execute_scan_workflow(
            mock_client,
            scan_workflow_params,
            "SCAN123",
            {},
        )

        assert result is True
        assert mock_client.scan_operations.start_scan.call_count == 1
        mock_client.scan_operations.scan_failed_files.assert_called_once()
