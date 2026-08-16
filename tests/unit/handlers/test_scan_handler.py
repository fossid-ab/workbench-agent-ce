"""Tests for scan handler -- incremental upload + scan target prep wiring."""

import argparse
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

from workbench_agent.handlers.scan import handle_scan


@contextmanager
def _passthrough_prepared(path):
    """Stand-in for prepare_scan_target that yields the input path."""
    yield path


@pytest.fixture
def base_params():
    ns = argparse.Namespace()
    ns.command = "scan"
    ns.project_name = "TestProject"
    ns.scan_name = "TestScan"
    ns.path = "/tmp/src"
    ns.incremental_upload = False
    ns.recursively_extract_archives = True
    ns.jar_file_extraction = False
    ns.scan_number_of_tries = 10
    return ns


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.scan_content = MagicMock()
    client.scan_content.remove_uploaded_content.return_value = True
    client.scan_content.extract_archives.return_value = False
    return client


@patch(
    "workbench_agent.handlers.scan.find_or_create_project_and_scan",
    return_value=("proj_code", "scan_code", False),
)
@patch(
    "workbench_agent.handlers.scan.prepare_scan_target",
    side_effect=_passthrough_prepared,
)
class TestScanHandlerClearBehavior:
    """Tests for the content-clearing step gated by --incremental-upload."""

    @patch(
        "workbench_agent.handlers.scan.execute_scan_workflow",
        return_value=True,
    )
    @patch("workbench_agent.handlers.scan.scan_pre_flight_check")
    def test_existing_scan_clears_content_by_default(
        self,
        mock_preflight,
        _mock_workflow,
        _mock_prep,
        _mock_resolve,
        mock_client,
        base_params,
    ):
        """Default behavior: existing scan content is cleared before upload."""
        handle_scan(mock_client, base_params)

        mock_preflight.assert_called_once_with(mock_client, "scan_code", base_params)
        mock_client.scan_content.remove_uploaded_content.assert_called_once_with("scan_code", "")

    @patch(
        "workbench_agent.handlers.scan.execute_scan_workflow",
        return_value=True,
    )
    @patch("workbench_agent.handlers.scan.scan_pre_flight_check")
    def test_incremental_upload_skips_clear(
        self,
        _mock_preflight,
        _mock_workflow,
        _mock_prep,
        _mock_resolve,
        mock_client,
        base_params,
    ):
        """With --incremental-upload, existing content is NOT cleared."""
        base_params.incremental_upload = True

        handle_scan(mock_client, base_params)

        mock_client.scan_content.remove_uploaded_content.assert_not_called()

    @patch(
        "workbench_agent.handlers.scan.execute_scan_workflow",
        return_value=True,
    )
    @patch("workbench_agent.handlers.scan.scan_pre_flight_check")
    def test_incremental_upload_prints_message(
        self,
        _mock_preflight,
        _mock_workflow,
        _mock_prep,
        _mock_resolve,
        mock_client,
        base_params,
        capsys,
    ):
        """Incremental upload on existing scan prints info message."""
        base_params.incremental_upload = True

        handle_scan(mock_client, base_params)

        captured = capsys.readouterr()
        assert "Incremental Upload - existing content will be kept." in captured.out

    @patch(
        "workbench_agent.handlers.scan.execute_scan_workflow",
        return_value=True,
    )
    @patch("workbench_agent.handlers.scan.scan_pre_flight_check")
    def test_new_scan_skips_clear_regardless_of_flag(
        self,
        _mock_preflight,
        _mock_workflow,
        _mock_prep,
        mock_resolve,
        mock_client,
        base_params,
    ):
        """New scans never clear content, with or without the flag."""
        mock_resolve.return_value = ("proj_code", "scan_code", True)
        base_params.incremental_upload = True

        handle_scan(mock_client, base_params)

        mock_client.scan_content.remove_uploaded_content.assert_not_called()

    @patch(
        "workbench_agent.handlers.scan.execute_scan_workflow",
        return_value=True,
    )
    @patch("workbench_agent.handlers.scan.scan_pre_flight_check")
    def test_new_scan_without_flag_skips_clear(
        self,
        mock_preflight,
        _mock_workflow,
        _mock_prep,
        mock_resolve,
        mock_client,
        base_params,
    ):
        """New scans skip clearing even without --incremental-upload."""
        mock_resolve.return_value = ("proj_code", "scan_code", True)

        handle_scan(mock_client, base_params)

        mock_preflight.assert_not_called()
        mock_client.scan_content.remove_uploaded_content.assert_not_called()


class TestScanHandlerUploadWiring:
    """Confirm the handler hands the prepared path to the upload service."""

    @patch(
        "workbench_agent.handlers.scan.find_or_create_project_and_scan",
        return_value=("proj_code", "scan_code", False),
    )
    @patch(
        "workbench_agent.handlers.scan.execute_scan_workflow",
        return_value=True,
    )
    @patch("workbench_agent.handlers.scan.scan_pre_flight_check")
    @patch("workbench_agent.handlers.scan.prepare_scan_target")
    def test_uses_prepared_path_for_upload(
        self,
        mock_prep,
        _mock_preflight,
        _mock_workflow,
        _mock_resolve,
        mock_client,
        base_params,
    ):
        """upload_scan_target receives the path yielded by prepare_scan_target."""
        prepared_ctx = MagicMock()
        prepared_ctx.__enter__.return_value = "/tmp/prepared.zip"
        prepared_ctx.__exit__.return_value = False
        mock_prep.return_value = prepared_ctx

        handle_scan(mock_client, base_params)

        mock_prep.assert_called_once_with(base_params.path)
        mock_client.scan_content.upload_scan_target.assert_called_once_with(
            "scan_code", "/tmp/prepared.zip"
        )
        prepared_ctx.__exit__.assert_called_once()
