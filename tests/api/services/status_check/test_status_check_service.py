# tests/unit/api/services/test_status_check_service.py

from unittest.mock import MagicMock, patch

import pytest

from workbench_agent.api.exceptions import (
    ApiError,
    NetworkError,
    UnsupportedStatusCheck,
)
from workbench_agent.api.services.status_check_service import (
    StatusCheckService,
)
from workbench_agent.api.utils.process_waiter import (
    StatusResult,
    extract_server_duration,
)


# --- Fixtures ---
@pytest.fixture
def mock_scans_client(mocker):
    """Create a mock ScansClient."""
    client = mocker.MagicMock()
    return client


@pytest.fixture
def mock_projects_client(mocker):
    """Create a mock ProjectsClient."""
    client = mocker.MagicMock()
    return client


@pytest.fixture
def status_check_service(mock_scans_client, mock_projects_client):
    """Create a StatusCheckService instance for testing."""
    return StatusCheckService(mock_scans_client, mock_projects_client)


# --- Test StatusResult dataclass ---
def test_status_result_creation():
    """Test StatusResult object creation and auto-calculation."""
    result = StatusResult(status="FINISHED", raw_data={"test": "data"})
    assert result.status == "FINISHED"
    assert result.is_finished is True
    assert result.is_failed is False
    assert result.raw_data == {"test": "data"}


def test_status_result_failed_status():
    """Test StatusResult with failed status."""
    result = StatusResult(
        status="FAILED", raw_data={"error": "Something went wrong"}
    )
    assert result.status == "FAILED"
    # FAILED is a completion state, so is_finished should be True
    assert result.is_finished is True
    assert result.is_failed is True
    assert result.error_message == "Something went wrong"


def test_status_result_progress_extraction():
    """Test progress information extraction."""
    raw_data = {
        "state": "RUNNING",
        "current_step": "Processing files",
        "percentage_done": "45%",
        "total_files": 100,
        "current_file": "test.py",
    }
    result = StatusResult(status="RUNNING", raw_data=raw_data)
    assert result.progress_info is not None
    assert result.progress_info["state"] == "RUNNING"
    assert result.progress_info["percentage_done"] == "45%"


# --- Test standard_scan_status_accessor ---
def test_standard_scan_status_accessor_with_is_finished(
    status_check_service,
):
    """Test status accessor with is_finished flag."""
    data = {"is_finished": "1"}
    status = status_check_service._standard_scan_status_accessor(data)
    assert status == "FINISHED"

    data = {"is_finished": True}
    status = status_check_service._standard_scan_status_accessor(data)
    assert status == "FINISHED"


def test_standard_scan_status_accessor_with_status(status_check_service):
    """Test status accessor with status field."""
    data = {"status": "RUNNING"}
    status = status_check_service._standard_scan_status_accessor(data)
    assert status == "RUNNING"

    data = {"status": "running"}  # Lowercase
    status = status_check_service._standard_scan_status_accessor(data)
    assert status == "RUNNING"  # Should be uppercase


def test_standard_scan_status_accessor_unknown(status_check_service):
    """Test status accessor with unknown data."""
    data = {"some_other_key": "value"}
    status = status_check_service._standard_scan_status_accessor(data)
    assert status == "UNKNOWN"


def test_standard_scan_status_accessor_access_error(status_check_service):
    """Test status accessor with invalid data type."""
    data = 123  # Not a dict, will cause AttributeError
    status = status_check_service._standard_scan_status_accessor(data)
    assert status == "ACCESS_ERROR"


def test_standard_scan_status_accessor_new_status(status_check_service):
    """Test that NEW status is preserved (six-state model)."""
    data = {"status": "NEW"}
    status = status_check_service._standard_scan_status_accessor(data)
    assert status == "NEW"


def test_standard_scan_status_accessor_progress_state(
    status_check_service,
):
    """Test status accessor with progress_state field."""
    data = {"progress_state": "RUNNING"}
    status = status_check_service._standard_scan_status_accessor(data)
    assert status == "RUNNING"

    data = {"progress_state": "NEW"}
    status = status_check_service._standard_scan_status_accessor(data)
    assert status == "NEW"  # NEW is preserved in six-state model


# --- Test specialized status checking methods ---
def test_check_scan_status(status_check_service, mock_scans_client):
    """Test check_scan_status method."""
    mock_scans_client.check_status.return_value = {
        "status": "FINISHED",
        "is_finished": "1",
    }

    result = status_check_service.check_scan_status("scan123")

    assert isinstance(result, StatusResult)
    assert result.status == "FINISHED"
    assert result.is_finished is True
    mock_scans_client.check_status.assert_called_once_with(
        "scan123", "SCAN"
    )


def test_check_dependency_analysis_status(
    status_check_service, mock_scans_client
):
    """Test check_dependency_analysis_status method."""
    mock_scans_client.check_status.return_value = {
        "status": "RUNNING",
        "percentage_done": "75%",
    }

    result = status_check_service.check_dependency_analysis_status(
        "scan456"
    )

    assert isinstance(result, StatusResult)
    assert result.status == "RUNNING"
    assert result.is_finished is False
    mock_scans_client.check_status.assert_called_once_with(
        "scan456", "DEPENDENCY_ANALYSIS"
    )


def test_check_extract_archives_status(
    status_check_service, mock_scans_client
):
    """Test check_extract_archives_status method."""
    mock_scans_client.check_status.return_value = {
        "status": "FAILED",
        "error": "Archive corrupted",
    }

    result = status_check_service.check_extract_archives_status("scan789")

    assert isinstance(result, StatusResult)
    assert result.status == "FAILED"
    assert result.is_failed is True
    assert result.error_message == "Archive corrupted"
    mock_scans_client.check_status.assert_called_once_with(
        "scan789", "EXTRACT_ARCHIVES"
    )


def test_check_scan_report_status(status_check_service, mock_scans_client):
    """Test check_scan_report_status method."""
    mock_scans_client.check_status.return_value = {
        "status": "FINISHED",
        "is_finished": "1",
    }

    result = status_check_service.check_scan_report_status("scan123", 456)

    assert isinstance(result, StatusResult)
    assert result.status == "FINISHED"
    assert result.is_finished is True
    mock_scans_client.check_status.assert_called_once_with(
        "scan123", "REPORT_GENERATION", process_id="456"
    )


def test_check_delete_scan_status(status_check_service, mock_scans_client):
    """Test check_delete_scan_status method."""
    mock_scans_client.check_status.return_value = {
        "status": "FINISHED",
        "is_finished": "1",
    }

    result = status_check_service.check_delete_scan_status("scan123", 789)

    assert isinstance(result, StatusResult)
    assert result.status == "FINISHED"
    assert result.is_finished is True
    mock_scans_client.check_status.assert_called_once_with(
        None, "DELETE_SCAN", process_id=789
    )


def test_check_project_report_status(
    status_check_service, mock_projects_client
):
    """Test check_project_report_status method."""
    mock_projects_client.check_status.return_value = {
        "progress_state": "FINISHED"
    }

    result = status_check_service.check_project_report_status(
        123, "PROJ456"
    )

    assert isinstance(result, StatusResult)
    assert result.status == "FINISHED"
    assert result.is_finished is True
    mock_projects_client.check_status.assert_called_once_with(
        process_id=123, process_type="REPORT_GENERATION"
    )


def test_check_git_clone_status(status_check_service, mock_scans_client):
    """Test check_git_clone_status method."""
    mock_scans_client.check_status_download_content_from_git.return_value = {
        "data": "FINISHED"
    }

    result = status_check_service.check_git_clone_status("scan123")

    assert isinstance(result, StatusResult)
    assert result.status == "FINISHED"
    assert result.is_finished is True
    mock_scans_client.check_status_download_content_from_git.assert_called_once_with(
        "scan123"
    )


# --- Test status accessor methods ---
def test_git_status_accessor_variants(status_check_service):
    """Test git status accessor with various input formats."""
    # Direct string
    assert (
        status_check_service._git_status_accessor("finished") == "FINISHED"
    )
    # Dict with 'data'
    assert (
        status_check_service._git_status_accessor({"data": "running"})
        == "RUNNING"
    )
    # NOT STARTED maps to NEW (six-state model)
    assert (
        status_check_service._git_status_accessor({"data": "NOT STARTED"})
        == "NEW"
    )
    # Unexpected type -> ACCESS_ERROR
    assert status_check_service._git_status_accessor(123) == "ACCESS_ERROR"


def test_project_report_status_accessor(status_check_service):
    """Test project report status accessor."""
    # NEW -> NEW (six-state model)
    assert (
        status_check_service._project_report_status_accessor(
            {"progress_state": "NEW"}
        )
        == "NEW"
    )
    # RUNNING -> RUNNING
    assert (
        status_check_service._project_report_status_accessor(
            {"progress_state": "RUNNING"}
        )
        == "RUNNING"
    )
    # Missing -> UNKNOWN
    assert (
        status_check_service._project_report_status_accessor({})
        == "UNKNOWN"
    )


def test_extract_server_duration_valid():
    """Test server duration extraction when started/finished present."""
    raw = {
        "started": "2025-08-08 00:00:00",
        "finished": "2025-08-08 00:00:05",
    }
    duration = extract_server_duration(raw)
    assert duration == 5.0


def test_extract_server_duration_git_format():
    """Test git format data should return None for duration."""
    raw = {"data": "FINISHED"}
    assert extract_server_duration(raw) is None


def test_extract_server_duration_missing():
    """Test missing timestamps -> None."""
    raw = {"status": "FINISHED"}
    assert extract_server_duration(raw) is None


def test_extract_server_duration_invalid():
    """Test invalid timestamp format -> None."""
    raw = {"started": "invalid", "finished": "invalid"}
    assert extract_server_duration(raw) is None


# --- Test wait=True functionality ---


def test_check_scan_status_with_wait(
    status_check_service, mock_scans_client, mocker
):
    """Test check_scan_status with wait=True."""
    # Mock the private method to return different states
    mock_scans_client.check_status.side_effect = [
        {"status": "RUNNING"},
        {"status": "RUNNING"},
        {
            "status": "FINISHED",
            "started": "2025-08-08 00:00:00",
            "finished": "2025-08-08 00:00:10",
        },
    ]

    result = status_check_service.check_scan_status(
        "scan123", wait=True, wait_retry_count=10, wait_retry_interval=0.01
    )

    assert isinstance(result, StatusResult)
    assert result.status == "FINISHED"
    assert result.success is True
    assert result.duration == 10.0
    assert result.is_terminal is True


def test_check_scan_status_without_wait(
    status_check_service, mock_scans_client
):
    """Test check_scan_status with wait=False (default)."""
    mock_scans_client.check_status.return_value = {"status": "RUNNING"}

    result = status_check_service.check_scan_status("scan123")

    assert isinstance(result, StatusResult)
    assert result.status == "RUNNING"
    assert result.is_active is True
    assert result.duration is None  # No duration when not waiting


def test_check_extract_archives_status_wait_failure(
    status_check_service, mock_scans_client
):
    """Test check_extract_archives_status with wait=True and failure."""
    mock_scans_client.check_status.side_effect = [
        {"status": "QUEUED"},
        {
            "status": "FAILED",
            "error": "Extraction failed",
            "started": "2025-08-08 00:00:00",
            "finished": "2025-08-08 00:00:05",
        },
    ]

    result = status_check_service.check_extract_archives_status(
        "scan123", wait=True, wait_retry_count=10, wait_retry_interval=0.01
    )

    assert result.status == "FAILED"
    assert result.success is False
    assert result.error_message == "Extraction failed"
    assert result.duration == 5.0


def test_check_dependency_analysis_status_wait_cancelled(
    status_check_service, mock_scans_client
):
    """Test check_dependency_analysis_status with CANCELLED status."""
    mock_scans_client.check_status.side_effect = [
        {"status": "RUNNING"},
        {"status": "CANCELLED", "info": "User cancelled"},
    ]

    result = status_check_service.check_dependency_analysis_status(
        "scan123", wait=True, wait_retry_count=10, wait_retry_interval=0.01
    )

    assert result.status == "CANCELLED"
    assert result.success is False
    assert result.is_failed is True
    assert result.error_message == "User cancelled"
