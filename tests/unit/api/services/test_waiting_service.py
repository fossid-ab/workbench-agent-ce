# tests/unit/api/services/test_waiting_service.py

import time
from unittest.mock import MagicMock, patch

import pytest

from workbench_agent.api.services.waiting_service import WaitingService
from workbench_agent.api.utils.process_waiter import StatusResult, WaitResult
from workbench_agent.api.exceptions import (
    ProcessError,
    ProcessTimeoutError,
    UnsupportedStatusCheck,
)


# --- Fixtures ---
@pytest.fixture
def mock_status_check_service(mocker):
    """Create a mock StatusCheckService."""
    service = mocker.MagicMock()
    return service


@pytest.fixture
def waiting_service(mock_status_check_service):
    """Create a WaitingService instance for testing."""
    return WaitingService(mock_status_check_service)


# --- Test WaitResult dataclass ---
def test_wait_result_creation():
    """Test WaitResult object creation."""
    result = WaitResult(
        status_data={"test": "data"},
        duration=10.5,
        success=True,
        error_message=None,
    )
    assert result.status_data == {"test": "data"}
    assert result.duration == 10.5
    assert result.success is True
    assert result.error_message is None


# --- Test _wait_for_completion ---
def test_wait_for_completion_success(
    waiting_service, mock_status_check_service
):
    """Test successful completion waiting."""
    mock_check_func = MagicMock()
    mock_check_func.side_effect = [
        StatusResult(status="RUNNING", raw_data={"state": "RUNNING"}),
        StatusResult(status="RUNNING", raw_data={"state": "RUNNING"}),
        StatusResult(status="FINISHED", raw_data={"state": "FINISHED"}),
    ]

    with patch("time.sleep", return_value=None):
        result = waiting_service._wait_for_completion(
            check_function=mock_check_func,
            max_tries=5,
            wait_interval=1,
            operation_name="Test Process",
        )

    assert isinstance(result, WaitResult)
    assert result.success is True
    assert mock_check_func.call_count == 3


def test_wait_for_completion_timeout(
    waiting_service, mock_status_check_service
):
    """Test timeout during completion waiting."""
    mock_check_func = MagicMock()
    mock_check_func.return_value = StatusResult(
        status="RUNNING", raw_data={"state": "RUNNING"}
    )

    with patch("time.sleep", return_value=None):
        with pytest.raises(ProcessTimeoutError, match="Test Timeout"):
            waiting_service._wait_for_completion(
                check_function=mock_check_func,
                max_tries=3,
                wait_interval=1,
                operation_name="Test Timeout",
            )
    assert mock_check_func.call_count == 3


def test_wait_for_completion_failure(
    waiting_service, mock_status_check_service
):
    """Test failure during completion waiting."""
    mock_check_func = MagicMock()
    mock_check_func.return_value = StatusResult(
        status="FAILED", raw_data={"status": "FAILED", "error": "Disk full"}
    )

    with patch("time.sleep", return_value=None):
        result = waiting_service._wait_for_completion(
            check_function=mock_check_func,
            max_tries=5,
            wait_interval=1,
            operation_name="Test Failure",
        )

    assert isinstance(result, WaitResult)
    assert result.success is False
    assert result.error_message == "Disk full"
    assert mock_check_func.call_count == 1  # Fails immediately


# --- Test specialized waiting methods ---
def test_wait_for_scan(waiting_service, mock_status_check_service):
    """Test wait_for_scan method."""
    mock_status_check_service.check_scan_status.return_value = StatusResult(
        status="FINISHED", raw_data={"status": "FINISHED"}
    )

    with patch.object(waiting_service, "_wait_for_completion") as mock_wait:
        mock_wait.return_value = WaitResult(
            status_data={"status": "FINISHED"}, duration=20.0, success=True
        )

        result = waiting_service.wait_for_scan("scan123", 10, 5)

        assert isinstance(result, WaitResult)
        assert result.success is True
        assert result.duration == 20.0
        mock_wait.assert_called_once()


def test_wait_for_da(waiting_service, mock_status_check_service):
    """Test wait_for_da method."""
    with patch.object(waiting_service, "_wait_for_completion") as mock_wait:
        mock_wait.return_value = WaitResult(
            status_data={"status": "FINISHED"}, duration=15.0, success=True
        )

        result = waiting_service.wait_for_da("scan456", 8, 3)

        assert isinstance(result, WaitResult)
        assert result.success is True
        assert result.duration == 15.0
        mock_wait.assert_called_once()


def test_wait_for_extract_archives(waiting_service, mock_status_check_service):
    """Test wait_for_extract_archives method."""
    with patch.object(waiting_service, "_wait_for_completion") as mock_wait:
        mock_wait.return_value = WaitResult(
            status_data={"status": "FINISHED"}, duration=10.0, success=True
        )

        result = waiting_service.wait_for_extract_archives("scan789", 5, 2)

        assert isinstance(result, WaitResult)
        assert result.success is True
        assert result.duration == 10.0
        mock_wait.assert_called_once()


def test_wait_for_extract_archives_unsupported(
    waiting_service, mock_status_check_service
):
    """Test wait_for_extract_archives with unsupported status check."""
    mock_status_check_service.check_extract_archives_status.side_effect = (
        UnsupportedStatusCheck("Not supported")
    )

    with patch("time.sleep", return_value=None):
        result = waiting_service.wait_for_extract_archives("scan789", 5, 2)

    assert isinstance(result, WaitResult)
    assert result.success is True
    assert result.duration is None


def test_wait_for_scan_report_completion(
    waiting_service, mock_status_check_service
):
    """Test wait_for_scan_report_completion method."""
    with patch.object(waiting_service, "_wait_for_completion") as mock_wait:
        mock_wait.return_value = WaitResult(
            status_data={"status": "FINISHED"}, duration=25.0, success=True
        )

        result = waiting_service.wait_for_scan_report_completion(
            "scan123", 456, 12, 4
        )

        assert isinstance(result, WaitResult)
        assert result.success is True
        assert result.duration == 25.0
        mock_wait.assert_called_once()


def test_wait_for_project_report_completion(
    waiting_service, mock_status_check_service
):
    """Test wait_for_project_report_completion method."""
    with patch.object(waiting_service, "_wait_for_completion") as mock_wait:
        mock_wait.return_value = WaitResult(
            status_data={"status": "FINISHED"}, duration=30.0, success=True
        )

        result = waiting_service.wait_for_project_report_completion(
            "PROJ123", 789, 15, 5
        )

        assert isinstance(result, WaitResult)
        assert result.success is True
        assert result.duration == 30.0
        mock_wait.assert_called_once()


def test_wait_for_git_clone(waiting_service, mock_status_check_service):
    """Test wait_for_git_clone method."""
    with patch.object(waiting_service, "_wait_for_completion") as mock_wait:
        mock_wait.return_value = WaitResult(
            status_data={"data": "FINISHED"}, duration=12.0, success=True
        )

        result = waiting_service.wait_for_git_clone("scan123", 8, 3)

        assert isinstance(result, WaitResult)
        assert result.success is True
        assert result.duration == 12.0
        mock_wait.assert_called_once()


# --- Test helper methods ---
def test_extract_server_duration_valid(waiting_service):
    """Test server duration extraction when started/finished present."""
    raw = {"started": "2025-08-08 00:00:00", "finished": "2025-08-08 00:00:10"}
    duration = waiting_service._extract_server_duration(raw)
    assert duration == 10.0


def test_extract_server_duration_git_format(waiting_service):
    """Test git format data should return None for duration."""
    raw = {"data": "FINISHED"}
    assert waiting_service._extract_server_duration(raw) is None


def test_extract_server_duration_missing(waiting_service):
    """Test missing timestamps -> None."""
    raw = {"status": "FINISHED"}
    assert waiting_service._extract_server_duration(raw) is None


def test_extract_server_duration_invalid(waiting_service):
    """Test invalid timestamp format -> None."""
    raw = {"started": "invalid", "finished": "invalid"}
    assert waiting_service._extract_server_duration(raw) is None


def test_wait_for_completion_with_server_duration(
    waiting_service, mock_status_check_service, capsys
):
    """Test that server duration is extracted and displayed."""
    running = StatusResult(status="RUNNING", raw_data={"status": "RUNNING"})
    finished = StatusResult(
        status="FINISHED",
        raw_data={
            "status": "FINISHED",
            "started": "2025-08-08 00:00:00",
            "finished": "2025-08-08 00:00:10",
        },
    )
    check_function = MagicMock(side_effect=[running, finished])

    with patch("time.sleep", return_value=None):
        result = waiting_service._wait_for_completion(
            check_function=check_function,
            max_tries=5,
            wait_interval=1,
            operation_name="Test Proc",
        )

    # Duration should be server-side 10s
    assert isinstance(result, WaitResult)
    assert result.duration == 10.0
    assert result.success is True
    out = capsys.readouterr().out
    assert "completed successfully" in out


def test_wait_for_completion_unsupported_operation_returns_success(
    waiting_service, mock_status_check_service
):
    """Test that UnsupportedStatusCheck is re-raised."""

    def raise_unsupported():
        raise UnsupportedStatusCheck("unsupported")

    with patch("time.sleep", return_value=None):
        with pytest.raises(UnsupportedStatusCheck):
            waiting_service._wait_for_completion(
                check_function=raise_unsupported,
                max_tries=3,
                wait_interval=1,
                operation_name="Unsupported Op",
            )


def test_wait_for_completion_retry_on_exception_then_success(
    waiting_service, mock_status_check_service
):
    """Test that generic exceptions are retried and then succeed."""
    running = StatusResult(status="RUNNING", raw_data={"status": "RUNNING"})
    finished = StatusResult(status="FINISHED", raw_data={"status": "FINISHED"})

    call_states = [Exception("transient"), running, finished]

    def side_effect():
        state = call_states.pop(0)
        if isinstance(state, Exception):
            raise state
        return state

    with patch("time.sleep", return_value=None):
        result = waiting_service._wait_for_completion(
            check_function=side_effect,
            max_tries=5,
            wait_interval=1,
            operation_name="Retry Op",
        )

    assert isinstance(result, WaitResult)
    assert result.success is True
