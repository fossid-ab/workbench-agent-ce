# tests/unit/api/utils/test_process_waiter.py

from unittest.mock import MagicMock

import pytest

from workbench_agent.api.exceptions import (
    ProcessError,
    ProcessTimeoutError,
    UnsupportedStatusCheck,
)
from workbench_agent.api.utils.process_waiter import (
    StatusResult,
    extract_server_duration,
    wait_for_completion,
)


# --- Test StatusResult with six-state model ---


def test_status_result_new_state():
    """Test NEW state normalization."""
    result = StatusResult(status="NEW", raw_data={})
    assert result.status == "NEW"
    assert result.is_idle is True
    assert result.is_active is False
    assert result.is_terminal is False
    assert result.is_finished is False
    assert result.is_failed is False
    assert result.success is True


def test_status_result_queued_state():
    """Test QUEUED state normalization."""
    result = StatusResult(status="QUEUED", raw_data={})
    assert result.status == "QUEUED"
    assert result.is_idle is False
    assert result.is_active is True
    assert result.is_terminal is False
    assert result.success is True


def test_status_result_running_state():
    """Test RUNNING state normalization."""
    result = StatusResult(status="RUNNING", raw_data={})
    assert result.status == "RUNNING"
    assert result.is_active is True
    assert result.is_terminal is False
    assert result.success is True


def test_status_result_finished_state():
    """Test FINISHED state normalization."""
    result = StatusResult(status="FINISHED", raw_data={})
    assert result.status == "FINISHED"
    assert result.is_terminal is True
    assert result.is_idle is True
    assert result.is_finished is True
    assert result.is_failed is False
    assert result.success is True


def test_status_result_failed_state():
    """Test FAILED state normalization."""
    result = StatusResult(
        status="FAILED", raw_data={"error": "Something went wrong"}
    )
    assert result.status == "FAILED"
    assert result.is_terminal is True
    assert result.is_idle is True
    assert result.is_finished is True
    assert result.is_failed is True
    assert result.success is False
    assert result.error_message == "Something went wrong"


def test_status_result_cancelled_state():
    """Test CANCELLED state normalization."""
    result = StatusResult(status="CANCELLED", raw_data={})
    assert result.status == "CANCELLED"
    assert result.is_terminal is True
    assert result.is_idle is True
    assert result.is_finished is True
    assert result.is_failed is True
    assert result.success is False


def test_status_result_normalizes_variants():
    """Test normalization of status variants."""
    # IN_PROGRESS → RUNNING
    result = StatusResult(status="IN_PROGRESS", raw_data={})
    assert result.status == "RUNNING"

    # PENDING → QUEUED
    result = StatusResult(status="PENDING", raw_data={})
    assert result.status == "QUEUED"

    # ERROR → FAILED
    result = StatusResult(status="ERROR", raw_data={})
    assert result.status == "FAILED"

    # COMPLETE → FINISHED
    result = StatusResult(status="COMPLETE", raw_data={})
    assert result.status == "FINISHED"


def test_status_result_with_duration():
    """Test StatusResult with duration populated (after waiting)."""
    result = StatusResult(
        status="FINISHED", raw_data={"status": "FINISHED"}, duration=45.2
    )
    assert result.status == "FINISHED"
    assert result.duration == 45.2
    assert result.success is True


# --- Test extract_server_duration function ---


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


def test_extract_server_duration_not_dict():
    """Test non-dict input -> None."""
    assert extract_server_duration("not a dict") is None
    assert extract_server_duration(None) is None


# --- Test wait_for_completion function ---


def test_wait_for_completion_success():
    """Test wait_for_completion with successful operation."""
    mock_check = MagicMock(
        side_effect=[
            StatusResult(status="RUNNING", raw_data={"state": "RUNNING"}),
            StatusResult(status="RUNNING", raw_data={"state": "RUNNING"}),
            StatusResult(
                status="FINISHED",
                raw_data={
                    "state": "FINISHED",
                    "started": "2025-08-08 00:00:00",
                    "finished": "2025-08-08 00:00:10",
                },
            ),
        ]
    )

    result = wait_for_completion(
        check_function=mock_check,
        max_tries=10,
        wait_interval=0.01,
        operation_name="Test Operation",
    )

    assert isinstance(result, StatusResult)
    assert result.status == "FINISHED"
    assert result.success is True
    assert result.duration == 10.0
    assert mock_check.call_count == 3


def test_wait_for_completion_failure():
    """Test wait_for_completion with failed operation."""
    mock_check = MagicMock(
        side_effect=[
            StatusResult(status="RUNNING", raw_data={}),
            StatusResult(
                status="FAILED",
                raw_data={"error": "Operation failed", "info": "Test error"},
            ),
        ]
    )

    result = wait_for_completion(
        check_function=mock_check,
        max_tries=10,
        wait_interval=0.01,
        operation_name="Test Operation",
    )

    assert result.status == "FAILED"
    assert result.success is False
    assert result.error_message == "Operation failed"


def test_wait_for_completion_timeout():
    """Test wait_for_completion timeout."""
    mock_check = MagicMock(
        return_value=StatusResult(status="RUNNING", raw_data={})
    )

    with pytest.raises(ProcessTimeoutError) as exc_info:
        wait_for_completion(
            check_function=mock_check,
            max_tries=3,
            wait_interval=0.01,
            operation_name="Test Operation",
        )

    assert "did not complete within" in str(exc_info.value)
    assert mock_check.call_count == 3


def test_wait_for_completion_cancelled():
    """Test wait_for_completion with cancelled operation."""
    mock_check = MagicMock(
        side_effect=[
            StatusResult(status="QUEUED", raw_data={}),
            StatusResult(
                status="CANCELLED", raw_data={"info": "User cancelled"}
            ),
        ]
    )

    result = wait_for_completion(
        check_function=mock_check,
        max_tries=10,
        wait_interval=0.01,
        operation_name="Test Operation",
    )

    assert result.status == "CANCELLED"
    assert result.success is False
    assert result.is_failed is True


def test_wait_for_completion_unsupported_status_check():
    """Test wait_for_completion re-raises UnsupportedStatusCheck."""
    mock_check = MagicMock(
        side_effect=UnsupportedStatusCheck("Not supported")
    )

    with pytest.raises(UnsupportedStatusCheck):
        wait_for_completion(
            check_function=mock_check,
            max_tries=10,
            wait_interval=0.01,
            operation_name="Test Operation",
        )


def test_wait_for_completion_with_progress_callback():
    """Test wait_for_completion with custom progress callback."""
    mock_check = MagicMock(
        side_effect=[
            StatusResult(status="RUNNING", raw_data={}),
            StatusResult(status="FINISHED", raw_data={}),
        ]
    )

    callback_calls = []

    def progress_callback(status_result, attempt, max_tries):
        callback_calls.append((status_result.status, attempt, max_tries))

    result = wait_for_completion(
        check_function=mock_check,
        max_tries=10,
        wait_interval=0.01,
        operation_name="Test Operation",
        progress_callback=progress_callback,
    )

    assert result.status == "FINISHED"
    assert len(callback_calls) == 2
    assert callback_calls[0] == ("RUNNING", 1, 10)
    assert callback_calls[1] == ("FINISHED", 2, 10)


def test_wait_for_completion_exception_retry():
    """Test wait_for_completion retries on exception."""
    mock_check = MagicMock(
        side_effect=[
            Exception("Temporary error"),
            StatusResult(status="FINISHED", raw_data={}),
        ]
    )

    result = wait_for_completion(
        check_function=mock_check,
        max_tries=10,
        wait_interval=0.01,
        operation_name="Test Operation",
    )

    assert result.status == "FINISHED"
    assert mock_check.call_count == 2


def test_wait_for_completion_exception_max_tries():
    """Test wait_for_completion raises ProcessError after max retries."""
    mock_check = MagicMock(side_effect=Exception("Persistent error"))

    with pytest.raises(ProcessError) as exc_info:
        wait_for_completion(
            check_function=mock_check,
            max_tries=3,
            wait_interval=0.01,
            operation_name="Test Operation",
        )

    assert "Failed to check" in str(exc_info.value)
    assert mock_check.call_count == 3
