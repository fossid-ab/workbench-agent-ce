"""Tests for ScanDeletionService."""

from unittest.mock import MagicMock

import pytest

from workbench_agent.api.exceptions import ApiError, ScanNotFoundError
from workbench_agent.api.services.scan_deletion import ScanDeletionService
from workbench_agent.api.utils.process_waiter import StatusResult


def test_delete_scan_success():
    scans = MagicMock()
    status_check = MagicMock()
    svc = ScanDeletionService(scans, status_check)

    scans.delete.return_value = {
        "status": "1",
        "data": {"process_id": 1001},
    }
    terminal = StatusResult(
        status="FINISHED",
        raw_data={"status": "FINISHED", "is_finished": "1"},
    )
    status_check.check_delete_scan_status.return_value = terminal

    result = svc.delete_scan("scan_a")

    assert result is terminal
    scans.delete.assert_called_once_with(
        "scan_a", delete_identifications=True
    )
    status_check.check_delete_scan_status.assert_called_once_with(
        "scan_a",
        1001,
        wait=True,
        wait_retry_count=360,
        wait_retry_interval=2,
    )


def test_delete_scan_not_found():
    scans = MagicMock()
    scans.delete.side_effect = ApiError(
        "API Error: Classes.TableRepository.row_not_found",
        details={
            "error": "Classes.TableRepository.row_not_found",
            "message_parameters": {
                "rowidentifier": "scan_code",
                "table": "scans",
            },
        },
    )
    svc = ScanDeletionService(scans, MagicMock())

    with pytest.raises(ScanNotFoundError, match="Scan 'missing' not found"):
        svc.delete_scan("missing")
