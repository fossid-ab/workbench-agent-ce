"""Tests for ScanContentService."""

from unittest.mock import MagicMock

import pytest

from workbench_agent.api.services.scan_content_service import ScanContentService
from workbench_agent.api.utils.process_waiter import StatusResult


@pytest.fixture
def scan_content_service():
    scans = MagicMock()
    status_check = MagicMock()
    return ScanContentService(
        scans_client=scans, status_check_service=status_check
    )


def test_remove_uploaded_content_delegates(scan_content_service):
    scan_content_service._scans.remove_uploaded_content.return_value = True
    assert scan_content_service.remove_uploaded_content("S1", ".git/") is True
    scan_content_service._scans.remove_uploaded_content.assert_called_once_with(
        "S1", ".git/"
    )


def test_download_content_from_git_delegates(scan_content_service):
    scan_content_service._scans.download_content_from_git.return_value = True
    assert scan_content_service.download_content_from_git("S1") is True
    scan_content_service._scans.download_content_from_git.assert_called_once_with(
        "S1"
    )


def test_check_git_clone_status_delegates(scan_content_service):
    done = StatusResult(status="FINISHED", raw_data={})
    scan_content_service._status_check.check_git_clone_status.return_value = (
        done
    )
    out = scan_content_service.check_git_clone_status(
        "S1", wait=True, wait_retry_count=5, wait_retry_interval=2
    )
    assert out is done
    scan_content_service._status_check.check_git_clone_status.assert_called_once_with(
        "S1", wait=True, wait_retry_count=5, wait_retry_interval=2
    )


def test_download_git_and_wait_orchestrates(scan_content_service):
    done = StatusResult(
        status="FINISHED",
        raw_data={},
        duration=1.5,
    )
    scan_content_service._status_check.check_git_clone_status.return_value = (
        done
    )
    out = scan_content_service.download_git_and_wait(
        "S1", wait_retry_count=10, wait_retry_interval=3
    )
    assert out is done
    scan_content_service._scans.download_content_from_git.assert_called_once_with(
        "S1"
    )
    scan_content_service._status_check.check_git_clone_status.assert_called_once_with(
        "S1", wait=True, wait_retry_count=10, wait_retry_interval=3
    )
