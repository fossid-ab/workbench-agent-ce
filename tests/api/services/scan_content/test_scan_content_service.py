"""Tests for ScanContentService."""

from unittest.mock import MagicMock

import pytest

from workbench_agent.api.services.scan_content_service import ScanContentService
from workbench_agent.api.utils.process_waiter import StatusResult


@pytest.fixture
def scan_content_service():
    scans = MagicMock()
    uploads = MagicMock()
    status_check = MagicMock()
    return ScanContentService(
        scans_client=scans,
        uploads_client=uploads,
        status_check_service=status_check,
    )


def test_remove_uploaded_content_delegates(scan_content_service):
    scan_content_service._scans.remove_uploaded_content.return_value = True
    assert scan_content_service.remove_uploaded_content("S1", ".git/") is True
    scan_content_service._scans.remove_uploaded_content.assert_called_once_with("S1", ".git/")


def test_download_content_from_git_delegates(scan_content_service):
    scan_content_service._scans.download_content_from_git.return_value = True
    assert scan_content_service.download_content_from_git("S1") is True
    scan_content_service._scans.download_content_from_git.assert_called_once_with("S1")


def test_download_git_and_wait_orchestrates(scan_content_service):
    done = StatusResult(
        status="FINISHED",
        raw_data={},
        duration=1.5,
    )
    scan_content_service._status_check.check_git_clone_status.return_value = done
    out = scan_content_service.download_git_and_wait(
        "S1", wait_retry_count=10, wait_retry_interval=3
    )
    assert out is done
    scan_content_service._scans.download_content_from_git.assert_called_once_with("S1")
    scan_content_service._status_check.check_git_clone_status.assert_called_once_with(
        "S1", wait=True, wait_retry_count=10, wait_retry_interval=3
    )


def test_extract_archives_basic(scan_content_service):
    scan_content_service._scans.extract_archives.return_value = True
    result = scan_content_service.extract_archives(
        scan_code="test_scan",
        recursively_extract_archives=True,
        jar_file_extraction=False,
    )
    assert result is True
    call_args = scan_content_service._scans.extract_archives.call_args[0][0]
    assert call_args["scan_code"] == "test_scan"
    assert call_args["recursively_extract_archives"] == "true"
    assert call_args["jar_file_extraction"] == "false"
    assert call_args["extract_to_directory"] == "0"


def test_extract_archives_with_options(scan_content_service):
    scan_content_service._scans.extract_archives.return_value = True
    result = scan_content_service.extract_archives(
        scan_code="another_scan",
        recursively_extract_archives=False,
        jar_file_extraction=True,
        extract_to_directory=True,
        filename="archive.zip",
    )
    assert result is True
    call_args = scan_content_service._scans.extract_archives.call_args[0][0]
    assert call_args["filename"] == "archive.zip"
    assert call_args["extract_to_directory"] == "1"
