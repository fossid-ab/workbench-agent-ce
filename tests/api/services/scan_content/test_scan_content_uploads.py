"""Upload validation tests for ScanContentService."""

from unittest.mock import MagicMock, patch

import pytest

from workbench_agent.api.services.scan_content_service import ScanContentService
from workbench_agent.exceptions import FileSystemError


@pytest.fixture
def mock_uploads_client():
    return MagicMock()


@pytest.fixture
def scan_content_with_uploads(mock_uploads_client):
    return ScanContentService(
        scans_client=MagicMock(),
        uploads_client=mock_uploads_client,
        status_check_service=MagicMock(),
    )


def test_scan_content_stores_uploads_client(
    scan_content_with_uploads, mock_uploads_client
):
    assert scan_content_with_uploads._uploads is mock_uploads_client


@patch("os.path.exists")
def test_upload_scan_target_path_validation(mock_exists, scan_content_with_uploads):
    mock_exists.return_value = False
    with pytest.raises(
        FileSystemError, match="Scan target file does not exist"
    ):
        scan_content_with_uploads.upload_scan_target(
            "scan1", "/nonexistent/path"
        )


@patch("os.path.exists")
@patch("os.path.isfile")
def test_upload_scan_target_rejects_directory(
    mock_isfile, mock_exists, scan_content_with_uploads
):
    mock_exists.return_value = True
    mock_isfile.return_value = False
    with pytest.raises(
        FileSystemError, match="Scan target file does not exist"
    ):
        scan_content_with_uploads.upload_scan_target(
            "scan1", "/path/to/directory"
        )


@patch("os.path.exists")
@patch("os.path.isfile")
def test_upload_da_results_validation(
    mock_isfile, mock_exists, scan_content_with_uploads
):
    mock_exists.return_value = True
    mock_isfile.return_value = False
    with pytest.raises(
        FileSystemError,
        match="Dependency analysis results file does not exist",
    ):
        scan_content_with_uploads.upload_da_results(
            "scan1", "/path/to/directory"
        )


@patch("os.path.exists")
def test_upload_sbom_file_validation(mock_exists, scan_content_with_uploads):
    mock_exists.return_value = False
    with pytest.raises(FileSystemError, match="SBOM file does not exist"):
        scan_content_with_uploads.upload_sbom_file(
            "scan1", "/nonexistent/sbom.json"
        )


@patch("os.path.exists")
@patch("os.path.isfile")
def test_upload_sbom_file_not_a_file(
    mock_isfile, mock_exists, scan_content_with_uploads
):
    mock_exists.return_value = True
    mock_isfile.return_value = False
    with pytest.raises(FileSystemError, match="SBOM file does not exist"):
        scan_content_with_uploads.upload_sbom_file(
            "scan1", "/path/to/directory"
        )
