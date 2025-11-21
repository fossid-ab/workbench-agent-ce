# tests/unit/api/services/test_upload_service.py

from unittest.mock import patch

import pytest

from workbench_agent.api.services.upload_service import UploadService
from workbench_agent.exceptions import FileSystemError


# --- Fixtures ---
@pytest.fixture
def mock_uploads_client(mocker):
    """Create a mock UploadsClient."""
    client = mocker.MagicMock()
    return client


@pytest.fixture
def upload_service(mock_uploads_client):
    """Create an UploadService instance for testing."""
    return UploadService(mock_uploads_client)


# --- Test Cases ---


def test_upload_service_initialization(upload_service, mock_uploads_client):
    """Test that UploadService can be initialized properly."""
    assert upload_service._uploads == mock_uploads_client


@patch("os.path.exists")
def test_upload_scan_target_path_validation(mock_exists, upload_service):
    """Test that upload_scan_target validates path existence."""
    mock_exists.return_value = False

    with pytest.raises(FileSystemError, match="Path does not exist"):
        upload_service.upload_scan_target("scan1", "/nonexistent/path")

    mock_exists.assert_called_once_with("/nonexistent/path")


@patch("os.path.exists")
@patch("os.path.isfile")
def test_upload_da_results_validation(
    mock_isfile, mock_exists, upload_service
):
    """Test that upload_da_results validates file existence."""
    mock_exists.return_value = True
    mock_isfile.return_value = False  # Path exists but is not a file

    with pytest.raises(
        FileSystemError,
        match="Dependency analysis results file does not exist",
    ):
        upload_service.upload_da_results("scan1", "/path/to/directory")

    mock_exists.assert_called_once_with("/path/to/directory")
    mock_isfile.assert_called_once_with("/path/to/directory")


@patch("os.path.exists")
def test_upload_sbom_file_validation(mock_exists, upload_service):
    """Test that upload_sbom_file validates file existence."""
    mock_exists.return_value = False

    with pytest.raises(FileSystemError, match="SBOM file does not exist"):
        upload_service.upload_sbom_file("scan1", "/nonexistent/sbom.json")

    mock_exists.assert_called_once_with("/nonexistent/sbom.json")


@patch("os.path.exists")
@patch("os.path.isfile")
def test_upload_sbom_file_not_a_file(mock_isfile, mock_exists, upload_service):
    """Test that upload_sbom_file validates that path is a file."""
    mock_exists.return_value = True
    mock_isfile.return_value = False  # Path exists but is not a file

    with pytest.raises(FileSystemError, match="SBOM file does not exist"):
        upload_service.upload_sbom_file("scan1", "/path/to/directory")

    mock_exists.assert_called_once_with("/path/to/directory")
    mock_isfile.assert_called_once_with("/path/to/directory")
