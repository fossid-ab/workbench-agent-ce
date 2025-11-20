# tests/unit/api/services/test_scan_operations_service.py

from unittest.mock import MagicMock, patch

import pytest

from workbench_agent.api.services.scan_operations_service import ScanOperationsService
from workbench_agent.api.exceptions import ApiError, ScanNotFoundError


# --- Fixtures ---
@pytest.fixture
def mock_scans_client(mocker):
    """Create a mock ScansClient."""
    client = mocker.MagicMock()
    return client


@pytest.fixture
def mock_resolver_service(mocker):
    """Create a mock ResolverService."""
    service = mocker.MagicMock()
    return service


@pytest.fixture
def scan_operations_service(mock_scans_client, mock_resolver_service):
    """Create a ScanOperationsService instance for testing."""
    return ScanOperationsService(mock_scans_client, mock_resolver_service)


# --- Test start_scan ---
def test_start_scan_basic(scan_operations_service, mock_scans_client):
    """Test starting a basic scan."""
    mock_scans_client.run.return_value = None

    scan_operations_service.start_scan(
        scan_code="test_scan",
        limit=100,
        sensitivity=80,
        autoid_file_licenses=True,
        autoid_file_copyrights=False,
        autoid_pending_ids=True,
        delta_scan=False,
    )

    # Verify the payload was built correctly
    mock_scans_client.run.assert_called_once()
    call_args = mock_scans_client.run.call_args[0][0]
    assert call_args["scan_code"] == "test_scan"
    assert call_args["limit"] == "100"
    assert call_args["sensitivity"] == "80"
    assert call_args["auto_identification_detect_declaration"] == "1"
    assert call_args["auto_identification_detect_copyright"] == "0"
    assert call_args["auto_identification_resolve_pending_ids"] == "1"
    assert call_args["delta_only"] == "0"
    assert call_args["replace_existing_identifications"] == "0"
    assert call_args["scan_failed_only"] == "0"
    assert call_args["full_file_only"] == "0"
    assert call_args["advanced_match_scoring"] == "1"


def test_start_scan_with_optional_params(scan_operations_service, mock_scans_client):
    """Test starting a scan with optional parameters."""
    mock_scans_client.run.return_value = None

    scan_operations_service.start_scan(
        scan_code="test_scan",
        limit=50,
        sensitivity=90,
        autoid_file_licenses=True,
        autoid_file_copyrights=True,
        autoid_pending_ids=False,
        delta_scan=True,
        id_reuse_type="any",
        id_reuse_specific_code=None,
        run_dependency_analysis=True,
        replace_existing_identifications=True,
        scan_failed_only=True,
        full_file_only=True,
        advanced_match_scoring=False,
        match_filtering_threshold=100,
    )

    call_args = mock_scans_client.run.call_args[0][0]
    assert call_args["reuse_identification"] == "1"
    assert call_args["identification_reuse_type"] == "any"
    assert call_args["run_dependency_analysis"] == "1"
    assert call_args["replace_existing_identifications"] == "1"
    assert call_args["scan_failed_only"] == "1"
    assert call_args["full_file_only"] == "1"
    assert call_args["advanced_match_scoring"] == "0"
    assert call_args["match_filtering_threshold"] == "100"


def test_start_scan_with_specific_id_reuse(scan_operations_service, mock_scans_client):
    """Test starting a scan with specific ID reuse."""
    mock_scans_client.run.return_value = None

    scan_operations_service.start_scan(
        scan_code="test_scan",
        limit=100,
        sensitivity=80,
        autoid_file_licenses=True,
        autoid_file_copyrights=False,
        autoid_pending_ids=True,
        delta_scan=False,
        id_reuse_type="specific_project",
        id_reuse_specific_code="PROJ123",
    )

    call_args = mock_scans_client.run.call_args[0][0]
    assert call_args["reuse_identification"] == "1"
    assert call_args["identification_reuse_type"] == "specific_project"
    assert call_args["specific_code"] == "PROJ123"


# --- Test start_archive_extraction ---
def test_start_archive_extraction_basic(scan_operations_service, mock_scans_client):
    """Test starting archive extraction with basic parameters."""
    mock_scans_client.extract_archives.return_value = True

    result = scan_operations_service.start_archive_extraction(
        scan_code="test_scan", recursively_extract_archives=True, jar_file_extraction=False
    )

    assert result is True
    mock_scans_client.extract_archives.assert_called_once()
    call_args = mock_scans_client.extract_archives.call_args[0][0]
    assert call_args["scan_code"] == "test_scan"
    assert call_args["recursively_extract_archives"] == "true"
    assert call_args["jar_file_extraction"] == "false"
    assert call_args["extract_to_directory"] == "0"


def test_start_archive_extraction_with_options(scan_operations_service, mock_scans_client):
    """Test starting archive extraction with different options."""
    mock_scans_client.extract_archives.return_value = True

    result = scan_operations_service.start_archive_extraction(
        scan_code="another_scan",
        recursively_extract_archives=False,
        jar_file_extraction=True,
        extract_to_directory=True,
        filename="archive.zip",
    )

    assert result is True
    call_args = mock_scans_client.extract_archives.call_args[0][0]
    assert call_args["scan_code"] == "another_scan"
    assert call_args["recursively_extract_archives"] == "false"
    assert call_args["jar_file_extraction"] == "true"
    assert call_args["extract_to_directory"] == "1"
    assert call_args["filename"] == "archive.zip"


# --- Test DA methods ---
def test_start_da_only(scan_operations_service, mock_scans_client):
    """Test start_da_only method."""
    mock_scans_client.run_dependency_analysis.return_value = None

    scan_operations_service.start_da_only("test_scan")

    mock_scans_client.run_dependency_analysis.assert_called_once()
    call_args = mock_scans_client.run_dependency_analysis.call_args[0][0]
    assert call_args["scan_code"] == "test_scan"
    assert call_args["import_only"] == "0"


def test_start_da_import(scan_operations_service, mock_scans_client):
    """Test start_da_import method."""
    mock_scans_client.run_dependency_analysis.return_value = None

    scan_operations_service.start_da_import("test_scan")

    mock_scans_client.run_dependency_analysis.assert_called_once()
    call_args = mock_scans_client.run_dependency_analysis.call_args[0][0]
    assert call_args["scan_code"] == "test_scan"
    assert call_args["import_only"] == "1"


def test_start_sbom_import(scan_operations_service, mock_scans_client):
    """Test start_sbom_import method."""
    mock_scans_client.import_report.return_value = None

    scan_operations_service.start_sbom_import("test_scan")

    mock_scans_client.import_report.assert_called_once_with("test_scan")
