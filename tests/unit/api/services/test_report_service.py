# tests/unit/api/services/test_report_service.py

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest
import requests

from workbench_agent.api.services.report_service import ReportService
from workbench_agent.exceptions import FileSystemError, ValidationError


# --- Fixtures ---
@pytest.fixture
def mock_projects_client(mocker):
    """Create a mock ProjectsClient."""
    client = mocker.MagicMock()
    return client


@pytest.fixture
def mock_scans_client(mocker):
    """Create a mock ScansClient."""
    client = mocker.MagicMock()
    return client


@pytest.fixture
def report_service(mock_projects_client, mock_scans_client):
    """Create a ReportService instance for testing."""
    return ReportService(mock_projects_client, mock_scans_client)


# --- Tests for save_report (migrated from _save_report_content) ---
class TestSaveReport:
    """Test cases for the save_report method."""

    def test_save_text_response_success(self, report_service):
        """Test saving a text response successfully."""
        response = MagicMock(spec=requests.Response)
        response.content = b"Test content"
        response.headers = {"content-type": "text/plain"}
        response.encoding = "utf-8"

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                result = report_service.save_report(
                    response, "output_dir", "test_scan", "basic", "scan"
                )
                mock_file.assert_called_once_with(
                    "output_dir/scan-test_scan-basic.txt", "w", encoding="utf-8"
                )
                mock_file().write.assert_called_once_with("Test content")
                assert result == "output_dir/scan-test_scan-basic.txt"

    def test_save_binary_response_success(self, report_service):
        """Test saving a binary response successfully."""
        response = MagicMock(spec=requests.Response)
        response.content = b"\x00\x01\x02\x03"
        response.headers = {"content-type": "application/octet-stream"}

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                result = report_service.save_report(
                    response, "output_dir", "test_scan", "xlsx", "scan"
                )
                mock_file.assert_called_once_with("output_dir/scan-test_scan-xlsx.xlsx", "wb")
                mock_file().write.assert_called_once_with(b"\x00\x01\x02\x03")
                assert result == "output_dir/scan-test_scan-xlsx.xlsx"

    def test_save_dict_success(self, report_service):
        """Test saving a dictionary as JSON successfully."""
        content = {"key": "value", "number": 42}

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                result = report_service.save_report(
                    content, "output_dir", "test_scan", "json", "scan"
                )
                mock_file.assert_called_once_with(
                    "output_dir/scan-test_scan-json.json", "w", encoding="utf-8"
                )
                assert result == "output_dir/scan-test_scan-json.json"

    def test_makedirs_error(self, report_service):
        """Test handling of directory creation errors."""
        response = MagicMock(spec=requests.Response)
        response.content = b"Test content"
        response.headers = {"content-type": "text/plain"}
        response.encoding = "utf-8"

        with patch("os.makedirs", side_effect=OSError("Cannot create directory")):
            with pytest.raises(FileSystemError, match="Could not create output directory"):
                report_service.save_report(response, "output_dir", "test_scan", "basic", "scan")

    def test_file_write_error(self, report_service):
        """Test handling of file write errors."""
        response = MagicMock(spec=requests.Response)
        response.content = b"Test content"
        response.headers = {"content-type": "text/plain"}
        response.encoding = "utf-8"

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                mock_file().write.side_effect = IOError("File write error")
                with pytest.raises(FileSystemError, match="Failed to write report to"):
                    report_service.save_report(response, "output_dir", "test_scan", "basic", "scan")

    def test_save_json_response_success(self, report_service):
        """Test saving a JSON response successfully."""
        response = MagicMock(spec=requests.Response)
        response.content = b'{"key": "value"}'
        response.headers = {"content-type": "application/json"}
        response.encoding = "utf-8"

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                result = report_service.save_report(
                    response, "output_dir", "test_project", "cyclone_dx", "project"
                )
                mock_file.assert_called_once_with(
                    "output_dir/project-test_project-cyclone_dx.json", "w", encoding="utf-8"
                )
                mock_file().write.assert_called_once_with('{"key": "value"}')
                assert result == "output_dir/project-test_project-cyclone_dx.json"

    def test_save_list_success(self, report_service):
        """Test saving a list as JSON successfully."""
        content = ["item1", "item2", {"nested": "object"}]

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                result = report_service.save_report(
                    content, "output_dir", "test_project", "results", "project"
                )
                mock_file.assert_called_once_with(
                    "output_dir/project-test_project-results.json", "w", encoding="utf-8"
                )
                assert result == "output_dir/project-test_project-results.json"

    def test_save_string_success(self, report_service):
        """Test saving a string successfully."""
        content = "This is a test string content"

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                result = report_service.save_report(
                    content, "output_dir", "test_scan", "basic", "scan"
                )
                mock_file.assert_called_once_with(
                    "output_dir/scan-test_scan-basic.txt", "w", encoding="utf-8"
                )
                mock_file().write.assert_called_once_with(content)
                assert result == "output_dir/scan-test_scan-basic.txt"

    def test_save_bytes_success(self, report_service):
        """Test saving bytes successfully."""
        content = b"Binary data content"

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                result = report_service.save_report(
                    content, "output_dir", "test_project", "binary", "project"
                )
                mock_file.assert_called_once_with(
                    "output_dir/project-test_project-binary.bin", "wb"
                )
                mock_file().write.assert_called_once_with(content)
                assert result == "output_dir/project-test_project-binary.bin"

    def test_response_content_read_error(self, report_service):
        """Test handling of response content read errors."""
        response = MagicMock(spec=requests.Response)
        response.headers = {"content-type": "text/plain"}
        response.encoding = "utf-8"

        # Use property descriptor to make content property raise exception
        def _content_prop():
            raise Exception("Content read error")

        type(response).content = property(lambda self: _content_prop())

        with pytest.raises(FileSystemError, match="Failed to read content from response object"):
            report_service.save_report(response, "output_dir", "test_scan", "basic", "scan")

    def test_json_serialization_error(self, report_service):
        """Test handling of JSON serialization errors."""
        # Create a dict with non-serializable content
        content = {"function": lambda x: x}  # Functions are not JSON serializable

        with pytest.raises(
            ValidationError, match="Failed to serialize provided dictionary/list to JSON"
        ):
            report_service.save_report(content, "output_dir", "test_scan", "json", "scan")

    def test_filename_sanitization(self, report_service):
        """Test filename sanitization with special characters."""
        response = MagicMock(spec=requests.Response)
        response.content = b"Test content"
        response.headers = {"content-type": "text/plain"}
        response.encoding = "utf-8"

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                result = report_service.save_report(
                    response, "output_dir", "test/scan:name*", "basic", "scan"
                )
                # Check that filename was sanitized
                mock_file.assert_called_once_with(
                    "output_dir/scan-test_scan_name_-basic.txt", "w", encoding="utf-8"
                )
                assert result == "output_dir/scan-test_scan_name_-basic.txt"

    @pytest.mark.parametrize(
        "report_type,expected_ext",
        [
            ("xlsx", "xlsx"),
            ("spdx", "rdf"),
            ("spdx_lite", "xlsx"),
            ("cyclone_dx", "json"),
            ("html", "html"),
            ("dynamic_top_matched_components", "html"),
            ("string_match", "xlsx"),
            ("basic", "txt"),
            ("unknown_type", "txt"),  # Default case
        ],
    )
    def test_various_report_types(self, report_service, report_type, expected_ext):
        """Test filename extensions for various report types."""
        response = MagicMock(spec=requests.Response)
        response.content = b"Test content"
        response.headers = {"content-type": "application/octet-stream"}

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                result = report_service.save_report(
                    response, "output_dir", "test_scan", report_type, "scan"
                )
                expected_filename = f"output_dir/scan-test_scan-{report_type}.{expected_ext}"
                mock_file.assert_called_once_with(expected_filename, "wb")
                assert result == expected_filename

    def test_validation_error_no_output_dir(self, report_service):
        """Test validation error when output directory is not specified."""
        response = MagicMock(spec=requests.Response)

        with pytest.raises(ValidationError, match="Output directory is not specified"):
            report_service.save_report(response, "", "test_scan", "basic", "scan")

    def test_validation_error_no_name_component(self, report_service):
        """Test validation error when name component is not specified."""
        response = MagicMock(spec=requests.Response)

        with pytest.raises(ValidationError, match="Name component.*is not specified"):
            report_service.save_report(response, "output_dir", "", "basic", "scan")

    def test_validation_error_no_report_type(self, report_service):
        """Test validation error when report type is not specified."""
        response = MagicMock(spec=requests.Response)

        with pytest.raises(ValidationError, match="Report type is not specified"):
            report_service.save_report(response, "output_dir", "test_scan", "", "scan")

    def test_unsupported_content_type(self, report_service):
        """Test validation error for unsupported content types."""
        unsupported_content = 12345  # Integer is not supported

        with pytest.raises(ValidationError, match="Unsupported content type for saving"):
            report_service.save_report(
                unsupported_content, "output_dir", "test_scan", "basic", "scan"
            )

    def test_response_decode_fallback(self, report_service):
        """Test handling of response decode errors with fallback to binary."""
        response = MagicMock(spec=requests.Response)
        response.content = b"Test content with \xff invalid utf-8"
        response.headers = {"content-type": "text/plain"}
        response.encoding = "utf-8"

        # The actual implementation uses errors='replace' which doesn't raise an exception
        # But we can test with invalid binary that would trigger the fallback warning
        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                result = report_service.save_report(
                    response, "output_dir", "test_scan", "basic", "scan"
                )
                # Due to errors='replace', it should still be text mode
                mock_file.assert_called_once_with(
                    "output_dir/scan-test_scan-basic.txt", "w", encoding="utf-8"
                )
                assert result == "output_dir/scan-test_scan-basic.txt"


# --- Tests for build_project_report_payload ---
class TestBuildProjectReportPayload:
    """Test cases for build_project_report_payload method."""

    def test_build_project_report_payload_success(self, report_service):
        """Test building project report payload successfully."""
        result = report_service.build_project_report_payload(
            project_code="TEST_PROJECT", report_type="xlsx", selection_type="all", include_vex=False
        )

        expected = {
            "project_code": "TEST_PROJECT",
            "report_type": "xlsx",
            "async": "1",
            "include_vex": False,
            "selection_type": "all",
        }
        assert result == expected

    def test_build_project_report_payload_invalid_type(self, report_service):
        """Test validation error for invalid project report type."""
        with pytest.raises(
            ValidationError, match="Report type 'html' is not supported for project reports"
        ):
            report_service.build_project_report_payload(
                project_code="TEST_PROJECT", report_type="html"
            )

    def test_build_project_report_payload_with_all_options(self, report_service):
        """Test building project report payload with all optional parameters."""
        result = report_service.build_project_report_payload(
            project_code="TEST_PROJECT",
            report_type="spdx_lite",
            selection_type="custom",
            selection_view="licenses",
            disclaimer="Custom disclaimer text",
            include_vex=True,
            include_dep_det_info=True,
        )

        expected = {
            "project_code": "TEST_PROJECT",
            "report_type": "spdx_lite",
            "async": "1",
            # include_vex is only added for cyclone_dx and xlsx
            "selection_type": "custom",
            "selection_view": "licenses",
            "disclaimer": "Custom disclaimer text",
            "include_dep_det_info": True,
        }
        assert result == expected

    def test_build_project_report_payload_minimal(self, report_service):
        """Test building project report payload with minimal parameters."""
        result = report_service.build_project_report_payload(
            project_code="TEST_PROJECT", report_type="spdx"
        )

        expected = {
            "project_code": "TEST_PROJECT",
            "report_type": "spdx",
            "async": "1",
        }
        assert result == expected


# --- Tests for build_scan_report_payload ---
class TestBuildScanReportPayload:
    """Test cases for build_scan_report_payload method."""

    def test_build_scan_report_payload_with_all_options(self, report_service):
        """Test building scan report payload with all optional parameters."""
        result = report_service.build_scan_report_payload(
            scan_code="TEST_SCAN",
            report_type="spdx",
            selection_type="vulnerabilities",
            selection_view="detailed",
            disclaimer="Scan disclaimer",
            include_vex=False,
        )

        expected = {
            "scan_code": "TEST_SCAN",
            "report_type": "spdx",
            "async": "1",  # spdx is async
            # include_vex is only added for cyclone_dx and xlsx
            "selection_type": "vulnerabilities",
            "selection_view": "detailed",
            "disclaimer": "Scan disclaimer",
        }
        assert result == expected

    @pytest.mark.parametrize(
        "report_type,expected_async",
        [
            ("xlsx", "1"),
            ("spdx", "1"),
            ("spdx_lite", "1"),
            ("cyclone_dx", "1"),
            ("html", "0"),
            ("dynamic_top_matched_components", "0"),
            ("string_match", "0"),
        ],
    )
    def test_scan_report_async_types(self, report_service, report_type, expected_async):
        """Test async/sync behavior for different scan report types."""
        result = report_service.build_scan_report_payload(
            scan_code="TEST_SCAN", report_type=report_type
        )

        assert result["async"] == expected_async
        assert result["scan_code"] == "TEST_SCAN"
        assert result["report_type"] == report_type

    def test_build_scan_report_payload_async(self, report_service):
        """Test building scan report payload for async report types."""
        result = report_service.build_scan_report_payload(
            scan_code="TEST_SCAN",
            report_type="xlsx",
            selection_type="all",
            disclaimer="Test disclaimer",
        )

        expected = {
            "scan_code": "TEST_SCAN",
            "report_type": "xlsx",
            "async": "1",  # xlsx is async
            "include_vex": True,
            "selection_type": "all",
            "disclaimer": "Test disclaimer",
        }
        assert result == expected

    def test_build_scan_report_payload_sync(self, report_service):
        """Test building scan report payload for sync report types."""
        result = report_service.build_scan_report_payload(
            scan_code="TEST_SCAN", report_type="html"  # HTML is sync
        )

        expected = {
            "scan_code": "TEST_SCAN",
            "report_type": "html",
            "async": "0",  # html is sync
            # include_vex is only added for cyclone_dx and xlsx
        }
        assert result == expected


# --- Tests for download_project_report and download_scan_report ---
class TestDownloadReports:
    """Test cases for download_project_report and download_scan_report methods."""

    def test_download_project_report_success(self, report_service, mock_projects_client):
        """Test successful project report download."""
        mock_base_api = MagicMock()
        mock_projects_client._api = mock_base_api

        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.headers = {
            "content-type": "application/pdf",
            "content-disposition": "attachment; filename=report.pdf",
        }
        mock_base_api._send_request.return_value = {"_raw_response": mock_response}

        result = report_service.download_project_report(12345)

        # Verify _send_request was called with correct payload
        mock_base_api._send_request.assert_called_once()
        call_args = mock_base_api._send_request.call_args
        payload = call_args[0][0]
        assert payload["group"] == "download"
        assert payload["action"] == "download_report"
        assert payload["data"]["report_entity"] == "projects"
        assert payload["data"]["process_id"] == "12345"
        assert call_args[1]["timeout"] == 1800

        # The method returns the result from _send_request
        assert result == {"_raw_response": mock_response}

    def test_download_scan_report_success(self, report_service, mock_projects_client):
        """Test successful scan report download."""
        mock_base_api = MagicMock()
        mock_projects_client._api = mock_base_api

        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.headers = {
            "content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "content-disposition": 'attachment; filename="scan_report.xlsx"',
        }
        mock_base_api._send_request.return_value = {"_raw_response": mock_response}

        result = report_service.download_scan_report(54321)

        # Verify _send_request was called with correct payload
        mock_base_api._send_request.assert_called_once()
        call_args = mock_base_api._send_request.call_args
        payload = call_args[0][0]
        assert payload["group"] == "download"
        assert payload["action"] == "download_report"
        assert payload["data"]["report_entity"] == "scans"
        assert payload["data"]["process_id"] == "54321"
        assert call_args[1]["timeout"] == 1800

        # The method returns the result from _send_request
        assert result == {"_raw_response": mock_response}

    def test_download_project_report_api_error(self, report_service, mock_projects_client):
        """Test download when API returns error."""
        from workbench_agent.api.exceptions import ApiError

        mock_base_api = MagicMock()
        mock_projects_client._api = mock_base_api
        mock_base_api._send_request.side_effect = ApiError("Report not found")

        with pytest.raises(ApiError, match="Report not found"):
            report_service.download_project_report(12345)

    def test_download_scan_report_api_error(self, report_service, mock_projects_client):
        """Test download when API returns error."""
        from workbench_agent.api.exceptions import ApiError

        mock_base_api = MagicMock()
        mock_projects_client._api = mock_base_api
        mock_base_api._send_request.side_effect = ApiError("Report not found")

        with pytest.raises(ApiError, match="Report not found"):
            report_service.download_scan_report(54321)

    def test_download_project_report_network_error(self, report_service, mock_projects_client):
        """Test download when network request fails."""
        from workbench_agent.api.exceptions import NetworkError

        mock_base_api = MagicMock()
        mock_projects_client._api = mock_base_api
        mock_base_api._send_request.side_effect = NetworkError("Connection failed")

        with pytest.raises(NetworkError, match="Connection failed"):
            report_service.download_project_report(12345)

    def test_download_scan_report_network_error(self, report_service, mock_projects_client):
        """Test download when network request fails."""
        from workbench_agent.api.exceptions import NetworkError

        mock_base_api = MagicMock()
        mock_projects_client._api = mock_base_api
        mock_base_api._send_request.side_effect = NetworkError("Connection failed")

        with pytest.raises(NetworkError, match="Connection failed"):
            report_service.download_scan_report(54321)

    def test_download_project_report_with_content_disposition(
        self, report_service, mock_projects_client
    ):
        """Test download with proper content-disposition header."""
        mock_base_api = MagicMock()
        mock_projects_client._api = mock_base_api

        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.headers = {
            "content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "content-disposition": 'attachment; filename="project_report.xlsx"',
        }
        mock_base_api._send_request.return_value = {"_raw_response": mock_response}

        result = report_service.download_project_report(54321)

        assert result == {"_raw_response": mock_response}
        mock_base_api._send_request.assert_called_once()

    def test_download_scan_report_without_content_disposition_but_binary_type(
        self, report_service, mock_projects_client
    ):
        """Test download with binary content type but no content-disposition."""
        mock_base_api = MagicMock()
        mock_projects_client._api = mock_base_api

        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/octet-stream"}
        mock_base_api._send_request.return_value = {"_raw_response": mock_response}

        result = report_service.download_scan_report(12345)

        assert result == {"_raw_response": mock_response}
        mock_base_api._send_request.assert_called_once()
