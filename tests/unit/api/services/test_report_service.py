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
def mock_downloads_client(mocker):
    """Create a mock DownloadClient."""
    client = mocker.MagicMock()
    return client


@pytest.fixture
def report_service(
    mock_projects_client, mock_scans_client, mock_downloads_client
):
    """Create a ReportService instance for testing."""
    return ReportService(
        mock_projects_client, mock_scans_client, mock_downloads_client
    )


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
                    "output_dir/scan-test_scan-basic.txt",
                    "w",
                    encoding="utf-8",
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
                mock_file.assert_called_once_with(
                    "output_dir/scan-test_scan-xlsx.xlsx", "wb"
                )
                mock_file().write.assert_called_once_with(
                    b"\x00\x01\x02\x03"
                )
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
                    "output_dir/scan-test_scan-json.json",
                    "w",
                    encoding="utf-8",
                )
                assert result == "output_dir/scan-test_scan-json.json"

    def test_makedirs_error(self, report_service):
        """Test handling of directory creation errors."""
        response = MagicMock(spec=requests.Response)
        response.content = b"Test content"
        response.headers = {"content-type": "text/plain"}
        response.encoding = "utf-8"

        with patch(
            "os.makedirs", side_effect=OSError("Cannot create directory")
        ):
            with pytest.raises(
                FileSystemError, match="Could not create output directory"
            ):
                report_service.save_report(
                    response, "output_dir", "test_scan", "basic", "scan"
                )

    def test_file_write_error(self, report_service):
        """Test handling of file write errors."""
        response = MagicMock(spec=requests.Response)
        response.content = b"Test content"
        response.headers = {"content-type": "text/plain"}
        response.encoding = "utf-8"

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                mock_file().write.side_effect = IOError("File write error")
                with pytest.raises(
                    FileSystemError, match="Failed to write report to"
                ):
                    report_service.save_report(
                        response,
                        "output_dir",
                        "test_scan",
                        "basic",
                        "scan",
                    )

    def test_save_json_response_success(self, report_service):
        """Test saving a JSON response successfully."""
        response = MagicMock(spec=requests.Response)
        response.content = b'{"key": "value"}'
        response.headers = {"content-type": "application/json"}
        response.encoding = "utf-8"

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                result = report_service.save_report(
                    response,
                    "output_dir",
                    "test_project",
                    "cyclone_dx",
                    "project",
                )
                mock_file.assert_called_once_with(
                    "output_dir/project-test_project-cyclone_dx.json",
                    "w",
                    encoding="utf-8",
                )
                mock_file().write.assert_called_once_with(
                    '{"key": "value"}'
                )
                assert (
                    result
                    == "output_dir/project-test_project-cyclone_dx.json"
                )

    def test_save_list_success(self, report_service):
        """Test saving a list as JSON successfully."""
        content = ["item1", "item2", {"nested": "object"}]

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                result = report_service.save_report(
                    content,
                    "output_dir",
                    "test_project",
                    "results",
                    "project",
                )
                mock_file.assert_called_once_with(
                    "output_dir/project-test_project-results.json",
                    "w",
                    encoding="utf-8",
                )
                assert (
                    result
                    == "output_dir/project-test_project-results.json"
                )

    def test_save_string_success(self, report_service):
        """Test saving a string successfully."""
        content = "This is a test string content"

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                result = report_service.save_report(
                    content, "output_dir", "test_scan", "basic", "scan"
                )
                mock_file.assert_called_once_with(
                    "output_dir/scan-test_scan-basic.txt",
                    "w",
                    encoding="utf-8",
                )
                mock_file().write.assert_called_once_with(content)
                assert result == "output_dir/scan-test_scan-basic.txt"

    def test_save_bytes_success(self, report_service):
        """Test saving bytes successfully."""
        content = b"Binary data content"

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                result = report_service.save_report(
                    content,
                    "output_dir",
                    "test_project",
                    "binary",
                    "project",
                )
                mock_file.assert_called_once_with(
                    "output_dir/project-test_project-binary.bin", "wb"
                )
                mock_file().write.assert_called_once_with(content)
                assert (
                    result == "output_dir/project-test_project-binary.bin"
                )

    def test_response_content_read_error(self, report_service):
        """Test handling of response content read errors."""
        response = MagicMock(spec=requests.Response)
        response.headers = {"content-type": "text/plain"}
        response.encoding = "utf-8"

        # Use property descriptor to make content property raise exception
        def _content_prop():
            raise Exception("Content read error")

        type(response).content = property(lambda self: _content_prop())

        with pytest.raises(
            FileSystemError,
            match="Failed to read content from response object",
        ):
            report_service.save_report(
                response, "output_dir", "test_scan", "basic", "scan"
            )

    def test_json_serialization_error(self, report_service):
        """Test handling of JSON serialization errors."""
        # Create a dict with non-serializable content
        content = {
            "function": lambda x: x
        }  # Functions are not JSON serializable

        with pytest.raises(
            ValidationError,
            match="Failed to serialize provided dictionary/list to JSON",
        ):
            report_service.save_report(
                content, "output_dir", "test_scan", "json", "scan"
            )

    def test_filename_sanitization(self, report_service):
        """Test filename sanitization with special characters."""
        response = MagicMock(spec=requests.Response)
        response.content = b"Test content"
        response.headers = {"content-type": "text/plain"}
        response.encoding = "utf-8"

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                result = report_service.save_report(
                    response,
                    "output_dir",
                    "test/scan:name*",
                    "basic",
                    "scan",
                )
                # Check that filename was sanitized
                mock_file.assert_called_once_with(
                    "output_dir/scan-test_scan_name_-basic.txt",
                    "w",
                    encoding="utf-8",
                )
                assert (
                    result == "output_dir/scan-test_scan_name_-basic.txt"
                )

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
    def test_various_report_types(
        self, report_service, report_type, expected_ext
    ):
        """Test filename extensions for various report types."""
        response = MagicMock(spec=requests.Response)
        response.content = b"Test content"
        response.headers = {"content-type": "application/octet-stream"}

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.makedirs"):
                result = report_service.save_report(
                    response,
                    "output_dir",
                    "test_scan",
                    report_type,
                    "scan",
                )
                expected_filename = f"output_dir/scan-test_scan-{report_type}.{expected_ext}"
                mock_file.assert_called_once_with(expected_filename, "wb")
                assert result == expected_filename

    def test_validation_error_no_output_dir(self, report_service):
        """Test validation error when output directory is not specified."""
        response = MagicMock(spec=requests.Response)

        with pytest.raises(
            ValidationError, match="Output directory is not specified"
        ):
            report_service.save_report(
                response, "", "test_scan", "basic", "scan"
            )

    def test_validation_error_no_name_component(self, report_service):
        """Test validation error when name component is not specified."""
        response = MagicMock(spec=requests.Response)

        with pytest.raises(
            ValidationError, match="Name component.*is not specified"
        ):
            report_service.save_report(
                response, "output_dir", "", "basic", "scan"
            )

    def test_validation_error_no_report_type(self, report_service):
        """Test validation error when report type is not specified."""
        response = MagicMock(spec=requests.Response)

        with pytest.raises(
            ValidationError, match="Report type is not specified"
        ):
            report_service.save_report(
                response, "output_dir", "test_scan", "", "scan"
            )

    def test_unsupported_content_type(self, report_service):
        """Test validation error for unsupported content types."""
        unsupported_content = 12345  # Integer is not supported

        with pytest.raises(
            ValidationError, match="Unsupported content type for saving"
        ):
            report_service.save_report(
                unsupported_content,
                "output_dir",
                "test_scan",
                "basic",
                "scan",
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
                    "output_dir/scan-test_scan-basic.txt",
                    "w",
                    encoding="utf-8",
                )
                assert result == "output_dir/scan-test_scan-basic.txt"


# --- Tests for build_project_report_payload ---
class TestBuildProjectReportPayload:
    """Test cases for build_project_report_payload method."""

    def test_build_project_report_payload_success(self, report_service):
        """Test building project report payload successfully."""
        result = report_service.build_project_report_payload(
            project_code="TEST_PROJECT",
            report_type="xlsx",
            selection_type="all",
            include_vex=False,
        )

        expected = {
            "project_code": "TEST_PROJECT",
            "report_type": "xlsx",
            "async": "1",
            "include_vex": False,
            "selection_type": "all",
        }
        assert result == expected

    def test_build_project_report_payload_invalid_type(
        self, report_service
    ):
        """Test validation error for invalid project report type."""
        with pytest.raises(
            ValidationError,
            match="Report type 'html' is not supported for project reports",
        ):
            report_service.build_project_report_payload(
                project_code="TEST_PROJECT", report_type="html"
            )

    def test_build_project_report_payload_with_all_options(
        self, report_service
    ):
        """Test building project report payload with all optional parameters."""
        # Use xlsx which supports all parameters
        result = report_service.build_project_report_payload(
            project_code="TEST_PROJECT",
            report_type="xlsx",
            selection_type="custom",
            selection_view="licenses",
            include_vex=True,
            include_dep_det_info=True,
            report_content_type="abbreviated",
        )

        expected = {
            "project_code": "TEST_PROJECT",
            "report_type": "xlsx",
            "async": "1",
            "selection_type": "custom",
            "selection_view": "licenses",
            "include_vex": True,
            "include_dep_det_info": True,
            "report_content_type": "abbreviated",
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

    def test_build_scan_report_payload_with_all_options(
        self, report_service
    ):
        """Test building scan report payload with all optional parameters."""
        # Use xlsx which supports most parameters
        result = report_service.build_scan_report_payload(
            scan_code="TEST_SCAN",
            report_type="xlsx",
            selection_type="vulnerabilities",
            selection_view="detailed",
            include_vex=False,
            include_dep_det_info=True,
            report_content_type="abbreviated",
        )

        expected = {
            "scan_code": "TEST_SCAN",
            "report_type": "xlsx",
            "async": "1",
            "selection_type": "vulnerabilities",
            "selection_view": "detailed",
            "include_vex": False,
            "include_dep_det_info": True,
            "report_content_type": "abbreviated",
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
    def test_scan_report_async_types(
        self, report_service, report_type, expected_async
    ):
        """Test async/sync behavior for different scan report types."""
        result = report_service.build_scan_report_payload(
            scan_code="TEST_SCAN", report_type=report_type
        )

        assert result["async"] == expected_async
        assert result["scan_code"] == "TEST_SCAN"
        assert result["report_type"] == report_type

    def test_build_scan_report_payload_async(self, report_service):
        """Test building scan report payload for async report types."""
        # Use html which supports disclaimer
        result = report_service.build_scan_report_payload(
            scan_code="TEST_SCAN",
            report_type="html",
            selection_type="all",
            disclaimer="Test disclaimer",
        )

        expected = {
            "scan_code": "TEST_SCAN",
            "report_type": "html",
            "async": "0",  # html is sync by default
            "include_vex": True,  # html supports vex
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
            "include_vex": True,  # html supports vex
        }
        assert result == expected


# --- Tests for download_project_report and download_scan_report ---
class TestDownloadReports:
    """Test cases for download_project_report and download_scan_report methods."""

    def test_download_project_report_success(
        self, report_service, mock_downloads_client
    ):
        """Test successful project report download."""
        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.headers = {
            "content-type": "application/pdf",
            "content-disposition": "attachment; filename=report.pdf",
        }
        mock_downloads_client.download_report.return_value = {
            "_raw_response": mock_response
        }

        result = report_service.download_project_report(12345)

        # Verify download_report was called with correct entity
        mock_downloads_client.download_report.assert_called_once_with(
            "projects", 12345
        )

        # The method returns the result from downloads client
        assert result == {"_raw_response": mock_response}

    def test_download_scan_report_success(
        self, report_service, mock_downloads_client
    ):
        """Test successful scan report download."""
        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.headers = {
            "content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "content-disposition": 'attachment; filename="scan_report.xlsx"',
        }
        mock_downloads_client.download_report.return_value = {
            "_raw_response": mock_response
        }

        result = report_service.download_scan_report(54321)

        # Verify download_report was called with correct entity
        mock_downloads_client.download_report.assert_called_once_with(
            "scans", 54321
        )

        # The method returns the result from downloads client
        assert result == {"_raw_response": mock_response}

    def test_download_project_report_api_error(
        self, report_service, mock_downloads_client
    ):
        """Test download when API returns error."""
        from workbench_agent.api.exceptions import ApiError

        mock_downloads_client.download_report.side_effect = ApiError(
            "Report not found"
        )

        with pytest.raises(ApiError, match="Report not found"):
            report_service.download_project_report(12345)

    def test_download_scan_report_api_error(
        self, report_service, mock_downloads_client
    ):
        """Test download when API returns error."""
        from workbench_agent.api.exceptions import ApiError

        mock_downloads_client.download_report.side_effect = ApiError(
            "Report not found"
        )

        with pytest.raises(ApiError, match="Report not found"):
            report_service.download_scan_report(54321)

    def test_download_project_report_network_error(
        self, report_service, mock_downloads_client
    ):
        """Test download when network request fails."""
        from workbench_agent.api.exceptions import NetworkError

        mock_downloads_client.download_report.side_effect = NetworkError(
            "Connection failed"
        )

        with pytest.raises(NetworkError, match="Connection failed"):
            report_service.download_project_report(12345)

    def test_download_scan_report_network_error(
        self, report_service, mock_downloads_client
    ):
        """Test download when network request fails."""
        from workbench_agent.api.exceptions import NetworkError

        mock_downloads_client.download_report.side_effect = NetworkError(
            "Connection failed"
        )

        with pytest.raises(NetworkError, match="Connection failed"):
            report_service.download_scan_report(54321)

    def test_download_project_report_with_content_disposition(
        self, report_service, mock_downloads_client
    ):
        """Test download with proper content-disposition header."""
        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.headers = {
            "content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "content-disposition": 'attachment; filename="project_report.xlsx"',
        }
        mock_downloads_client.download_report.return_value = {
            "_raw_response": mock_response
        }

        result = report_service.download_project_report(54321)

        assert result == {"_raw_response": mock_response}
        mock_downloads_client.download_report.assert_called_once_with(
            "projects", 54321
        )

    def test_download_scan_report_without_content_disposition_but_binary_type(
        self, report_service, mock_downloads_client
    ):
        """Test download with binary content type but no content-disposition."""
        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.headers = {
            "content-type": "application/octet-stream"
        }
        mock_downloads_client.download_report.return_value = {
            "_raw_response": mock_response
        }

        result = report_service.download_scan_report(12345)

        assert result == {"_raw_response": mock_response}
        mock_downloads_client.download_report.assert_called_once_with(
            "scans", 12345
        )


# --- Tests for check_project_report_status ---
class TestCheckProjectReportStatus:
    """Test cases for check_project_report_status method."""

    def test_check_project_report_status_success(
        self, report_service, mock_projects_client
    ):
        """Test successful project report status check."""
        mock_status = {"progress_state": "FINISHED", "progress": 100}
        mock_projects_client.check_status.return_value = mock_status

        result = report_service.check_project_report_status(
            12345, "MyProject"
        )

        # Verify check_status was called with correct parameters
        mock_projects_client.check_status.assert_called_once_with(
            12345, "REPORT_GENERATION"
        )

        # Verify result is passed through
        assert result == mock_status

    def test_check_project_report_status_in_progress(
        self, report_service, mock_projects_client
    ):
        """Test checking status when report generation is in progress."""
        mock_status = {"progress_state": "IN_PROGRESS", "progress": 50}
        mock_projects_client.check_status.return_value = mock_status

        result = report_service.check_project_report_status(
            12345, "MyProject"
        )

        mock_projects_client.check_status.assert_called_once_with(
            12345, "REPORT_GENERATION"
        )
        assert result["progress_state"] == "IN_PROGRESS"
        assert result["progress"] == 50

    def test_check_project_report_status_api_error(
        self, report_service, mock_projects_client
    ):
        """Test status check when API returns error."""
        from workbench_agent.api.exceptions import ApiError

        mock_projects_client.check_status.side_effect = ApiError(
            "Process not found"
        )

        with pytest.raises(ApiError, match="Process not found"):
            report_service.check_project_report_status(12345, "MyProject")


# --- Tests for parameter validation ---
class TestReportParameterValidation:
    """Test cases for report parameter validation based on capabilities."""

    def test_xlsx_supports_all_parameters(self, report_service):
        """Test that Excel reports support all parameters."""
        # Should not raise warnings
        payload = report_service.build_scan_report_payload(
            scan_code="scan123",
            report_type="xlsx",
            selection_type="include_foss",
            selection_view="all",
            include_vex=True,
            include_dep_det_info=True,
        )

        # Verify all parameters are included
        assert payload["selection_type"] == "include_foss"
        assert payload["selection_view"] == "all"
        assert payload["include_vex"] is True
        assert payload["include_dep_det_info"] is True

    def test_cyclonedx_only_supports_vex(self, report_service):
        """Test that CycloneDX only supports VEX parameter."""
        payload = report_service.build_scan_report_payload(
            scan_code="scan123",
            report_type="cyclone_dx",
            selection_type="include_foss",  # Should be ignored
            selection_view="all",  # Should be ignored
            include_vex=True,
            include_dep_det_info=True,  # Should be ignored
        )

        # Only include_vex should be in payload
        assert "selection_type" not in payload
        assert "selection_view" not in payload
        assert payload["include_vex"] is True
        assert "include_dep_det_info" not in payload

    def test_spdx_supports_selection_only(self, report_service):
        """Test that SPDX supports only selection parameters."""
        payload = report_service.build_scan_report_payload(
            scan_code="scan123",
            report_type="spdx",
            selection_type="include_foss",
            selection_view="all",
            include_vex=True,  # Should be ignored
            include_dep_det_info=True,  # Should be ignored
        )

        assert payload["selection_type"] == "include_foss"
        assert payload["selection_view"] == "all"
        assert "include_vex" not in payload
        assert "include_dep_det_info" not in payload

    def test_html_supports_disclaimer(self, report_service):
        """Test that HTML reports support disclaimer."""
        payload = report_service.build_scan_report_payload(
            scan_code="scan123",
            report_type="html",
            disclaimer="Custom disclaimer text",
            selection_type="include_foss",
            selection_view="all",
        )

        assert payload["disclaimer"] == "Custom disclaimer text"
        assert payload["selection_type"] == "include_foss"
        assert payload["selection_view"] == "all"

    def test_dynamic_top_matched_components_no_options(
        self, report_service
    ):
        """Test that dynamic_top_matched_components has no optional parameters."""
        payload = report_service.build_scan_report_payload(
            scan_code="scan123",
            report_type="dynamic_top_matched_components",
            selection_type="include_foss",  # Should be ignored
            selection_view="all",  # Should be ignored
            include_vex=True,  # Should be ignored
        )

        # No optional parameters should be in payload
        assert "selection_type" not in payload
        assert "selection_view" not in payload
        assert "include_vex" not in payload

    def test_string_match_only_supports_selection_view(
        self, report_service
    ):
        """Test that string_match only supports selection_view."""
        payload = report_service.build_scan_report_payload(
            scan_code="scan123",
            report_type="string_match",
            selection_type="include_foss",  # Should be ignored
            selection_view="all",
        )

        assert "selection_type" not in payload
        assert payload["selection_view"] == "all"

    def test_project_excel_report_content_type(self, report_service):
        """Test that project Excel reports support report_content_type."""
        payload = report_service.build_project_report_payload(
            project_code="proj123",
            report_type="xlsx",
            report_content_type="abbreviated",
        )

        assert payload["report_content_type"] == "abbreviated"

    def test_scan_excel_report_content_type(self, report_service):
        """Test that scan Excel reports support report_content_type."""
        payload = report_service.build_scan_report_payload(
            scan_code="scan123",
            report_type="xlsx",
            report_content_type="abbreviated",
        )

        assert payload["report_content_type"] == "abbreviated"

    def test_scan_html_report_content_type(self, report_service):
        """Test that scan HTML (basic) reports support report_content_type."""
        payload = report_service.build_scan_report_payload(
            scan_code="scan123",
            report_type="html",
            report_content_type="abbreviated",
        )

        assert payload["report_content_type"] == "abbreviated"
