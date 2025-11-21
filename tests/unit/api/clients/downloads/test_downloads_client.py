# tests/unit/api/clients/downloads/test_downloads_client.py

from unittest.mock import MagicMock

import pytest
import requests

from workbench_agent.api.clients.download_api import DownloadClient
from workbench_agent.api.exceptions import ApiError, NetworkError
from workbench_agent.api.helpers.base_api import BaseAPI
from workbench_agent.exceptions import ValidationError


# --- Fixtures ---
@pytest.fixture
def mock_session(mocker):
    """Create a mock requests.Session."""
    mock_sess = mocker.MagicMock(spec=requests.Session)
    mock_sess.post = mocker.MagicMock()
    mocker.patch("requests.Session", return_value=mock_sess)
    return mock_sess


@pytest.fixture
def base_api(mock_session):
    """Create a BaseAPI instance with a properly mocked session."""
    api = BaseAPI(
        api_url="http://dummy.com/api.php",
        api_user="testuser",
        api_token="testtoken",
    )
    api.session = mock_session
    return api


@pytest.fixture
def downloads_client(base_api):
    """Create a DownloadClient instance with a properly mocked BaseAPI."""
    return DownloadClient(base_api)


# --- Test Cases ---


class TestDownloadClientInitialization:
    """Test cases for DownloadClient initialization."""

    def test_initialization(self, downloads_client, base_api):
        """Test that DownloadClient can be initialized properly."""
        assert downloads_client._api == base_api
        assert downloads_client._api.api_url == "http://dummy.com/api.php"
        assert downloads_client._api.api_user == "testuser"
        assert downloads_client._api.api_token == "testtoken"
        assert downloads_client._api.session is not None

    def test_default_timeout_constant(self, downloads_client):
        """Test that the default timeout constant is set correctly."""
        assert downloads_client.DEFAULT_DOWNLOAD_TIMEOUT == 1800


class TestDownloadReport:
    """Test cases for download_report method."""

    def test_download_report_scan_success(self, downloads_client, base_api):
        """Test successful scan report download."""
        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.content = b"scan report content"
        mock_response.headers = {
            "content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "content-disposition": 'attachment; filename="scan_report.xlsx"',
        }

        base_api._send_request = MagicMock(
            return_value={"_raw_response": mock_response}
        )

        result = downloads_client.download_report("scans", 12345)

        # Verify the method was called with correct parameters
        base_api._send_request.assert_called_once()
        call_args = base_api._send_request.call_args

        # Check payload structure
        payload = call_args[0][0]
        assert payload["group"] == "download"
        assert payload["action"] == "download_report"
        assert payload["data"]["report_entity"] == "scans"
        assert payload["data"]["process_id"] == "12345"

        # Check timeout
        assert call_args[1]["timeout"] == 1800

        # Check return value
        assert result == {"_raw_response": mock_response}

    def test_download_report_project_success(self, downloads_client, base_api):
        """Test successful project report download."""
        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.content = b"project report content"
        mock_response.headers = {
            "content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "content-disposition": 'attachment; filename="project_report.xlsx"',
        }

        base_api._send_request = MagicMock(
            return_value={"_raw_response": mock_response}
        )

        result = downloads_client.download_report("projects", 67890)

        # Verify the method was called with correct parameters
        base_api._send_request.assert_called_once()
        call_args = base_api._send_request.call_args

        # Check payload structure
        payload = call_args[0][0]
        assert payload["group"] == "download"
        assert payload["action"] == "download_report"
        assert payload["data"]["report_entity"] == "projects"
        assert payload["data"]["process_id"] == "67890"

        # Check timeout
        assert call_args[1]["timeout"] == 1800

        # Check return value
        assert result == {"_raw_response": mock_response}

    def test_download_report_custom_timeout(self, downloads_client, base_api):
        """Test download with custom timeout."""
        mock_response = MagicMock(spec=requests.Response)
        mock_response.status_code = 200

        base_api._send_request = MagicMock(
            return_value={"_raw_response": mock_response}
        )

        downloads_client.download_report("scans", 12345, timeout=3600)

        # Verify custom timeout was used
        call_args = base_api._send_request.call_args
        assert call_args[1]["timeout"] == 3600

    def test_download_report_invalid_entity(self, downloads_client):
        """Test that invalid report_entity raises ValidationError."""
        with pytest.raises(
            ValidationError, match="Invalid report_entity 'invalid'"
        ):
            downloads_client.download_report("invalid", 12345)

    def test_download_report_api_error(self, downloads_client, base_api):
        """Test that API errors are propagated."""
        base_api._send_request = MagicMock(
            side_effect=ApiError(
                "Report not found", details={"error": "not_found"}
            )
        )

        with pytest.raises(ApiError, match="Report not found"):
            downloads_client.download_report("scans", 12345)

    def test_download_report_network_error(self, downloads_client, base_api):
        """Test that network errors are propagated."""
        base_api._send_request = MagicMock(
            side_effect=NetworkError("Connection timeout")
        )

        with pytest.raises(NetworkError, match="Connection timeout"):
            downloads_client.download_report("projects", 67890)


class TestDownloadClientIntegration:
    """Integration-style tests for DownloadClient."""

    def test_process_id_string_conversion(self, downloads_client, base_api):
        """Test that process_id is converted to string in payload."""
        mock_response = MagicMock(spec=requests.Response)
        base_api._send_request = MagicMock(
            return_value={"_raw_response": mock_response}
        )

        # Pass integer process_id
        downloads_client.download_report("scans", 99999)

        call_args = base_api._send_request.call_args
        payload = call_args[0][0]

        # Verify it's converted to string
        assert payload["data"]["process_id"] == "99999"
        assert isinstance(payload["data"]["process_id"], str)

    def test_payload_structure(self, downloads_client, base_api):
        """Test that the payload has the correct structure."""
        mock_response = MagicMock(spec=requests.Response)
        base_api._send_request = MagicMock(
            return_value={"_raw_response": mock_response}
        )

        downloads_client.download_report("scans", 12345)

        call_args = base_api._send_request.call_args
        payload = call_args[0][0]

        # Verify payload structure matches API spec
        assert "group" in payload
        assert "action" in payload
        assert "data" in payload
        assert payload["group"] == "download"
        assert payload["action"] == "download_report"
        assert "report_entity" in payload["data"]
        assert "process_id" in payload["data"]
