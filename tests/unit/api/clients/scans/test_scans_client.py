# tests/unit/api/clients/test_scans_client.py

from unittest.mock import patch

import pytest
import requests

# Import from the new client structure
from workbench_agent.api.clients.scans_api import ScansClient
from workbench_agent.api.helpers.base_api import BaseAPI
from workbench_agent.exceptions import ApiError, ScanExistsError, ScanNotFoundError


# --- Fixtures ---
@pytest.fixture
def mock_session(mocker):
    mock_sess = mocker.MagicMock(spec=requests.Session)
    mock_sess.post = mocker.MagicMock()
    mocker.patch("requests.Session", return_value=mock_sess)
    return mock_sess


@pytest.fixture
def base_api(mock_session):
    """Create a BaseAPI instance with a properly mocked session."""
    api = BaseAPI(api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken")
    api.session = mock_session
    return api


@pytest.fixture
def scans_client(base_api):
    """Create a ScansClient instance with a properly mocked BaseAPI."""
    return ScansClient(base_api)


# --- Test Cases ---
# --- Test create_scan ---
@patch.object(BaseAPI, "_send_request")
def test_create_scan_success(mock_send, scans_client):
    mock_send.return_value = {"status": "1", "data": {"scan_id": 999}}
    data = {"scan_name": "New Scan", "project_code": "PROJ1"}
    result = scans_client.create_scan(data)
    assert result == 999  # Returns scan_id as int
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["action"] == "create"
    assert payload["data"]["scan_name"] == "New Scan"
    assert payload["data"]["project_code"] == "PROJ1"


@patch.object(BaseAPI, "_send_request")
def test_create_scan_with_git_branch(mock_send, scans_client):
    mock_send.return_value = {"status": "1", "data": {"scan_id": 999}}
    data = {
        "scan_name": "Git Scan",
        "project_code": "PROJ1",
        "git_repo_url": "https://github.com/example/repo.git",
        "git_branch": "main",
        "git_ref_type": "branch",
    }
    result = scans_client.create_scan(data)
    assert result == 999  # Returns scan_id as int
    payload = mock_send.call_args[0][0]
    assert payload["data"]["git_repo_url"] == "https://github.com/example/repo.git"
    assert payload["data"]["git_branch"] == "main"
    assert payload["data"]["git_ref_type"] == "branch"


@patch.object(BaseAPI, "_send_request")
def test_create_scan_with_git_tag(mock_send, scans_client):
    mock_send.return_value = {"status": "1", "data": {"scan_id": 999}}
    data = {
        "scan_name": "Git Scan",
        "project_code": "PROJ1",
        "git_repo_url": "https://github.com/example/repo.git",
        "git_branch": "v1.0.0",  # API uses git_branch field for both branches and tags
        "git_ref_type": "tag",
    }
    result = scans_client.create_scan(data)
    assert result == 999  # Returns scan_id as int
    payload = mock_send.call_args[0][0]
    assert payload["data"]["git_repo_url"] == "https://github.com/example/repo.git"
    assert payload["data"]["git_branch"] == "v1.0.0"  # API uses git_branch field for both values
    assert payload["data"]["git_ref_type"] == "tag"


@patch.object(BaseAPI, "_send_request")
def test_create_scan_with_git_commit(mock_send, scans_client):
    mock_send.return_value = {"status": "1", "data": {"scan_id": 999}}
    data = {
        "scan_name": "Git Scan",
        "project_code": "PROJ1",
        "git_repo_url": "https://github.com/example/repo.git",
        "git_branch": "abc123def456",  # API uses git_branch field for commits too
        "git_ref_type": "commit",
    }
    result = scans_client.create_scan(data)
    assert result == 999  # Returns scan_id as int
    payload = mock_send.call_args[0][0]
    assert payload["data"]["git_repo_url"] == "https://github.com/example/repo.git"
    assert payload["data"]["git_branch"] == "abc123def456"
    assert payload["data"]["git_ref_type"] == "commit"


@patch.object(BaseAPI, "_send_request")
def test_create_scan_with_git_depth(mock_send, scans_client):
    mock_send.return_value = {"status": "1", "data": {"scan_id": 999}}
    data = {
        "scan_name": "Git Scan",
        "project_code": "PROJ1",
        "git_repo_url": "https://github.com/example/repo.git",
        "git_branch": "main",
        "git_depth": "1",
    }
    result = scans_client.create_scan(data)
    assert result == 999  # Returns scan_id as int
    payload = mock_send.call_args[0][0]
    assert payload["data"]["git_depth"] == "1"


@patch.object(BaseAPI, "_send_request")
def test_create_scan_exists(mock_send, scans_client):
    mock_send.return_value = {"status": "0", "error": "Scan code already exists"}
    data = {"scan_name": "Existing Scan", "project_code": "PROJ1"}
    with pytest.raises(ScanExistsError, match="Scan 'Existing Scan' already exists"):
        scans_client.create_scan(data)


# --- Tests for Git operations ---
@patch.object(BaseAPI, "_send_request")
def test_download_content_from_git_success(mock_send, scans_client):
    mock_send.return_value = {"status": "1", "data": {"status": "QUEUED"}}
    result = scans_client.download_content_from_git("scan1")
    assert result is True  # Method returns True on success
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "scans"
    assert payload["action"] == "download_content_from_git"
    assert payload["data"]["scan_code"] == "scan1"


@patch.object(BaseAPI, "_send_request")
def test_download_content_from_git_failure(mock_send, scans_client):
    mock_send.return_value = {"status": "0", "error": "Git URL not set"}
    with pytest.raises(ApiError, match="Failed to initiate download from Git: Git URL not set"):
        scans_client.download_content_from_git("scan1")


@patch.object(BaseAPI, "_send_request")
def test_check_status_download_content_from_git(mock_send, scans_client):
    mock_send.return_value = {"status": "1", "data": {"status": "RUNNING", "other_info": "test"}}
    status_data = scans_client.check_status_download_content_from_git("scan1")
    assert status_data == {"status": "RUNNING", "other_info": "test"}
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "scans"
    assert payload["action"] == "check_status_download_content_from_git"
    assert payload["data"]["scan_code"] == "scan1"


# --- Test remove_uploaded_content ---
@patch.object(BaseAPI, "_send_request")
def test_remove_uploaded_content_success(mock_send, scans_client):
    mock_send.return_value = {"status": "1"}
    result = scans_client.remove_uploaded_content("scan1", "test_file.txt")
    assert result is True
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "scans"
    assert payload["action"] == "remove_uploaded_content"
    assert payload["data"]["scan_code"] == "scan1"
    assert payload["data"]["filename"] == "test_file.txt"


@patch.object(BaseAPI, "_send_request")
def test_remove_uploaded_content_file_not_found(mock_send, scans_client):
    # Response indicating file not found but API returns status 0
    mock_send.return_value = {
        "status": "0",
        "error": "RequestData.Base.issues_while_parsing_request",
        "data": [{"code": "RequestData.Traits.PathTrait.filename_is_not_valid"}],
    }

    # Should return True since the end goal (file not present) is satisfied
    result = scans_client.remove_uploaded_content("scan1", "nonexistent.txt")
    assert result is True
    mock_send.assert_called_once()


# --- Tests for extract_archives_raw ---
@patch.object(BaseAPI, "_send_request")
def test_extract_archives_success(mock_send, scans_client):
    mock_send.return_value = {"status": "1"}
    payload_data = {
        "scan_code": "scan1",
        "recursively_extract_archives": "true",
        "jar_file_extraction": "false",
    }
    result = scans_client.extract_archives_raw(payload_data)
    assert result is True
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "scans"
    assert payload["action"] == "extract_archives"
    assert payload["data"]["scan_code"] == "scan1"
    assert payload["data"]["recursively_extract_archives"] == "true"
    assert payload["data"]["jar_file_extraction"] == "false"


@patch.object(BaseAPI, "_send_request")
def test_extract_archives_not_found(mock_send, scans_client):
    mock_send.return_value = {"status": "0", "error": "Scan not found"}
    payload_data = {
        "scan_code": "scan1",
        "recursively_extract_archives": "true",
        "jar_file_extraction": "true",
    }
    with pytest.raises(ScanNotFoundError, match="Scan 'scan1' not found"):
        scans_client.extract_archives_raw(payload_data)


@patch.object(BaseAPI, "_send_request")
def test_extract_archives_api_error(mock_send, scans_client):
    mock_send.return_value = {"status": "0", "error": "Invalid parameters"}
    payload_data = {
        "scan_code": "scan1",
        "recursively_extract_archives": "true",
        "jar_file_extraction": "true",
    }
    with pytest.raises(ApiError, match="Archive extraction failed for scan 'scan1'"):
        scans_client.extract_archives_raw(payload_data)


# --- Tests for run_scan_raw and related methods ---


@patch.object(BaseAPI, "_send_request")
def test_run_scan_basic_success(mock_send, scans_client):
    mock_send.return_value = {"status": "1"}
    payload_data = {
        "scan_code": "scan1",
        "limit": 100,
        "sensitivity": 3,
        "auto_identification_detect_declaration": 1,
        "auto_identification_detect_copyright": 1,
        "auto_identification_resolve_pending_ids": 0,
        "delta_only": 0,
    }
    scans_client.run_scan_raw(payload_data)
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "scans"
    assert payload["action"] == "run"
    assert payload["data"]["scan_code"] == "scan1"
    assert payload["data"]["limit"] == 100
    assert payload["data"]["sensitivity"] == 3
    assert payload["data"]["auto_identification_detect_declaration"] == 1
    assert payload["data"]["auto_identification_detect_copyright"] == 1
    assert payload["data"]["auto_identification_resolve_pending_ids"] == 0
    assert payload["data"]["delta_only"] == 0
    assert "reuse_identification" not in payload["data"]


@patch.object(BaseAPI, "_send_request")
def test_run_scan_with_run_dependency_analysis(mock_send, scans_client):
    mock_send.return_value = {"status": "1"}
    payload_data = {
        "scan_code": "scan1",
        "limit": 100,
        "sensitivity": 3,
        "auto_identification_detect_declaration": 1,
        "auto_identification_detect_copyright": 1,
        "auto_identification_resolve_pending_ids": 0,
        "delta_only": 0,
        "run_dependency_analysis": "1",
    }
    scans_client.run_scan_raw(payload_data)
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "scans"
    assert payload["action"] == "run"
    assert payload["data"]["scan_code"] == "scan1"
    assert payload["data"]["run_dependency_analysis"] == "1"


@patch.object(BaseAPI, "_send_request")
def test_run_scan_with_id_reuse_any(mock_send, scans_client):
    mock_send.return_value = {"status": "1"}
    payload_data = {
        "scan_code": "scan1",
        "limit": 100,
        "sensitivity": 3,
        "auto_identification_detect_declaration": 1,
        "auto_identification_detect_copyright": 1,
        "auto_identification_resolve_pending_ids": 0,
        "delta_only": 0,
        "reuse_identification": "1",
        "identification_reuse_type": "any",
    }
    scans_client.run_scan_raw(payload_data)
    payload = mock_send.call_args[0][0]
    assert payload["data"]["reuse_identification"] == "1"
    assert payload["data"]["identification_reuse_type"] == "any"


@patch.object(BaseAPI, "_send_request")
def test_run_scan_with_id_reuse_project(mock_send, scans_client):
    mock_send.return_value = {"status": "1"}
    payload_data = {
        "scan_code": "scan1",
        "limit": 100,
        "sensitivity": 3,
        "auto_identification_detect_declaration": 1,
        "auto_identification_detect_copyright": 1,
        "auto_identification_resolve_pending_ids": 0,
        "delta_only": 0,
        "reuse_identification": "1",
        "identification_reuse_type": "specific_project",
        "specific_code": "PROJECT_CODE",
    }
    scans_client.run_scan_raw(payload_data)
    payload = mock_send.call_args[0][0]
    assert payload["data"]["reuse_identification"] == "1"
    assert payload["data"]["identification_reuse_type"] == "specific_project"
    assert payload["data"]["specific_code"] == "PROJECT_CODE"


@patch.object(BaseAPI, "_send_request")
def test_run_scan_with_id_reuse_scan(mock_send, scans_client):
    mock_send.return_value = {"status": "1"}
    payload_data = {
        "scan_code": "scan1",
        "limit": 100,
        "sensitivity": 3,
        "auto_identification_detect_declaration": 1,
        "auto_identification_detect_copyright": 1,
        "auto_identification_resolve_pending_ids": 0,
        "delta_only": 0,
        "reuse_identification": "1",
        "identification_reuse_type": "specific_scan",
        "specific_code": "OTHER_SCAN_CODE",
    }
    scans_client.run_scan_raw(payload_data)
    payload = mock_send.call_args[0][0]
    assert payload["data"]["reuse_identification"] == "1"
    assert payload["data"]["identification_reuse_type"] == "specific_scan"
    assert payload["data"]["specific_code"] == "OTHER_SCAN_CODE"


@patch.object(BaseAPI, "_send_request")
def test_run_scan_not_found(mock_send, scans_client):
    mock_send.return_value = {"status": "0", "error": "Scan not found"}
    payload_data = {
        "scan_code": "scan1",
        "limit": 100,
        "sensitivity": 3,
        "auto_identification_detect_declaration": 1,
        "auto_identification_detect_copyright": 1,
        "auto_identification_resolve_pending_ids": 0,
        "delta_only": 0,
    }
    with pytest.raises(ScanNotFoundError, match="Scan 'scan1' not found"):
        scans_client.run_scan_raw(payload_data)


@patch.object(BaseAPI, "_send_request")
def test_run_scan_raw_basic_payload(mock_send, scans_client):
    # Test that run_scan_raw accepts and forwards payload correctly
    mock_send.return_value = {"status": "1"}
    payload_data = {
        "scan_code": "scan1",
        "limit": 100,
        "sensitivity": 3,
        "auto_identification_detect_declaration": 1,
        "auto_identification_detect_copyright": 1,
        "auto_identification_resolve_pending_ids": 0,
        "delta_only": 0,
    }
    scans_client.run_scan_raw(payload_data)

    # Verify _send_request was called
    mock_send.assert_called_once()

    # Verify payload structure
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "scans"
    assert payload["action"] == "run"
    assert payload["data"]["scan_code"] == "scan1"


# --- Tests for dependency analysis ---


@patch.object(BaseAPI, "_send_request")
def test_start_dependency_analysis_success(mock_send, scans_client):
    mock_send.return_value = {"status": "1"}
    payload_data = {"scan_code": "scan1", "import_only": "0"}
    scans_client.start_dependency_analysis_raw(payload_data)
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "scans"
    assert payload["action"] == "run_dependency_analysis"
    assert payload["data"]["scan_code"] == "scan1"
    assert payload["data"]["import_only"] == "0"


@patch.object(BaseAPI, "_send_request")
def test_start_dependency_analysis_import_only(mock_send, scans_client):
    mock_send.return_value = {"status": "1"}
    payload_data = {"scan_code": "scan1", "import_only": "1"}
    scans_client.start_dependency_analysis_raw(payload_data)
    payload = mock_send.call_args[0][0]
    assert payload["data"]["import_only"] == "1"


@patch.object(BaseAPI, "_send_request")
def test_start_dependency_analysis_scan_not_found(mock_send, scans_client):
    mock_send.return_value = {"status": "0", "error": "Scan not found"}
    payload_data = {"scan_code": "scan1", "import_only": "0"}
    with pytest.raises(
        ApiError, match="Failed to start dependency analysis for 'scan1': Scan not found"
    ):
        scans_client.start_dependency_analysis_raw(payload_data)


# --- Tests for check_status ---
@patch.object(BaseAPI, "_send_request")
def test_check_status_success(mock_send, scans_client):
    mock_send.return_value = {"status": "1", "data": {"status": "RUNNING", "progress": 50}}
    status = scans_client.check_status("scan1", "SCAN")
    assert status == {"status": "RUNNING", "progress": 50}
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "scans"
    assert payload["action"] == "check_status"
    assert payload["data"]["scan_code"] == "scan1"
    assert payload["data"]["type"] == "SCAN"


@patch.object(BaseAPI, "_send_request")
def test_check_status_scan_not_found(mock_send, scans_client):
    mock_send.return_value = {"status": "0", "error": "Scan not found"}
    with pytest.raises(ScanNotFoundError, match="Scan 'scan1' not found"):
        scans_client.check_status("scan1", "SCAN")


# --- Tests for list_scans ---
@patch.object(BaseAPI, "_send_request")
def test_list_scans_success(mock_send, scans_client):
    mock_send.return_value = {
        "status": "1",
        "data": {
            "1": {"code": "SCAN_A", "name": "Scan A"},
            "2": {"code": "SCAN_B", "name": "Scan B"},
        },
    }
    scans = scans_client.list_scans()
    assert len(scans) == 2
    # Check that the scan ID from key was added to details
    assert any(scan["id"] == 1 for scan in scans)
    assert any(scan["id"] == 2 for scan in scans)
    # Check that all scan data was preserved
    assert any(scan["code"] == "SCAN_A" for scan in scans)
    assert any(scan["code"] == "SCAN_B" for scan in scans)
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "scans"
    assert payload["action"] == "list_scans"


@patch.object(BaseAPI, "_send_request")
def test_list_scans_empty(mock_send, scans_client):
    mock_send.return_value = {"status": "1", "data": []}  # API returns empty list
    scans = scans_client.list_scans()
    assert scans == []


# --- Tests for scan result fetching methods ---
@patch.object(BaseAPI, "_send_request")
def test_get_scan_folder_metrics_success(mock_send, scans_client):
    mock_send.return_value = {
        "status": "1",
        "data": {"total_files": 100, "no_match": 20, "pending": 10, "identified": 70},
    }
    metrics = scans_client.get_scan_folder_metrics("scan1")
    assert metrics["total_files"] == 100
    assert metrics["no_match"] == 20
    assert metrics["pending"] == 10
    assert metrics["identified"] == 70
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "scans"
    assert payload["action"] == "get_folder_metrics"
    assert payload["data"]["scan_code"] == "scan1"


@patch.object(BaseAPI, "_send_request")
def test_get_scan_folder_metrics_scan_not_found(mock_send, scans_client):
    mock_send.return_value = {"status": "0", "error": "row_not_found"}
    with pytest.raises(ScanNotFoundError, match="Scan 'scan1' not found"):
        scans_client.get_scan_folder_metrics("scan1")


# --- Tests for scan component and license fetching ---
@patch.object(BaseAPI, "_send_request")
def test_get_scan_identified_components_success(mock_send, scans_client):
    mock_send.return_value = {
        "status": "1",
        "data": {
            "1": {"name": "Component A", "version": "1.0"},
            "2": {"name": "Component B", "version": "2.0"},
        },
    }
    components = scans_client.get_scan_identified_components("scan1")
    assert len(components) == 2
    assert components[0]["name"] == "Component A"
    assert components[1]["version"] == "2.0"
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "scans"
    assert payload["action"] == "get_scan_identified_components"
    assert payload["data"]["scan_code"] == "scan1"


@patch.object(BaseAPI, "_send_request")
def test_get_scan_identified_licenses_success(mock_send, scans_client):
    mock_send.return_value = {
        "status": "1",
        "data": [{"name": "MIT", "id": 1}, {"name": "Apache-2.0", "id": 2}],
    }
    licenses = scans_client.get_scan_identified_licenses("scan1")
    assert len(licenses) == 2
    assert licenses[0]["name"] == "MIT"
    assert licenses[1]["name"] == "Apache-2.0"
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "scans"
    assert payload["action"] == "get_scan_identified_licenses"
    assert payload["data"]["scan_code"] == "scan1"
    assert payload["data"]["unique"] == "1"


@patch.object(BaseAPI, "_send_request")
def test_get_dependency_analysis_results_success(mock_send, scans_client):
    mock_send.return_value = {
        "status": "1",
        "data": [{"name": "dep1", "version": "1.0"}, {"name": "dep2", "version": "2.0"}],
    }
    deps = scans_client.get_dependency_analysis_results("scan1")
    assert len(deps) == 2
    assert deps[0]["name"] == "dep1"
    assert deps[1]["version"] == "2.0"
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "scans"
    assert payload["action"] == "get_dependency_analysis_results"
    assert payload["data"]["scan_code"] == "scan1"


@patch.object(BaseAPI, "_send_request")
def test_get_dependency_analysis_results_not_run(mock_send, scans_client):
    mock_send.return_value = {"status": "0", "error": "Dependency analysis has not been run"}
    deps = scans_client.get_dependency_analysis_results("scan1")
    assert deps == []


@patch.object(BaseAPI, "_send_request")
def test_get_pending_files_success(mock_send, scans_client):
    mock_send.return_value = {
        "status": "1",
        "data": {"file1.txt": "pending", "file2.txt": "pending"},
    }
    pending = scans_client.get_pending_files("scan1")
    assert len(pending) == 2
    assert "file1.txt" in pending
    assert "file2.txt" in pending
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "scans"
    assert payload["action"] == "get_pending_files"
    assert payload["data"]["scan_code"] == "scan1"


@patch.object(BaseAPI, "_send_request")
def test_get_policy_warnings_counter_success(mock_send, scans_client):
    mock_send.return_value = {"status": "1", "data": {"count": 5}}
    warnings = scans_client.get_policy_warnings_counter("scan1")
    assert warnings["count"] == 5
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "scans"
    assert payload["action"] == "get_policy_warnings_counter"
    assert payload["data"]["scan_code"] == "scan1"


@patch.object(BaseAPI, "_send_request")
def test_get_scan_information_failure(mock_send_request, scans_client):
    mock_send_request.return_value = {"status": "0", "error": "Not found"}
    with pytest.raises(ApiError, match="Not found"):
        scans_client.get_scan_information("scan1")


@patch.object(BaseAPI, "_send_request")
def test_run_scan_raw_api_failure(mock_send_request, scans_client, caplog):
    # Test API failure scenario
    mock_send_request.return_value = {"status": "0", "error": "API failure"}
    payload_data = {
        "scan_code": "scan1",
        "limit": 10,
        "sensitivity": 10,
    }

    with pytest.raises(ApiError, match="Failed to run scan 'scan1': API failure"):
        scans_client.run_scan_raw(payload_data)

    mock_send_request.assert_called_once()


# --- Tests for import_report method ---
@patch.object(BaseAPI, "_send_request")
def test_import_report_success(mock_send, scans_client):
    """Test successful SBOM/report import."""
    mock_send.return_value = {"status": "1", "data": {"message": "Import started successfully"}}

    result = scans_client.import_report("scan1")

    assert result is None
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload["group"] == "scans"
    assert payload["action"] == "import_report"
    assert payload["data"]["scan_code"] == "scan1"


@patch.object(BaseAPI, "_send_request")
def test_import_report_scan_not_found(mock_send, scans_client):
    """Test import_report with scan not found."""
    mock_send.return_value = {"status": "0", "error": "Scan not found"}

    with pytest.raises(ScanNotFoundError, match="Scan 'scan1' not found"):
        scans_client.import_report("scan1")


@patch.object(BaseAPI, "_send_request")
def test_import_report_api_error(mock_send, scans_client):
    """Test import_report with API error."""
    mock_send.return_value = {"status": "0", "error": "Import failed"}

    with pytest.raises(
        ApiError, match="Failed to start SBOM report import for 'scan1': Import failed"
    ):
        scans_client.import_report("scan1")


@patch.object(BaseAPI, "_send_request")
def test_get_scan_information_success(mock_send, scans_client):
    mock_send.return_value = {"status": "1", "data": {"id": 42, "code": "SCN"}}
    info = scans_client.get_scan_information("scan1")
    assert info["id"] == 42


@patch.object(BaseAPI, "_send_request")
def test_list_scans_status1_no_data_key(mock_send, scans_client):
    mock_send.return_value = {"status": "1"}  # No data key
    scans = scans_client.list_scans()
    assert scans == []


@patch.object(BaseAPI, "_send_request")
def test_list_scans_unexpected_format(mock_send, scans_client):
    mock_send.return_value = {"status": "1", "data": "weird"}
    scans = scans_client.list_scans()
    assert scans == []


@patch.object(BaseAPI, "_send_request")
def test_check_status_requires_process_id_for_report_generation(mock_send, scans_client):
    # The new implementation doesn't validate process_id upfront - it will fail with ApiError
    # when the API returns an error. Let's test that it calls the API without process_id
    mock_send.return_value = {"status": "0", "error": "process_id required"}
    with pytest.raises(ApiError):
        scans_client.check_status("scan1", "REPORT_GENERATION")


@patch.object(BaseAPI, "_send_request")
def test_check_status_unsupported_maps_to_exception(mock_send, scans_client):
    # The new implementation doesn't convert ApiError to UnsupportedStatusCheck
    # It just raises ApiError directly
    mock_send.side_effect = ApiError("Field_not_valid_option: type")

    with pytest.raises(ApiError, match="Field_not_valid_option: type"):
        scans_client.check_status("scan1", "SOME_UNKNOWN_TYPE")


@patch.object(BaseAPI, "_send_request")
def test_check_status_api_error_generic(mock_send, scans_client):
    mock_send.return_value = {"status": "0", "error": "Bad request"}
    with pytest.raises(ApiError, match="Failed to retrieve REPORT_GENERATION status"):
        scans_client.check_status("scan1", "REPORT_GENERATION", process_id="99")


@patch.object(BaseAPI, "_send_request")
def test_get_pending_files_status1_no_data(mock_send, scans_client):
    mock_send.return_value = {"status": "1"}
    files = scans_client.get_pending_files("scan1")
    assert files == {}


@patch.object(BaseAPI, "_send_request")
def test_get_pending_files_status0_returns_empty(mock_send, scans_client):
    mock_send.return_value = {"status": "0", "error": "something"}
    files = scans_client.get_pending_files("scan1")
    assert files == {}


@patch.object(BaseAPI, "_send_request")
def test_get_policy_warnings_counter_scan_not_found(mock_send, scans_client):
    mock_send.return_value = {"status": "0", "error": "row_not_found"}
    with pytest.raises(ScanNotFoundError):
        scans_client.get_policy_warnings_counter("scan1")


@patch.object(BaseAPI, "_send_request")
def test_get_policy_warnings_counter_api_error(mock_send, scans_client):
    mock_send.return_value = {"status": "0", "error": "Other error"}
    with pytest.raises(ApiError):
        scans_client.get_policy_warnings_counter("scan1")


@patch.object(BaseAPI, "_send_request")
def test_get_scan_identified_components_scan_not_found(mock_send, scans_client):
    mock_send.return_value = {"status": "0", "error": "Scan not found"}
    with pytest.raises(ScanNotFoundError):
        scans_client.get_scan_identified_components("scan1")


@patch.object(BaseAPI, "_send_request")
def test_get_scan_identified_components_api_error(mock_send, scans_client):
    mock_send.return_value = {"status": "0", "error": "Backend down"}
    with pytest.raises(ApiError):
        scans_client.get_scan_identified_components("scan1")


@patch.object(BaseAPI, "_send_request")
def test_get_scan_identified_licenses_no_data_key_returns_empty(mock_send, scans_client):
    mock_send.return_value = {"status": "1"}
    licenses = scans_client.get_scan_identified_licenses("scan1")
    assert licenses == []


@patch.object(BaseAPI, "_send_request")
def test_get_scan_folder_metrics_unexpected_data_format(mock_send, scans_client):
    mock_send.return_value = {"status": "1", "data": [1, 2, 3]}
    with pytest.raises(ApiError, match="Unexpected data format"):
        scans_client.get_scan_folder_metrics("scan1")


@patch.object(BaseAPI, "_send_request")
def test_check_status_download_content_from_git_failure(mock_send, scans_client):
    mock_send.return_value = {"status": "0", "error": "Not available"}
    with pytest.raises(ApiError):
        scans_client.check_status_download_content_from_git("scan1")


@patch.object(BaseAPI, "_send_request")
def test_generate_scan_report_sync_success(mock_send, scans_client):
    raw = object()
    mock_send.return_value = {"_raw_response": raw}
    payload_data = {"scan_code": "scan1", "report_type": "spdx", "async": "0"}
    result = scans_client.generate_scan_report_raw(payload_data)
    assert result is raw


@patch.object(BaseAPI, "_send_request")
def test_generate_scan_report_async_success(mock_send, scans_client):
    mock_send.return_value = {"status": "1", "data": {"process_queue_id": "123"}}
    payload_data = {"scan_code": "scan1", "report_type": "spdx", "async": "1"}
    pid = scans_client.generate_scan_report_raw(payload_data)
    assert pid == 123


@patch.object(BaseAPI, "_send_request")
def test_generate_scan_report_error(mock_send, scans_client):
    mock_send.return_value = {"status": "0", "error": "Bad"}
    payload_data = {"scan_code": "scan1", "report_type": "spdx", "async": "1"}
    with pytest.raises(ApiError):
        scans_client.generate_scan_report_raw(payload_data)
