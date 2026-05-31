"""Unit tests for FilesAndFoldersClient."""

import base64
from unittest.mock import patch

import pytest

from workbench_agent.api.clients.files_and_folders import FilesAndFoldersClient
from workbench_agent.api.clients.files_and_folders.errors import path_for_action
from workbench_agent.api.utils.path_encoding import encode_path
from workbench_agent.api.exceptions import ApiError
from workbench_agent.api.helpers.base_api import BaseAPI


@pytest.fixture
def files_client(mock_session):
    api = BaseAPI(
        api_url="http://dummy.com/api.php",
        api_user="testuser",
        api_token="testtoken",
    )
    api.session = mock_session
    return FilesAndFoldersClient(api)


def test_encode_path_delegates_to_util():
    path = "src/main.c"
    assert FilesAndFoldersClient.encode_path(path) == encode_path(path)
    assert encode_path(path) == base64.b64encode(path.encode()).decode()


def test_path_for_action_encodes_except_remove():
    path = "src/main.c"
    assert path_for_action("get_identification", path) == encode_path(path)
    assert path_for_action("remove_component_identification", path) == path


@patch.object(BaseAPI, "_send_request")
def test_get_folder_extensions_ranking(mock_send, files_client):
    mock_send.return_value = {
        "status": "1",
        "data": [
            {"id": "6", "file_extension": "c", "amount": "28"},
            {"id": "2", "file_extension": "h", "amount": "17"},
        ],
    }
    result = files_client.get_folder_extensions_ranking(
        "SCAN1",
        "OpenFastPath",
        current_view="pending_items",
    )
    assert len(result) == 2
    assert result[0]["file_extension"] == "c"
    data = mock_send.call_args[0][0]["data"]
    assert data["path"] == FilesAndFoldersClient.encode_path("OpenFastPath")
    assert data["current_view"] == "pending_items"


@patch.object(BaseAPI, "_send_request")
def test_get_folder_extensions_ranking_file_returns_false(mock_send, files_client):
    mock_send.return_value = {"status": "1", "data": False}
    result = files_client.get_folder_extensions_ranking("SCAN1", "LICENSE")
    assert result is False


@patch.object(BaseAPI, "_send_request")
def test_get_folder_components_ranking(mock_send, files_client):
    mock_send.return_value = {
        "status": "1",
        "data": [
            {
                "rownum": "0",
                "artifact": "ofp",
                "version": "1.1",
                "amount_per_artifact_version": "15",
                "amount": "43",
                "fcrid": "1612",
            }
        ],
    }
    result = files_client.get_folder_components_ranking("SCAN1", "OpenFastPath")
    assert len(result) == 1
    assert result[0]["artifact"] == "ofp"
    data = mock_send.call_args[0][0]["data"]
    assert data["path"] == FilesAndFoldersClient.encode_path("OpenFastPath")


@patch.object(BaseAPI, "_send_request")
def test_get_folder_components_ranking_file_returns_false(mock_send, files_client):
    mock_send.return_value = {"status": "1", "data": False}
    result = files_client.get_folder_components_ranking("SCAN1", "LICENSE")
    assert result is False


@patch.object(BaseAPI, "_send_request")
def test_get_folder_content_metrics_file_path_zeros(mock_send, files_client):
    mock_send.return_value = {
        "status": "1",
        "data": {
            "total": "0",
            "pending_identification": "0",
            "identified_files": "0",
            "without_matches": "0",
        },
    }
    result = files_client.get_folder_content_metrics("SCAN1", "LICENSE")
    assert result["total"] == "0"


@patch.object(BaseAPI, "_send_request")
def test_get_folder_content_metrics(mock_send, files_client):
    mock_send.return_value = {
        "status": "1",
        "data": {
            "total": "200",
            "pending_identification": "126",
            "identified_files": "0",
            "without_matches": "74",
        },
        "message": "Success",
    }
    result = files_client.get_folder_content_metrics("SCAN1", ".")
    assert result["total"] == "200"
    assert result["pending_identification"] == "126"
    payload = mock_send.call_args[0][0]
    assert payload["action"] == "get_folder_content_metrics"
    assert payload["data"]["path"] == FilesAndFoldersClient.encode_path(".")


@patch.object(BaseAPI, "_send_request")
def test_get_folder_content(mock_send, files_client):
    mock_send.return_value = {
        "status": "1",
        "data": [
            {
                "id": "Li9BbmRyb2lkLUJsdWV0b290aA==",
                "text": "Android-Bluetooth",
                "is_directory": "1",
                "children": "1",
            },
            {
                "id": "Li9BbmRyb2lkLUJsdWV0b290aC9CbHVldG9vdGhBY3Rpdml0eUVuZXJneUluZm8uamF2YQ==",
                "icon": "images/languages_icons/java_26.png",
                "is_directory": "0",
                "text": "BluetoothActivityEnergyInfo.java",
            },
        ],
    }
    result = files_client.get_folder_content(
        "SCAN1",
        ".",
        show_all=False,
        source_code_only=True,
    )
    assert len(result) == 2
    data = mock_send.call_args[0][0]["data"]
    assert data["path"] == FilesAndFoldersClient.encode_path(".")
    assert data["show_all"] == "0"
    assert data["source_code_only"] == "1"


@patch.object(BaseAPI, "_send_request")
def test_get_identification_encodes_path(mock_send, files_client):
    mock_send.return_value = {
        "status": "1",
        "data": {"component_identification": {}, "licenses": {}},
    }
    files_client.get_identification("SCAN1", "src/main.c")
    data = mock_send.call_args[0][0]["data"]
    assert data["path"] == FilesAndFoldersClient.encode_path("src/main.c")
    assert data["scan_code"] == "SCAN1"


@patch.object(BaseAPI, "_send_request")
def test_set_identification_copyright_message(mock_send, files_client):
    mock_send.return_value = {
        "status": "1",
        "data": None,
        "message": "Success",
    }
    result = files_client.set_identification_copyright(
        "SCAN1", "src/main.c", "(c) 2024", is_directory=False
    )
    assert result["message"] == "Success"
    assert mock_send.call_args[0][0]["data"]["is_directory"] == "0"


@patch.object(BaseAPI, "_send_request")
def test_add_license_identification(mock_send, files_client):
    mock_send.return_value = {
        "status": "1",
        "data": {"identification_id": 24888},
        "message": "Success",
    }
    result = files_client.add_license_identification(
        "SCAN1",
        "src/main.c",
        "MIT",
        "file",
    )
    assert result["data"]["identification_id"] == 24888


@patch.object(BaseAPI, "_send_request")
def test_set_identification_component_flags(mock_send, files_client):
    mock_send.return_value = {"status": "1", "data": None, "message": "Success"}
    files_client.set_identification_component(
        "SCAN1",
        "src/main.c",
        "openssl",
        "3.0",
        preserve_existing_identifications=True,
    )
    data = mock_send.call_args[0][0]["data"]
    assert data["preserve_existing_identifications"] == "1"


@patch.object(BaseAPI, "_send_request")
def test_get_fossid_results(mock_send, files_client):
    mock_send.return_value = {
        "status": "1",
        "data": {"35471": {"id": 35471, "artifact": "algorithm"}},
    }
    result = files_client.get_fossid_results("SCAN1", "include/boost.hpp")
    assert "35471" in result


@patch.object(BaseAPI, "_send_request")
def test_get_matched_lines(mock_send, files_client):
    mock_send.return_value = {
        "status": "1",
        "data": {"local_file": {"7": 7}, "mirror_file": {"7": 7}},
    }
    result = files_client.get_matched_lines(
        "SCAN1", "file.c", client_result_id="35471"
    )
    assert "local_file" in result


@patch.object(BaseAPI, "_send_request")
def test_get_file_comments_list(mock_send, files_client):
    mock_send.return_value = {
        "status": "1",
        "data": [{"id": 314, "comment": "text"}],
    }
    result = files_client.get_file_comments("SCAN1", "src/main.c")
    assert result[0]["id"] == 314


@patch.object(BaseAPI, "_send_request")
def test_remove_component_identification_plain_path(mock_send, files_client):
    mock_send.return_value = {"status": "1", "data": True}
    assert (
        files_client.remove_component_identification("SCAN1", "src/main.c")
        is True
    )
    data = mock_send.call_args[0][0]["data"]
    assert data["path"] == "src/main.c"
    assert data["path"] != files_client.encode_path("src/main.c")


@patch.object(BaseAPI, "_send_request")
def test_mark_as_identified_directory(mock_send, files_client):
    mock_send.return_value = {"status": "1", "data": None, "message": "Success"}
    files_client.mark_as_identified("SCAN1", "src/", is_directory=True)
    assert mock_send.call_args[0][0]["data"]["is_directory"] == "1"


@patch.object(BaseAPI, "_send_request")
def test_api_error(mock_send, files_client):
    mock_send.return_value = {"status": "0", "error": "File not found"}
    with pytest.raises(ApiError, match="File not found"):
        files_client.get_identification("SCAN1", "missing.c")
