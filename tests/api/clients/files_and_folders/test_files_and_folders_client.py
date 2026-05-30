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
