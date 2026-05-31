"""Unit smoke tests using recorded Workbench 2026.1.0 response fixtures."""

from unittest.mock import patch

import pytest

from workbench_agent.api.clients.files_and_folders import FilesAndFoldersClient
from workbench_agent.api.helpers.base_api import BaseAPI
from workbench_agent.api.utils.path_encoding import encode_path
from tests.api.support.contract import assert_contract
from tests.api.support.version_contracts import load_fixture

WORKBENCH_VERSION = "2026.1.0"
SCAN = "Test_Scan"
PATH = "Files with Snippets/kernel-snippet.c"


@pytest.fixture
def files_client(mock_session):
    api = BaseAPI(
        api_url="http://dummy.com/api.php",
        api_user="testuser",
        api_token="testtoken",
    )
    api.session = mock_session
    return FilesAndFoldersClient(api)


@patch.object(BaseAPI, "_send_request")
def test_get_folder_extensions_ranking_fixture(mock_send, files_client):
    fixture = load_fixture(
        WORKBENCH_VERSION, "files_get_folder_extensions_ranking"
    )
    mock_send.return_value = fixture
    data = files_client.get_folder_extensions_ranking(SCAN)
    assert_contract(
        "files_and_folders.get_folder_extensions_ranking",
        fixture,
        workbench_version=WORKBENCH_VERSION,
        data=data,
    )
    call = mock_send.call_args[0][0]["data"]
    assert call["path"] == encode_path(".")
    assert "current_view" not in call


@patch.object(BaseAPI, "_send_request")
def test_get_folder_components_ranking_fixture(mock_send, files_client):
    fixture = load_fixture(
        WORKBENCH_VERSION, "files_get_folder_components_ranking"
    )
    mock_send.return_value = fixture
    data = files_client.get_folder_components_ranking(SCAN)
    assert_contract(
        "files_and_folders.get_folder_components_ranking",
        fixture,
        workbench_version=WORKBENCH_VERSION,
        data=data,
    )
    call = mock_send.call_args[0][0]["data"]
    assert call["path"] == encode_path(".")


@patch.object(BaseAPI, "_send_request")
def test_get_folder_content_fixture(mock_send, files_client):
    fixture = load_fixture(WORKBENCH_VERSION, "files_get_folder_content")
    mock_send.return_value = fixture
    data = files_client.get_folder_content(SCAN)
    assert_contract(
        "files_and_folders.get_folder_content",
        fixture,
        workbench_version=WORKBENCH_VERSION,
        data=data,
    )
    call = mock_send.call_args[0][0]["data"]
    assert call["path"] == encode_path(".")
    assert call["show_all"] == "1"
    assert call["source_code_only"] == "0"


@patch.object(BaseAPI, "_send_request")
def test_get_identification_fixture(mock_send, files_client):
    fixture = load_fixture(WORKBENCH_VERSION, "files_get_identification")
    mock_send.return_value = fixture
    data = files_client.get_identification(SCAN, PATH)
    assert_contract(
        "files_and_folders.get_identification",
        fixture,
        workbench_version=WORKBENCH_VERSION,
        data=data,
    )
    call_path = mock_send.call_args[0][0]["data"]["path"]
    assert call_path == encode_path(PATH)


@patch.object(BaseAPI, "_send_request")
def test_get_matched_lines_fixture(mock_send, files_client):
    fixture = load_fixture(WORKBENCH_VERSION, "files_get_matched_lines")
    mock_send.return_value = fixture
    data = files_client.get_matched_lines(SCAN, PATH, client_result_id="74")
    assert_contract(
        "files_and_folders.get_matched_lines",
        fixture,
        workbench_version=WORKBENCH_VERSION,
        data=data,
    )


@patch.object(BaseAPI, "_send_request")
def test_get_fossid_results_fixture(mock_send, files_client):
    fixture = load_fixture(WORKBENCH_VERSION, "files_get_fossid_results")
    mock_send.return_value = fixture
    data = files_client.get_fossid_results(SCAN, PATH)
    assert_contract(
        "files_and_folders.get_fossid_results",
        fixture,
        workbench_version=WORKBENCH_VERSION,
        data=data,
    )
