"""Unit tests: FilesAndFoldersClient raises ApiError on API failures."""

from unittest.mock import patch

import pytest

from workbench_agent.api.clients.files_and_folders import FilesAndFoldersClient
from workbench_agent.api.exceptions import ApiError
from workbench_agent.api.helpers.base_api import BaseAPI
from tests.api.support.error_assertions import (
    assert_api_error,
    assert_api_error_details_status_zero,
)


@pytest.fixture
def files_client(mock_session):
    api = BaseAPI(
        api_url="http://dummy.com/api.php",
        api_user="testuser",
        api_token="testtoken",
    )
    api.session = mock_session
    return FilesAndFoldersClient(api)


ERROR_RESPONSE = {
    "status": "0",
    "error": "The provided file path does not exist",
    "operation": "files_and_folders_get_identification",
}

SCAN = "SCAN1"
PATH = "src/missing.c"


@patch.object(BaseAPI, "_send_request")
@pytest.mark.parametrize(
    "method_name,call_args",
    [
        ("get_identification", (SCAN, PATH)),
        (
            "set_identification_copyright",
            (SCAN, PATH, "(c) test"),
        ),
        (
            "add_license_identification",
            (SCAN, PATH, "MIT", "file"),
        ),
        (
            "set_identification_component",
            (SCAN, PATH, "nope", "1.0"),
        ),
        ("get_fossid_results", (SCAN, PATH)),
        ("get_matched_lines", (SCAN, PATH, "0")),
        ("add_file_comment", (SCAN, PATH, "hi")),
        ("get_file_comments", (SCAN, PATH)),
        ("edit_file_comment", (SCAN, "999")),
        ("delete_file_comment", (SCAN, "999")),
        ("mark_as_identified", (SCAN, PATH)),
        ("unmark_as_identified", (SCAN, PATH)),
        ("change_distribution_status", (SCAN, PATH)),
        ("remove_component_identification", (SCAN, PATH)),
    ],
)
def test_methods_raise_api_error_on_status_zero(
    mock_send, files_client, method_name, call_args
):
    mock_send.return_value = ERROR_RESPONSE
    method = getattr(files_client, method_name)
    err = assert_api_error(lambda: method(*call_args))
    assert_api_error_details_status_zero(err)
    assert "does not exist" in err.message


@patch.object(BaseAPI, "_send_request")
def test_get_file_comments_unexpected_shape_raises(mock_send, files_client):
    mock_send.return_value = {"status": "1", "data": {"not": "a list"}}
    with pytest.raises(ApiError, match="Unexpected get_file_comments"):
        files_client.get_file_comments(SCAN, PATH)
