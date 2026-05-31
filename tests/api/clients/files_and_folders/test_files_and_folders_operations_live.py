"""
Live validation for FilesAndFoldersClient (paths, errors, mutations).

Requires ``WORKBENCH_URL``, ``WORKBENCH_USER``, and ``WORKBENCH_TOKEN`` in the
environment (same variables CI uses).

    WORKBENCH_ALLOW_MUTATIONS=1 pytest tests/api/clients/files_and_folders/test_files_and_folders_operations_live.py -v
"""

import base64
import uuid

import pytest

from workbench_agent.api.clients.files_and_folders.errors import (
    PLAIN_PATH_ACTIONS,
    path_for_action,
)
from workbench_agent.api.exceptions import ApiError
from workbench_agent.api.utils.path_encoding import encode_path
from tests.api.support.contract import assert_data_contract
from tests.api.support.error_assertions import (
    assert_api_error,
    assert_api_error_details_status_zero,
)

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]

INVALID_SCAN = "INVALID_SCAN_CODE___NOT_REAL"
BAD_PATH = "__no/such/file/path__.c"


class TestFilesAndFoldersLiveRawProbes:
    def test_path_encoding_get_identification(
        self, test_scan_code, pending_path
    ):
        encoded = path_for_action("get_identification", pending_path)
        assert encoded == encode_path(pending_path)
        assert encoded != pending_path or "/" not in pending_path

    def test_path_encoding_remove_component_is_plain(
        self, test_scan_code, pending_path
    ):
        assert "remove_component_identification" in PLAIN_PATH_ACTIONS
        plain = path_for_action(
            "remove_component_identification", pending_path
        )
        assert plain == pending_path
        assert plain != encode_path(pending_path)

    def test_raw_get_identification_invalid_path(
        self, workbench_client, test_scan_code
    ):
        response = workbench_client.files_and_folders._api._send_request(
            {
                "group": "files_and_folders",
                "action": "get_identification",
                "data": {
                    "scan_code": test_scan_code,
                    "path": encode_path(BAD_PATH),
                },
            }
        )
        assert response.get("status") == "0", response
        assert "exist" in (response.get("error") or "").lower()

    def test_raw_payload_path_is_base64_on_wire(
        self, workbench_client, test_scan_code, pending_path
    ):
        payload = {
            "group": "files_and_folders",
            "action": "get_identification",
            "data": {
                "scan_code": test_scan_code,
                "path": path_for_action(
                    "get_identification", pending_path
                ),
            },
        }
        response = workbench_client.files_and_folders._api._send_request(
            payload
        )
        assert response.get("status") == "1", response
        wire_path = payload["data"]["path"]
        assert wire_path == base64.b64encode(
            pending_path.encode()
        ).decode()


class TestFilesAndFoldersLiveClientErrors:
    def test_get_identification_invalid_path_prefix(
        self, workbench_client, test_scan_code
    ):
        err = assert_api_error(
            lambda: workbench_client.files_and_folders.get_identification(
                test_scan_code, BAD_PATH
            ),
            message_contains="does not exist",
        )
        assert "Failed to get identification" in err.message
        assert_api_error_details_status_zero(err)

    def test_get_identification_invalid_scan(
        self, workbench_client, pending_path
    ):
        err = assert_api_error(
            lambda: workbench_client.files_and_folders.get_identification(
                INVALID_SCAN, pending_path
            ),
        )
        assert "Failed to get identification" in err.message

    def test_set_component_missing_catalog(
        self, workbench_client, test_scan_code, pending_path
    ):
        err = assert_api_error(
            lambda: workbench_client.files_and_folders.set_identification_component(
                test_scan_code,
                pending_path,
                f"__no_such_{uuid.uuid4().hex[:8]}__",
                "0.0.0",
            ),
            message_contains="Component not found",
        )
        assert "Failed to set component identification" in err.message

    def test_get_file_comments_empty_list_not_error(
        self, workbench_client, test_scan_code, pending_path
    ):
        comments = workbench_client.files_and_folders.get_file_comments(
            test_scan_code, pending_path
        )
        assert isinstance(comments, list)


@pytest.mark.usefixtures("allow_mutations", "scan_has_pending")
class TestFilesAndFoldersLiveMutationsViaClient:
    def test_add_license_and_write_shape(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
        mutation_pending_path,
    ):
        result = workbench_client.files_and_folders.add_license_identification(
            test_scan_code,
            mutation_pending_path,
            "MIT",
            "file",
        )
        assert result.get("message")
        if result.get("data"):
            assert_data_contract(
                "files_and_folders.add_license_identification",
                result["data"],
                workbench_version=workbench_version,
            )

    def test_remove_component_uses_plain_path_on_wire(
        self,
        workbench_client,
        test_scan_code,
        mutation_pending_path,
    ):
        payload = {
            "group": "files_and_folders",
            "action": "remove_component_identification",
            "data": {
                "scan_code": test_scan_code,
                "path": path_for_action(
                    "remove_component_identification",
                    mutation_pending_path,
                ),
                "component_name": f"__no_such_{uuid.uuid4().hex[:8]}__",
                "component_version": "0.0.0",
            },
        }
        assert payload["data"]["path"] == mutation_pending_path
        with pytest.raises(ApiError) as exc_info:
            workbench_client.files_and_folders.remove_component_identification(
                test_scan_code,
                mutation_pending_path,
                component_name=payload["data"]["component_name"],
                component_version="0.0.0",
            )
        assert "Failed to remove component identification" in str(
            exc_info.value
        )
