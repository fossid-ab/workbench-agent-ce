"""Live negative tests for FilesAndFoldersClient."""

import uuid

import pytest

from tests.api.support.error_assertions import (
    assert_api_error,
    assert_api_error_details_status_zero,
)

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]


class TestFilesAndFoldersErrorsLive:
    def test_get_identification_invalid_path(
        self, workbench_client, test_scan_code
    ):
        err = assert_api_error(
            lambda: workbench_client.files_and_folders.get_identification(
                test_scan_code,
                "__no/such/file/path.c",
            ),
            message_contains="does not exist",
        )
        assert_api_error_details_status_zero(err)

    def test_set_identification_component_missing_catalog_component(
        self,
        workbench_client,
        test_scan_code,
        pending_path,
    ):
        err = assert_api_error(
            lambda: workbench_client.files_and_folders.set_identification_component(
                test_scan_code,
                pending_path,
                f"__no_such_component_{uuid.uuid4().hex[:8]}__",
                "0.0.0",
            ),
            message_contains="Component not found",
        )
        assert_api_error_details_status_zero(err)

    def test_get_matched_lines_invalid_client_result_id(
        self,
        workbench_client,
        test_scan_code,
        pending_path,
    ):
        err = assert_api_error(
            lambda: workbench_client.files_and_folders.get_matched_lines(
                test_scan_code,
                pending_path,
                client_result_id="0",
            ),
        )
        assert_api_error_details_status_zero(err)

    def test_add_license_identification_invalid_license(
        self,
        workbench_client,
        test_scan_code,
        mutation_pending_path,
    ):
        err = assert_api_error(
            lambda: workbench_client.files_and_folders.add_license_identification(
                test_scan_code,
                mutation_pending_path,
                "NOT_A_REAL_LICENSE_XYZ_999",
                "file",
            ),
        )
        assert_api_error_details_status_zero(err)

    def test_remove_component_identification_when_none_present(
        self,
        workbench_client,
        test_scan_code,
        pending_path,
    ):
        err = assert_api_error(
            lambda: workbench_client.files_and_folders.remove_component_identification(
                test_scan_code,
                pending_path,
                component_name=f"__no_such_{uuid.uuid4().hex[:8]}__",
                component_version="0.0.0",
            ),
        )
        assert_api_error_details_status_zero(err)
