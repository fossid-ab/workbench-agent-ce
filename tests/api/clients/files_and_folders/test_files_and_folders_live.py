"""Live contract tests for FilesAndFoldersClient (requires Workbench server)."""

import uuid

import pytest

from tests.api.support.contract import assert_contract, assert_data_contract

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]


class TestFilesAndFoldersLiveReadOnly:
    def test_scan_has_pending(self, scan_has_pending):
        assert int(scan_has_pending.get("pending_identification", 0)) >= 1

    def test_get_identification(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
        pending_path,
    ):
        data = workbench_client.files_and_folders.get_identification(
            test_scan_code, pending_path
        )
        assert_data_contract(
            "files_and_folders.get_identification",
            data,
            workbench_version=workbench_version,
        )

    def test_get_fossid_results(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
        pending_path,
    ):
        data = workbench_client.files_and_folders.get_fossid_results(
            test_scan_code, pending_path
        )
        assert_data_contract(
            "files_and_folders.get_fossid_results",
            data,
            workbench_version=workbench_version,
        )

    def test_get_file_comments(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
        pending_path,
    ):
        data = workbench_client.files_and_folders.get_file_comments(
            test_scan_code, pending_path
        )
        assert_data_contract(
            "files_and_folders.get_file_comments",
            data,
            workbench_version=workbench_version,
        )

    def test_get_matched_lines_partial_match(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
        snippet_file_path,
    ):
        results = workbench_client.files_and_folders.get_fossid_results(
            test_scan_code, snippet_file_path
        )
        assert results
        client_result_id = None
        for entry in results.values():
            if isinstance(entry, dict) and entry.get("match_type") == "partial":
                client_result_id = str(entry.get("id"))
                break
        if not client_result_id:
            pytest.skip("No partial FossID match in snippet test file")
        data = workbench_client.files_and_folders.get_matched_lines(
            test_scan_code,
            snippet_file_path,
            client_result_id=client_result_id,
        )
        assert_data_contract(
            "files_and_folders.get_matched_lines",
            data,
            workbench_version=workbench_version,
        )

    def test_get_identification_under_openfastpath(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
        openfastpath_dir,
        pending_paths,
    ):
        file_path = next(
            (p for p in pending_paths if p.startswith(openfastpath_dir + "/")),
            None,
        )
        if not file_path:
            pytest.skip("No pending file under OpenFastPath")
        data = workbench_client.files_and_folders.get_identification(
            test_scan_code, file_path
        )
        assert_data_contract(
            "files_and_folders.get_identification",
            data,
            workbench_version=workbench_version,
        )


@pytest.mark.usefixtures("allow_mutations", "scan_has_pending")
class TestFilesAndFoldersLiveMutations:
    def test_add_license_identification_success(
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

    def test_change_distribution_status(
        self,
        workbench_client,
        test_scan_code,
        mutation_pending_path,
    ):
        result = workbench_client.files_and_folders.change_distribution_status(
            test_scan_code, mutation_pending_path
        )
        assert result.get("message")

    def test_set_copyright_on_openfastpath_directory(
        self,
        workbench_client,
        test_scan_code,
        openfastpath_dir,
    ):
        result = workbench_client.files_and_folders.set_identification_copyright(
            test_scan_code,
            openfastpath_dir,
            "(c) API directory test",
            is_directory=True,
        )
        assert result.get("message")

    def test_set_copyright(
        self,
        workbench_client,
        test_scan_code,
        mutation_pending_path,
    ):
        result = workbench_client.files_and_folders.set_identification_copyright(
            test_scan_code,
            mutation_pending_path,
            "(c) API test",
            is_directory=False,
        )
        assert result.get("message")

    def test_comment_cycle(
        self,
        workbench_client,
        test_scan_code,
        mutation_pending_path,
    ):
        tag = f"api-test-{uuid.uuid4().hex[:8]}"
        workbench_client.files_and_folders.add_file_comment(
            test_scan_code,
            mutation_pending_path,
            f"comment {tag}",
        )
        comments = workbench_client.files_and_folders.get_file_comments(
            test_scan_code, mutation_pending_path
        )
        created = [
            c
            for c in comments
            if tag in (c.get("comment") or "")
        ]
        if not created:
            pytest.skip("Could not find created comment for edit/delete")
        comment_id = created[-1]["id"]
        workbench_client.files_and_folders.edit_file_comment(
            test_scan_code,
            comment_id,
            comment=f"edited {tag}",
        )
        workbench_client.files_and_folders.delete_file_comment(
            test_scan_code, comment_id
        )

    def test_mark_and_unmark_identified(
        self,
        workbench_client,
        test_scan_code,
        mutation_pending_path,
    ):
        workbench_client.files_and_folders.mark_as_identified(
            test_scan_code, mutation_pending_path
        )
        workbench_client.files_and_folders.unmark_as_identified(
            test_scan_code, mutation_pending_path
        )

    def test_component_identification_cycle(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
        mutation_pending_path,
        unique_component_name,
    ):
        version = "0.0.1-api-test"
        create_response = workbench_client.components._api._send_request(
            {
                "group": "components",
                "action": "create",
                "data": {
                    "name": unique_component_name,
                    "version": version,
                    "license_identifier": "MIT",
                },
            }
        )
        assert_contract(
            "components.create",
            create_response,
            workbench_version=workbench_version,
        )
        try:
            workbench_client.files_and_folders.set_identification_component(
                test_scan_code,
                mutation_pending_path,
                unique_component_name,
                version,
            )
            removed = (
                workbench_client.files_and_folders.remove_component_identification(
                    test_scan_code, mutation_pending_path
                )
            )
            assert removed is True
        finally:
            workbench_client.components.delete(
                unique_component_name, version
            )
