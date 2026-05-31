"""Live contract tests for FilesAndFoldersClient (requires Workbench server)."""

import uuid

import pytest

from tests.api.support.contract import assert_data_contract

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]


class TestFilesAndFoldersLiveReadOnly:
    def test_scan_has_pending(self, scan_has_pending):
        assert int(scan_has_pending.get("pending_identification", 0)) >= 1

    def test_get_folder_content_subdirectory(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
        openfastpath_dir,
    ):
        entries = workbench_client.files_and_folders.get_folder_content(
            test_scan_code,
            openfastpath_dir,
        )
        assert_data_contract(
            "files_and_folders.get_folder_content",
            entries,
            workbench_version=workbench_version,
        )
        assert len(entries) >= 1

    def test_get_folder_content_pending_filter(
        self,
        workbench_client,
        test_scan_code,
        openfastpath_dir,
    ):
        all_entries = workbench_client.files_and_folders.get_folder_content(
            test_scan_code,
            openfastpath_dir,
            show_all=True,
        )
        pending_entries = workbench_client.files_and_folders.get_folder_content(
            test_scan_code,
            openfastpath_dir,
            show_all=False,
        )
        all_files = {
            e.get("text")
            for e in all_entries
            if isinstance(e, dict) and e.get("is_directory") == "0"
        }
        pending_files = {
            e.get("text")
            for e in pending_entries
            if isinstance(e, dict) and e.get("is_directory") == "0"
        }
        assert pending_files <= all_files
        assert len(pending_files) <= len(all_files)

    def test_get_folder_content_metrics_pending_folder(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
        openfastpath_dir,
    ):
        metrics = workbench_client.files_and_folders.get_folder_content_metrics(
            test_scan_code,
            openfastpath_dir,
        )
        assert_data_contract(
            "files_and_folders.get_folder_content_metrics",
            metrics,
            workbench_version=workbench_version,
        )
        total = int(metrics.get("total", 0) or 0)
        pending = int(metrics.get("pending_identification", 0) or 0)
        identified = int(metrics.get("identified_files", 0) or 0)
        without_matches = int(metrics.get("without_matches", 0) or 0)
        assert total >= 1
        assert pending >= 1
        assert total == pending + identified + without_matches

    @pytest.mark.usefixtures("scan_has_identified")
    def test_get_folder_content_metrics_identified_scan(
        self,
        workbench_client,
        workbench_version,
        identified_test_scan_code,
        openfastpath_dir,
    ):
        metrics = workbench_client.files_and_folders.get_folder_content_metrics(
            identified_test_scan_code,
            openfastpath_dir,
        )
        assert_data_contract(
            "files_and_folders.get_folder_content_metrics",
            metrics,
            workbench_version=workbench_version,
        )
        pending = int(metrics.get("pending_identification", 0) or 0)
        identified = int(metrics.get("identified_files", 0) or 0)
        assert pending == 0
        assert identified >= 1

    def test_get_folder_content_metrics_file_path_returns_zeros(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
    ):
        metrics = workbench_client.files_and_folders.get_folder_content_metrics(
            test_scan_code,
            "OpenFastPath/LICENSE",
        )
        assert_data_contract(
            "files_and_folders.get_folder_content_metrics",
            metrics,
            workbench_version=workbench_version,
        )
        for key in (
            "total",
            "pending_identification",
            "identified_files",
            "without_matches",
        ):
            assert int(metrics.get(key, 0) or 0) == 0

    def test_get_folder_components_ranking_subdirectory(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
        openfastpath_dir,
    ):
        ranking = workbench_client.files_and_folders.get_folder_components_ranking(
            test_scan_code,
            openfastpath_dir,
        )
        assert_data_contract(
            "files_and_folders.get_folder_components_ranking",
            ranking,
            workbench_version=workbench_version,
        )
        assert isinstance(ranking, list)
        assert len(ranking) >= 1
        assert ranking[0].get("artifact") == "ofp"

    def test_get_folder_components_ranking_file_path_returns_false(
        self,
        workbench_client,
        test_scan_code,
    ):
        ranking = workbench_client.files_and_folders.get_folder_components_ranking(
            test_scan_code,
            "OpenFastPath/LICENSE",
        )
        assert ranking is False

    def test_get_folder_extensions_ranking_pending_view(
        self,
        workbench_client,
        test_scan_code,
        openfastpath_dir,
    ):
        all_ranking = (
            workbench_client.files_and_folders.get_folder_extensions_ranking(
                test_scan_code,
                openfastpath_dir,
                current_view="show_all",
            )
        )
        pending_ranking = (
            workbench_client.files_and_folders.get_folder_extensions_ranking(
                test_scan_code,
                openfastpath_dir,
                current_view="pending_items",
            )
        )
        assert isinstance(all_ranking, list)
        assert isinstance(pending_ranking, list)
        all_total = sum(int(row.get("amount", 0)) for row in all_ranking)
        pending_total = sum(int(row.get("amount", 0)) for row in pending_ranking)
        assert pending_total <= all_total

    def test_get_folder_extensions_ranking_subdirectory(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
        openfastpath_dir,
    ):
        ranking = workbench_client.files_and_folders.get_folder_extensions_ranking(
            test_scan_code,
            openfastpath_dir,
        )
        assert_data_contract(
            "files_and_folders.get_folder_extensions_ranking",
            ranking,
            workbench_version=workbench_version,
        )
        assert isinstance(ranking, list)
        assert len(ranking) >= 1

    def test_get_folder_extensions_ranking_file_path_returns_false(
        self,
        workbench_client,
        test_scan_code,
    ):
        ranking = workbench_client.files_and_folders.get_folder_extensions_ranking(
            test_scan_code,
            "OpenFastPath/LICENSE",
        )
        assert ranking is False

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


@pytest.mark.usefixtures("scan_has_identified")
class TestFilesAndFoldersIdentifiedScanReadOnly:
    def test_get_identification_linked_component(
        self,
        identification_service,
        workbench_version,
        identified_test_scan_code,
        identified_file_path,
    ):
        data = identification_service.get_identification(
            identified_test_scan_code, identified_file_path
        )
        assert_data_contract(
            "files_and_folders.get_identification",
            data,
            workbench_version=workbench_version,
        )
        summary = identification_service.summarize_identification(
            identified_test_scan_code, identified_file_path
        )
        assert summary["has_linked_catalog_component"] is True
        assert summary["is_marked_identified"] is True


@pytest.mark.usefixtures("allow_mutations", "scan_has_pending")
class TestFilesAndFoldersLiveMutations:
    def test_add_license_identification_success(
        self,
        identification_service,
        workbench_version,
        test_scan_code,
        mutation_pending_path,
    ):
        result = identification_service.add_file_license_to_file(
            test_scan_code,
            mutation_pending_path,
            "MIT",
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
        identification_service,
        test_scan_code,
        mutation_pending_path,
    ):
        result = identification_service.set_distribution_status(
            test_scan_code, mutation_pending_path, distributed=False
        )
        assert result["changed"] is True
        identification_service.set_distribution_status(
            test_scan_code, mutation_pending_path, distributed=True
        )

    def test_set_copyright_on_openfastpath_directory(
        self,
        identification_service,
        test_scan_code,
        openfastpath_dir,
    ):
        result = identification_service.add_copyright_to_folder(
            test_scan_code,
            openfastpath_dir,
            "(c) API directory test",
        )
        assert result.get("message")

    def test_set_copyright(
        self,
        identification_service,
        test_scan_code,
        mutation_pending_path,
    ):
        result = identification_service.add_copyright_to_file(
            test_scan_code,
            mutation_pending_path,
            "(c) API test",
        )
        assert result.get("message")

    def test_comment_cycle(
        self,
        identification_service,
        workbench_client,
        test_scan_code,
        mutation_pending_path,
    ):
        tag = f"api-test-{uuid.uuid4().hex[:8]}"
        identification_service.add_file_comment(
            test_scan_code,
            mutation_pending_path,
            f"comment {tag}",
        )
        comments = identification_service.get_file_comments(
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
        identification_service,
        test_scan_code,
        mutation_pending_path,
    ):
        identification_service.mark_as_identified(
            test_scan_code, mutation_pending_path
        )
        identification_service.unmark_as_identified(
            test_scan_code, mutation_pending_path
        )

    def test_component_identification_cycle(
        self,
        identification_service,
        workbench_client,
        test_scan_code,
        mutation_pending_path,
        unique_component_name,
    ):
        version = "0.0.1-api-test"
        identification_service.resolve_component(
            unique_component_name, version, "MIT"
        )
        try:
            identification_service.identify_component_to_file(
                test_scan_code,
                mutation_pending_path,
                unique_component_name,
                version,
            )
            removed = identification_service.remove_component_identification(
                test_scan_code, mutation_pending_path
            )
            assert removed is True
        finally:
            workbench_client.components.delete(
                unique_component_name, version
            )
