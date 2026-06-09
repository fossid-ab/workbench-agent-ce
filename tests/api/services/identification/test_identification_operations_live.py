"""Live IdentificationService tests — read and write against Test Scan."""

import uuid

import pytest

from tests.api.support.contract import assert_data_contract

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]


@pytest.mark.usefixtures("scan_has_pending")
class TestIdentificationServiceLiveReadOnly:
    def test_wired_on_workbench_client(self, workbench_client, identification_service):
        assert workbench_client.identification is identification_service

    def test_scan_metrics(self, identification_service, test_scan_code):
        metrics = identification_service.get_scan_metrics(test_scan_code)
        assert int(metrics.get("pending_identification", 0) or 0) >= 1

    def test_pending_files_returns_paths(
        self, identification_service, test_scan_code, pending_files, pending_paths
    ):
        """Pending discovery via IdentificationService (auditor entry point)."""
        pending = identification_service.get_pending_files(test_scan_code)
        assert pending == pending_files
        for path in pending_paths[:3]:
            assert "/" in path or "." in path
            assert not path.isdigit()

    def test_explore_folder(
        self,
        identification_service,
        test_scan_code,
        openfastpath_dir,
    ):
        snapshot = identification_service.explore_folder(
            test_scan_code, openfastpath_dir, pending_only=True
        )
        assert snapshot["path"] == openfastpath_dir
        assert snapshot["scan_code"] == test_scan_code
        assert isinstance(snapshot["entries"], list)
        assert isinstance(snapshot["extensions"], list)
        assert isinstance(snapshot["components"], list)

    def test_get_matches_fields(self, identification_service, test_scan_code, pending_path):
        matches = identification_service.get_matches(test_scan_code, pending_path)
        assert matches
        first = next(iter(matches.values()))
        assert first.get("artifact")
        assert first.get("version")

    def test_get_matched_lines_for_snippet(
        self,
        identification_service,
        test_scan_code,
        snippet_file_path,
    ):
        matches = identification_service.get_matches(test_scan_code, snippet_file_path)
        partial = None
        for entry in matches.values():
            if isinstance(entry, dict) and entry.get("match_type") == "partial":
                partial = entry
                break
        if not partial:
            pytest.skip("No partial match on snippet test file")

        lines = identification_service.get_matched_content(
            test_scan_code,
            snippet_file_path,
            str(partial["id"]),
        )
        assert isinstance(lines, dict)


@pytest.mark.usefixtures("scan_has_identified")
class TestIdentificationServiceLiveIdentifiedReadOnly:
    def test_get_identification_and_summary(
        self,
        identification_service,
        workbench_version,
        identified_test_scan_code,
        identified_file_path,
    ):
        data = identification_service.get_identification(
            identified_test_scan_code, identified_file_path
        )
        assert isinstance(data, dict)
        assert_data_contract(
            "files_and_folders.get_identification",
            data,
            workbench_version=workbench_version,
        )

        summary = identification_service.summarize_identification(
            identified_test_scan_code, identified_file_path
        )
        assert summary["path"] == identified_file_path
        assert summary["has_linked_catalog_component"] is True
        assert summary["is_marked_identified"] is True

    def test_get_file_comments(
        self,
        identification_service,
        workbench_version,
        identified_test_scan_code,
        identified_file_path,
    ):
        comments = identification_service.get_file_comments(
            identified_test_scan_code, identified_file_path
        )
        assert_data_contract(
            "files_and_folders.get_file_comments",
            comments,
            workbench_version=workbench_version,
        )
        assert isinstance(comments, list)


@pytest.mark.usefixtures("allow_mutations", "scan_has_pending")
class TestIdentificationServiceLiveMutations:
    def test_file_license_write_and_verify(
        self,
        identification_service,
        workbench_version,
        test_scan_code,
        mutation_pending_path,
    ):
        tag = uuid.uuid4().hex[:8]
        license_id = "MIT"
        license_result = identification_service.add_file_license_to_file(
            test_scan_code, mutation_pending_path, license_id
        )
        assert license_result.get("message")
        if license_result.get("data"):
            assert_data_contract(
                "files_and_folders.add_license_identification",
                license_result["data"],
                workbench_version=workbench_version,
            )
        summary = identification_service.summarize_identification(
            test_scan_code, mutation_pending_path
        )
        assert summary["has_file_license"] is True

        comment = identification_service.add_file_comment(
            test_scan_code,
            mutation_pending_path,
            f"identification-service license test {tag}",
        )
        assert comment.get("message")

    def test_copyright_on_file(
        self,
        identification_service,
        test_scan_code,
        mutation_pending_path,
    ):
        tag = uuid.uuid4().hex[:8]
        result = identification_service.add_copyright_to_file(
            test_scan_code,
            mutation_pending_path,
            f"(c) identification service {tag}",
        )
        assert result.get("message")
        data = identification_service.get_identification(test_scan_code, mutation_pending_path)
        assert data.get("copyright") == f"(c) identification service {tag}"

    def test_identify_whole_file_from_match(
        self,
        identification_service,
        test_scan_code,
        mutation_pending_path,
    ):
        matches = identification_service.get_matches(test_scan_code, mutation_pending_path)
        full = None
        for entry in matches.values():
            if isinstance(entry, dict) and entry.get("match_type") == "full":
                full = entry
                break
        if not full:
            pytest.skip("No full-file FossID match on mutation pending path")

        result = identification_service.identify_whole_file_from_match(
            test_scan_code,
            mutation_pending_path,
            full,
            add_file_license=False,
        )
        assert result["catalog"]["component_name"]
        assert result["component"].get("message")
        identification_service.remove_component_identification(
            test_scan_code, mutation_pending_path
        )

    def test_resolve_component_and_identify_from_match(
        self,
        identification_service,
        workbench_client,
        test_scan_code,
        mutation_pending_path,
        unique_component_name,
    ):
        matches = identification_service.get_matches(test_scan_code, mutation_pending_path)
        assert matches

        resolved = identification_service.resolve_component(
            unique_component_name,
            "0.0.1-id-svc-test",
            "MIT",
        )
        assert resolved["created"] is True

        try:
            result = identification_service.identify_component_to_file(
                test_scan_code,
                mutation_pending_path,
                unique_component_name,
                "0.0.1-id-svc-test",
            )
            assert result.get("message")

            summary = identification_service.summarize_identification(
                test_scan_code, mutation_pending_path
            )
            assert summary["has_component_identification"] is True
        finally:
            identification_service.remove_component_identification(
                test_scan_code, mutation_pending_path
            )
            workbench_client.components.delete(unique_component_name, "0.0.1-id-svc-test")

    def test_resolve_component_from_match(
        self,
        identification_service,
        workbench_client,
        test_scan_code,
        pending_path,
        unique_component_name,
    ):
        """Map a FossID match to catalog fields and resolve via component catalog."""
        matches = identification_service.get_matches(test_scan_code, pending_path)
        match = {
            **next(iter(matches.values())),
            "artifact": unique_component_name,
            "version": "0.0.1-from-match",
            "purl": None,
            "url": "",
            "cpe": None,
        }
        resolved = identification_service.resolve_component_from_match(
            match, license_identifier="MIT"
        )
        assert resolved["created"] is True
        workbench_client.components.delete(unique_component_name, "0.0.1-from-match")

    def test_snippet_identification_on_snippet_file(
        self,
        identification_service,
        test_scan_code,
        snippet_file_path,
    ):
        matches = identification_service.get_matches(test_scan_code, snippet_file_path)
        partial = None
        for entry in matches.values():
            if isinstance(entry, dict) and entry.get("match_type") == "partial":
                partial = entry
                break
        if not partial:
            pytest.skip("No partial match on snippet file")

        license_id = (
            partial.get("artifact_license") or partial.get("file_license") or "BSD-3-Clause"
        )
        result = identification_service.identify_snippet_in_file(
            test_scan_code,
            snippet_file_path,
            license_id,
            partial,
            str(partial["id"]),
        )
        assert result["comment_text"]
        assert result["license"].get("message")

    def test_mark_and_unmark_identified(
        self,
        identification_service,
        test_scan_code,
        mutation_pending_path,
    ):
        identification_service.mark_as_identified(test_scan_code, mutation_pending_path)
        identification_service.unmark_as_identified(test_scan_code, mutation_pending_path)

    def test_set_distribution_status(
        self,
        identification_service,
        test_scan_code,
        mutation_pending_path,
    ):
        summary = identification_service.summarize_identification(
            test_scan_code, mutation_pending_path
        )
        current = summary.get("distribution_status")
        target = False if current is not False else True

        result = identification_service.set_distribution_status(
            test_scan_code, mutation_pending_path, distributed=target
        )
        if not result["changed"]:
            target = not target
            result = identification_service.set_distribution_status(
                test_scan_code, mutation_pending_path, distributed=target
            )
        assert result["changed"] is True

        identification_service.set_distribution_status(
            test_scan_code,
            mutation_pending_path,
            distributed=current if current is not None else True,
        )
