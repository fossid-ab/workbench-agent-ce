"""
Live auditor workflow for FilesAndFoldersClient.

Exercises every client method in the order an auditor (or agent) would use
them: discover pending work via ``scans.get_pending_files``, inspect folder
context, read matches and existing identifications, then create/update
identifications, comments, distribution, and audit-complete markers.

Requires ``WORKBENCH_URL``, ``WORKBENCH_USER``, and ``WORKBENCH_TOKEN`` in the
environment (same variables CI uses).

    pytest tests/api/clients/files_and_folders/test_files_and_folders_auditor_workflow_live.py -m requires_workbench -v

Mutations (Phase 2):

    WORKBENCH_ALLOW_MUTATIONS=1 pytest \\
        tests/api/clients/files_and_folders/test_files_and_folders_auditor_workflow_live.py \\
        -k Phase2 -v
"""

from __future__ import annotations

import uuid

import pytest

from tests.api.support.contract import assert_data_contract
from workbench_agent.api.utils.identification_helpers import (
    find_first_match,
    has_linked_catalog_component,
    parse_identifying_done,
    summarize_identification_state,
)

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]


def _has_file_license(data: dict) -> bool:
    return bool(summarize_identification_state(data).get("has_file_license"))


def _distributed_flag(data: dict):
    status = summarize_identification_state(data).get("distribution_status")
    if status is None:
        return None
    return "1" if status else "0"


def _identifying_done(data: dict):
    marked = parse_identifying_done(data)
    if marked is None:
        return None
    return "1" if marked else "0"


def _partial_match_id(matches: dict):
    match = find_first_match(matches, match_type="partial")
    return str(match["id"]) if match else None


@pytest.mark.usefixtures("scan_has_pending")
class TestAuditorWorkflowPhase1Discovery:
    """Read-only APIs: discover scope and inspect files before writing."""

    def test_list_pending_files(
        self,
        workbench_client,
        test_scan_code,
        pending_files,
        pending_paths,
    ):
        """Step 1 — list pending files (``scans.get_pending_files``; values → paths)."""
        assert pending_files
        assert len(pending_paths) >= 1
        for path in pending_paths[:5]:
            assert isinstance(path, str) and path
            assert not path.isdigit()
            assert path in pending_files.values()

        metrics = workbench_client.identification.get_scan_metrics(test_scan_code)
        assert int(metrics.get("pending_identification", 0) or 0) >= 1

    def test_folder_content_and_rankings(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
        openfastpath_dir,
    ):
        """Step 2 — folder browser and aggregate rankings under OpenFastPath."""
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
        assert_data_contract(
            "files_and_folders.get_folder_content",
            all_entries,
            workbench_version=workbench_version,
        )
        assert len(all_entries) >= len(pending_entries)

        folder_metrics = (
            workbench_client.files_and_folders.get_folder_content_metrics(
                test_scan_code,
                openfastpath_dir,
            )
        )
        assert_data_contract(
            "files_and_folders.get_folder_content_metrics",
            folder_metrics,
            workbench_version=workbench_version,
        )
        assert int(folder_metrics.get("pending_identification", 0) or 0) >= 1

        components = (
            workbench_client.files_and_folders.get_folder_components_ranking(
                test_scan_code,
                openfastpath_dir,
            )
        )
        assert_data_contract(
            "files_and_folders.get_folder_components_ranking",
            components,
            workbench_version=workbench_version,
        )
        assert isinstance(components, list) and components

        extensions_all = (
            workbench_client.files_and_folders.get_folder_extensions_ranking(
                test_scan_code,
                openfastpath_dir,
                current_view="show_all",
            )
        )
        extensions_pending = (
            workbench_client.files_and_folders.get_folder_extensions_ranking(
                test_scan_code,
                openfastpath_dir,
                current_view="pending_items",
            )
        )
        assert_data_contract(
            "files_and_folders.get_folder_extensions_ranking",
            extensions_all,
            workbench_version=workbench_version,
        )
        assert isinstance(extensions_pending, list)

        sub_entries = workbench_client.files_and_folders.get_folder_content(
            test_scan_code,
            f"{openfastpath_dir}/src",
        )
        assert len(sub_entries) >= 1

    def test_read_identification_and_matches(
        self,
        identification_service,
        workbench_version,
        test_scan_code,
        pending_path,
    ):
        """Step 3 — read current identification state and FossID matches."""
        identification = identification_service.get_identification(
            test_scan_code,
            pending_path,
        )
        assert_data_contract(
            "files_and_folders.get_identification",
            identification,
            workbench_version=workbench_version,
        )

        matches = identification_service.get_matches(
            test_scan_code,
            pending_path,
        )
        assert_data_contract(
            "files_and_folders.get_fossid_results",
            matches,
            workbench_version=workbench_version,
        )
        assert matches

    def test_read_matched_lines_for_snippet(
        self,
        identification_service,
        workbench_version,
        test_scan_code,
        snippet_file_path,
    ):
        """Step 4 — inspect line-level partial match data for snippet files."""
        matches = identification_service.get_matches(
            test_scan_code,
            snippet_file_path,
        )
        client_result_id = _partial_match_id(matches)
        if not client_result_id:
            pytest.skip("No partial FossID match in snippet test file")

        lines = identification_service.get_matched_content(
            test_scan_code,
            snippet_file_path,
            client_result_id,
        )
        assert_data_contract(
            "files_and_folders.get_matched_lines",
            lines,
            workbench_version=workbench_version,
        )

    def test_read_file_comments(
        self,
        identification_service,
        workbench_version,
        test_scan_code,
        pending_path,
    ):
        """Step 5 — read any existing auditor comments on a pending file."""
        comments = identification_service.get_file_comments(
            test_scan_code,
            pending_path,
        )
        assert_data_contract(
            "files_and_folders.get_file_comments",
            comments,
            workbench_version=workbench_version,
        )
        assert isinstance(comments, list)


@pytest.mark.usefixtures("allow_mutations", "scan_has_pending")
class TestAuditorWorkflowPhase2Mutations:
    """Write APIs: create identifications and verify by re-reading state."""

    def test_complete_file_audit_workflow(
        self,
        identification_service,
        workbench_client,
        workbench_version,
        test_scan_code,
        auditor_target_path,
        unique_component_name,
    ):
        """
        End-to-end auditor flow on one pending file:

        license → copyright → catalog component → distribution toggle →
        comment CRUD → mark identified → cleanup.
        """
        ff = workbench_client.files_and_folders
        path = auditor_target_path
        tag = uuid.uuid4().hex[:8]
        component_version = "0.0.1-auditor"
        copyright_text = f"(c) auditor workflow {tag}"

        baseline = identification_service.get_identification(
            test_scan_code, path
        )

        license_result = identification_service.add_file_license_to_file(
            test_scan_code,
            path,
            "MIT",
        )
        assert license_result.get("message")
        if license_result.get("data"):
            assert_data_contract(
                "files_and_folders.add_license_identification",
                license_result["data"],
                workbench_version=workbench_version,
            )
        after_license = identification_service.get_identification(
            test_scan_code, path
        )
        assert _has_file_license(after_license)

        copyright_result = identification_service.add_copyright_to_file(
            test_scan_code,
            path,
            copyright_text,
        )
        assert copyright_result.get("message")
        after_copyright = identification_service.get_identification(
            test_scan_code, path
        )
        assert after_copyright.get("copyright") == copyright_text

        identification_service.resolve_component(
            unique_component_name,
            component_version,
            "MIT",
        )

        try:
            component_result = identification_service.identify_component_to_file(
                test_scan_code,
                path,
                unique_component_name,
                component_version,
            )
            assert component_result.get("message")
            after_component = identification_service.get_identification(
                test_scan_code, path
            )
            assert has_linked_catalog_component(after_component)

            dist_before = _distributed_flag(after_component)
            identification_service.set_distribution_status(
                test_scan_code, path, distributed=dist_before != "1"
            )
            after_toggle = identification_service.get_identification(
                test_scan_code, path
            )
            assert _distributed_flag(after_toggle) != dist_before

            identification_service.set_distribution_status(
                test_scan_code, path, distributed=dist_before == "1"
            )
            after_restore = identification_service.get_identification(
                test_scan_code, path
            )
            assert _distributed_flag(after_restore) == dist_before

            identification_service.add_file_comment(
                test_scan_code,
                path,
                f"auditor workflow comment {tag}",
            )
            comments = identification_service.get_file_comments(
                test_scan_code, path
            )
            created = [
                c
                for c in comments
                if tag in (c.get("comment") or "")
            ]
            assert created, "Expected created comment to appear in list"
            comment_id = created[-1]["id"]

            edit_result = ff.edit_file_comment(
                test_scan_code,
                comment_id,
                comment=f"auditor workflow edited {tag}",
            )
            assert edit_result.get("message")

            done_before = _identifying_done(after_restore)
            mark_result = identification_service.mark_as_identified(
                test_scan_code, path
            )
            assert mark_result.get("message") or mark_result.get(
                "is_marked_identified"
            )
            after_mark = identification_service.get_identification(
                test_scan_code, path
            )
            assert _identifying_done(after_mark) == "1"

            unmark_result = identification_service.unmark_as_identified(
                test_scan_code, path
            )
            assert unmark_result.get("message") or unmark_result.get(
                "is_marked_identified"
            ) is False
            after_unmark = identification_service.get_identification(
                test_scan_code, path
            )
            assert _identifying_done(after_unmark) != "1"

            ff.delete_file_comment(test_scan_code, comment_id)
            remaining = identification_service.get_file_comments(
                test_scan_code, path
            )
            assert not any(
                str(c.get("id")) == str(comment_id) for c in remaining
            )

            removed = identification_service.remove_component_identification(
                test_scan_code,
                path,
            )
            assert removed is True
        finally:
            workbench_client.components.delete(
                unique_component_name,
                component_version,
            )

        # License/copyright from this test may persist on the shared scan;
        # baseline capture documents that writes are additive when not cleared.
        assert isinstance(baseline, dict)

    def test_snippet_license_identification(
        self,
        identification_service,
        test_scan_code,
        snippet_file_path,
    ):
        """Add snippet-level license identification on a partial-match file."""
        matches = identification_service.get_matches(
            test_scan_code,
            snippet_file_path,
        )
        partial = None
        for entry in matches.values():
            if isinstance(entry, dict) and entry.get("match_type") == "partial":
                partial = entry
                break
        if not partial:
            pytest.skip("No partial match on snippet test file")

        license_id = (
            partial.get("artifact_license")
            or partial.get("file_license")
            or "BSD-3-Clause"
        )
        result = identification_service.identify_snippet_in_file(
            test_scan_code,
            snippet_file_path,
            license_id,
            partial,
            str(partial["id"]),
        )
        assert result.get("comment_text")
        assert result["license"].get("message")

    def test_directory_copyright(
        self,
        identification_service,
        test_scan_code,
        openfastpath_dir,
    ):
        """Set copyright recursively on a directory (common auditor bulk action)."""
        result = identification_service.add_copyright_to_folder(
            test_scan_code,
            openfastpath_dir,
            "(c) auditor directory workflow test",
        )
        assert result.get("message")
