"""
Live auditor workflow for FilesAndFoldersClient.

Exercises every client method in the order an auditor (or agent) would use
them: discover pending work, inspect folder context, read matches and existing
identifications, then create/update identifications, comments, distribution,
and audit-complete markers.

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

from tests.api.support.contract import assert_contract, assert_data_contract
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
        """Step 1 — list pending files (scans API; paths feed files_and_folders)."""
        assert pending_files
        assert len(pending_paths) >= 1
        for path in pending_paths[:5]:
            assert isinstance(path, str) and path
            assert not path.isdigit()

        metrics = workbench_client.results.get_scan_metrics(test_scan_code)
        assert int(metrics.get("pending_identification", 0) or 0) >= 1

    def test_folder_content_and_rankings(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
        openfastpath_dir,
    ):
        """Step 2 — folder browser and aggregate rankings at scan root."""
        all_entries = workbench_client.files_and_folders.get_folder_content(
            test_scan_code,
            show_all=True,
        )
        pending_entries = workbench_client.files_and_folders.get_folder_content(
            test_scan_code,
            show_all=False,
        )
        assert_data_contract(
            "files_and_folders.get_folder_content",
            all_entries,
            workbench_version=workbench_version,
        )
        assert len(all_entries) >= len(pending_entries)

        root_metrics = (
            workbench_client.files_and_folders.get_folder_content_metrics(
                test_scan_code
            )
        )
        assert_data_contract(
            "files_and_folders.get_folder_content_metrics",
            root_metrics,
            workbench_version=workbench_version,
        )
        assert int(root_metrics.get("pending_identification", 0) or 0) >= 1

        components = (
            workbench_client.files_and_folders.get_folder_components_ranking(
                test_scan_code
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
                current_view="show_all",
            )
        )
        extensions_pending = (
            workbench_client.files_and_folders.get_folder_extensions_ranking(
                test_scan_code,
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
            openfastpath_dir,
        )
        assert len(sub_entries) >= 1

    def test_read_identification_and_matches(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
        pending_path,
    ):
        """Step 3 — read current identification state and FossID matches."""
        identification = workbench_client.files_and_folders.get_identification(
            test_scan_code,
            pending_path,
        )
        assert_data_contract(
            "files_and_folders.get_identification",
            identification,
            workbench_version=workbench_version,
        )

        matches = workbench_client.files_and_folders.get_fossid_results(
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
        workbench_client,
        workbench_version,
        test_scan_code,
        snippet_file_path,
    ):
        """Step 4 — inspect line-level partial match data for snippet files."""
        matches = workbench_client.files_and_folders.get_fossid_results(
            test_scan_code,
            snippet_file_path,
        )
        client_result_id = _partial_match_id(matches)
        if not client_result_id:
            pytest.skip("No partial FossID match in snippet test file")

        lines = workbench_client.files_and_folders.get_matched_lines(
            test_scan_code,
            snippet_file_path,
            client_result_id=client_result_id,
        )
        assert_data_contract(
            "files_and_folders.get_matched_lines",
            lines,
            workbench_version=workbench_version,
        )

    def test_read_file_comments(
        self,
        workbench_client,
        workbench_version,
        test_scan_code,
        pending_path,
    ):
        """Step 5 — read any existing auditor comments on a pending file."""
        comments = workbench_client.files_and_folders.get_file_comments(
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

        baseline = ff.get_identification(test_scan_code, path)

        license_result = ff.add_license_identification(
            test_scan_code,
            path,
            "MIT",
            "file",
        )
        assert license_result.get("message")
        if license_result.get("data"):
            assert_data_contract(
                "files_and_folders.add_license_identification",
                license_result["data"],
                workbench_version=workbench_version,
            )
        after_license = ff.get_identification(test_scan_code, path)
        assert _has_file_license(after_license)

        copyright_result = ff.set_identification_copyright(
            test_scan_code,
            path,
            copyright_text,
            is_directory=False,
        )
        assert copyright_result.get("message")
        after_copyright = ff.get_identification(test_scan_code, path)
        assert after_copyright.get("copyright") == copyright_text

        create_response = workbench_client.components._api._send_request(
            {
                "group": "components",
                "action": "create",
                "data": {
                    "name": unique_component_name,
                    "version": component_version,
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
            component_result = ff.set_identification_component(
                test_scan_code,
                path,
                unique_component_name,
                component_version,
            )
            assert component_result.get("message")
            after_component = ff.get_identification(test_scan_code, path)
            assert has_linked_catalog_component(after_component)

            dist_before = _distributed_flag(after_component)
            ff.change_distribution_status(test_scan_code, path)
            after_toggle = ff.get_identification(test_scan_code, path)
            assert _distributed_flag(after_toggle) != dist_before

            ff.change_distribution_status(test_scan_code, path)
            after_restore = ff.get_identification(test_scan_code, path)
            assert _distributed_flag(after_restore) == dist_before

            ff.add_file_comment(
                test_scan_code,
                path,
                f"auditor workflow comment {tag}",
            )
            comments = ff.get_file_comments(test_scan_code, path)
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
            mark_result = ff.mark_as_identified(test_scan_code, path)
            assert mark_result.get("message")
            after_mark = ff.get_identification(test_scan_code, path)
            assert _identifying_done(after_mark) == "1"

            unmark_result = ff.unmark_as_identified(test_scan_code, path)
            assert unmark_result.get("message")
            after_unmark = ff.get_identification(test_scan_code, path)
            assert _identifying_done(after_unmark) != "1"

            ff.delete_file_comment(test_scan_code, comment_id)
            remaining = ff.get_file_comments(test_scan_code, path)
            assert not any(
                str(c.get("id")) == str(comment_id) for c in remaining
            )

            removed = ff.remove_component_identification(
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
        workbench_client,
        test_scan_code,
        snippet_file_path,
    ):
        """Add snippet-level license identification on a partial-match file."""
        matches = workbench_client.files_and_folders.get_fossid_results(
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
        result = workbench_client.files_and_folders.add_license_identification(
            test_scan_code,
            snippet_file_path,
            license_id,
            "snippet",
        )
        assert result.get("message")

    def test_directory_copyright(
        self,
        workbench_client,
        test_scan_code,
        openfastpath_dir,
    ):
        """Set copyright recursively on a directory (common auditor bulk action)."""
        result = workbench_client.files_and_folders.set_identification_copyright(
            test_scan_code,
            openfastpath_dir,
            "(c) auditor directory workflow test",
            is_directory=True,
        )
        assert result.get("message")
