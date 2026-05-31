"""Live IdentificationService tests — read and write against Test Scan."""

import uuid

import pytest

from workbench_agent.api.utils.identification_helpers import (
    fossid_match_to_component_fields,
)

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]


@pytest.mark.usefixtures("scan_has_pending")
class TestIdentificationServiceLiveReadOnly:
    def test_scan_metrics(self, workbench_client, test_scan_code):
        metrics = workbench_client.results.get_scan_metrics(test_scan_code)
        assert int(metrics.get("pending_identification", 0) or 0) >= 1

    def test_pending_files_returns_paths(
        self, workbench_client, test_scan_code, pending_paths
    ):
        pending = workbench_client.results.get_pending_files(test_scan_code)
        assert pending
        for path in pending_paths[:3]:
            assert "/" in path or "." in path
            assert not path.isdigit()

    def test_get_identification_and_summary(
        self, identification_service, test_scan_code, pending_path
    ):
        data = identification_service.get_identification(
            test_scan_code, pending_path
        )
        assert isinstance(data, dict)

        summary = identification_service.summarize_identification(
            test_scan_code, pending_path
        )
        assert summary["path"] == pending_path
        assert "has_component_identification" in summary

    def test_get_matches_fields(
        self, identification_service, test_scan_code, pending_path
    ):
        matches = identification_service.get_matches(
            test_scan_code, pending_path
        )
        assert matches
        first = next(iter(matches.values()))
        fields = fossid_match_to_component_fields(first)
        assert fields["component_name"]
        assert fields["component_version"]

    def test_get_matched_lines_for_snippet(
        self,
        identification_service,
        test_scan_code,
        snippet_file_path,
    ):
        matches = identification_service.get_matches(
            test_scan_code, snippet_file_path
        )
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


@pytest.mark.usefixtures("allow_mutations", "scan_has_pending")
class TestIdentificationServiceLiveMutations:
    def test_file_license_write_and_verify(
        self,
        identification_service,
        test_scan_code,
        mutation_pending_path,
    ):
        tag = uuid.uuid4().hex[:8]
        license_id = "MIT"
        identification_service.add_file_license_to_file(
            test_scan_code, mutation_pending_path, license_id
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

    def test_ensure_component_and_identify_from_match(
        self,
        identification_service,
        workbench_client,
        test_scan_code,
        mutation_pending_path,
        unique_component_name,
    ):
        matches = identification_service.get_matches(
            test_scan_code, mutation_pending_path
        )
        assert matches

        ensured = identification_service.ensure_component(
            unique_component_name,
            "0.0.1-id-svc-test",
            "MIT",
        )
        assert ensured["created"] is True

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
            workbench_client.components.delete(
                unique_component_name, "0.0.1-id-svc-test"
            )

    def test_ensure_component_from_match(
        self,
        identification_service,
        workbench_client,
        test_scan_code,
        pending_path,
        unique_component_name,
    ):
        """Map a real FossID match to catalog fields and ensure component."""
        matches = identification_service.get_matches(
            test_scan_code, pending_path
        )
        match = next(iter(matches.values()))
        fields = fossid_match_to_component_fields(match)

        ensured = identification_service.ensure_component(
            unique_component_name,
            "0.0.1-from-match",
            fields["license_identifier"] or "MIT",
            supplier_name=fields.get("supplier_name"),
        )
        assert ensured["created"] is True
        workbench_client.components.delete(
            unique_component_name, "0.0.1-from-match"
        )

    def test_snippet_identification_on_snippet_file(
        self,
        identification_service,
        test_scan_code,
        snippet_file_path,
    ):
        matches = identification_service.get_matches(
            test_scan_code, snippet_file_path
        )
        partial = None
        for entry in matches.values():
            if isinstance(entry, dict) and entry.get("match_type") == "partial":
                partial = entry
                break
        if not partial:
            pytest.skip("No partial match on snippet file")

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
        assert result["comment_text"]
        assert result["license"].get("message")

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

    def test_set_distribution_status(
        self,
        identification_service,
        test_scan_code,
        mutation_pending_path,
    ):
        result = identification_service.set_distribution_status(
            test_scan_code, mutation_pending_path, distributed=False
        )
        assert result["changed"] is True

        restore = identification_service.set_distribution_status(
            test_scan_code, mutation_pending_path, distributed=True
        )
        assert restore["changed"] is True
