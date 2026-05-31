"""Live identification service tests (read-only) on Test Scan."""

import pytest

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]


@pytest.mark.usefixtures("scan_has_pending")
class TestIdentificationServiceLive:
    def test_get_matches_fields(
        self,
        identification_service,
        pending_path,
        test_scan_code,
    ):
        from workbench_agent.api.utils.identification_helpers import (
            fossid_match_to_component_fields,
        )

        matches = identification_service.get_matches(
            test_scan_code, pending_path
        )
        assert matches
        first = next(iter(matches.values()))
        fields = fossid_match_to_component_fields(first)
        assert fields["component_name"]
        assert fields["component_version"]

    def test_summarize_identification(
        self,
        identification_service,
        pending_path,
        test_scan_code,
    ):
        summary = identification_service.summarize_identification(
            test_scan_code, pending_path
        )
        assert summary["scan_code"] == test_scan_code
        assert summary["path"] == pending_path
        assert "has_component_identification" in summary
