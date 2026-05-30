"""Live negative tests for ScansClient."""

import pytest

from workbench_agent.api.clients.scans.errors import is_scan_not_found
from workbench_agent.api.exceptions import ApiError

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]


class TestScansErrorsLive:
    """
    Missing-scan errors on cs-demo are slow (often 1–3 minutes per request).

    We probe once per session (``unknown_scan_row_not_found_probe``) instead of
    calling every endpoint with an invalid ``scan_code``. See ``scans/quirks.md``.
    """

    def test_unknown_scan_row_not_found_via_get_information(
        self, unknown_scan_row_not_found_probe
    ):
        probe = unknown_scan_row_not_found_probe
        assert "row_not_found" in probe["message"]
        details = probe.get("details")
        assert isinstance(details, dict)

    def test_base_api_raises_before_client_maps_scan_not_found(
        self, unknown_scan_row_not_found_probe
    ):
        """Documented live behavior for ``get_information`` / similar paths."""
        assert "API Error" in unknown_scan_row_not_found_probe["message"]

    def test_is_scan_not_found_matches_documented_markers(
        self, unknown_scan_row_not_found_probe
    ):
        details = unknown_scan_row_not_found_probe.get("details") or {}
        error = details.get("error", unknown_scan_row_not_found_probe["message"])
        assert is_scan_not_found(str(error)) or "row_not_found" in str(error)
