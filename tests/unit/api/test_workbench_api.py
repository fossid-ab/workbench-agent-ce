# tests/unit/api/test_workbench_api.py

# Import from the package structure
from workbench_agent.api.services.report_service import ReportService


# --- Test Cases ---
# Note: WorkbenchClient initialization and composition tests have been removed
# as they conflict with integration test patches. These scenarios are better
# tested in integration tests which provide more realistic coverage.


# --- Test API Class Constants ---
def test_api_report_type_constants():
    """Test that the ReportService class constants are defined correctly."""
    assert isinstance(ReportService.ASYNC_REPORT_TYPES, set)
    assert isinstance(ReportService.PROJECT_REPORT_TYPES, set)
    assert isinstance(ReportService.SCAN_REPORT_TYPES, set)

    # Verify specific values
    assert "xlsx" in ReportService.ASYNC_REPORT_TYPES
    assert "spdx" in ReportService.PROJECT_REPORT_TYPES
    assert "html" in ReportService.SCAN_REPORT_TYPES
