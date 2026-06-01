"""Unit tests for PolicyService."""

from unittest.mock import MagicMock

from workbench_agent.api.services.policy_service import PolicyService


def test_get_policy_warnings_delegates_to_scans_client():
    scans = MagicMock()
    scans.get_policy_warnings_counter.return_value = {
        "policy_warnings_total": 3,
        "identified_files_with_warnings": 1,
        "dependencies_with_warnings": 2,
    }
    service = PolicyService(scans)

    result = service.get_policy_warnings("SCAN1")

    assert result["policy_warnings_total"] == 3
    scans.get_policy_warnings_counter.assert_called_once_with("SCAN1")
