"""Live tests for DownloadClient (requires Workbench credentials)."""

import pytest

pytestmark = pytest.mark.requires_workbench


class TestGetProjectPolicyLive:
    def test_get_project_policy_returns_json_array(
        self, workbench_client, test_project_code
    ):
        policy = workbench_client.policy.download_project_policy_json(
            test_project_code
        )
        assert isinstance(policy, list)
        assert len(policy) > 0
        first = policy[0]
        assert "id" in first
        assert "blocked" in first
        assert "reason" in first
