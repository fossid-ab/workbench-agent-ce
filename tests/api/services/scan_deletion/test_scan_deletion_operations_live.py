"""
Live tests for ScanDeletionService.

Creates an ephemeral scan in Test Project via ``scans.create``, verifies it
with ``projects.get_all_scans``, deletes through the service, and confirms
removal from the project scan list.

Requires ``WORKBENCH_URL``, ``WORKBENCH_USER``, and ``WORKBENCH_TOKEN`` in the
environment (same variables CI uses).

    WORKBENCH_ALLOW_MUTATIONS=1 pytest tests/api/services/scan_deletion/test_scan_deletion_operations_live.py -v
"""

import uuid

import pytest

from workbench_agent.api.utils.process_waiter import StatusResult

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]


def _project_scan_codes(workbench_client, project_code: str) -> set[str]:
    scans = workbench_client.projects.get_all_scans(project_code)
    return {s.get("code") for s in scans if isinstance(s, dict) and s.get("code")}


@pytest.mark.usefixtures("allow_mutations")
class TestScanDeletionServiceLiveMutations:
    def test_delete_scan_after_create(
        self,
        workbench_client,
        test_project_code,
    ):
        scan_code = f"scan_del_svc_{uuid.uuid4().hex[:10]}"
        scan_id = workbench_client.scans.create(
            {
                "scan_code": scan_code,
                "scan_name": "ScanDeletionService live test",
                "project_code": test_project_code,
                "description": (
                    "ephemeral scan; deleted by "
                    "test_scan_deletion_operations_live"
                ),
            }
        )
        assert scan_id > 0
        assert scan_code in _project_scan_codes(
            workbench_client, test_project_code
        )

        result = workbench_client.scan_deletion.delete_scan(
            scan_code,
            delete_identifications=True,
            wait_retry_count=30,
            wait_retry_interval=2,
        )

        assert isinstance(result, StatusResult)
        assert result.is_finished is True
        assert result.success is True
        assert scan_code not in _project_scan_codes(
            workbench_client, test_project_code
        )
