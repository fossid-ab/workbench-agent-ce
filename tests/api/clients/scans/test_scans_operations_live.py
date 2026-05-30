"""
Comprehensive live tests for ScansClient operations.

    set -a && source .env-cs && set +a
    WORKBENCH_ALLOW_MUTATIONS=1 pytest tests/api/clients/scans/test_scans_operations_live.py -v
"""

import uuid

import pytest

from workbench_agent.api.exceptions import ApiError
from tests.api.support.contract import assert_contract, assert_data_contract
from tests.api.support.error_assertions import assert_api_error

pytestmark = [pytest.mark.requires_workbench, pytest.mark.api_contract]

INVALID_CODE = f"INVALID_SCAN_{uuid.uuid4().hex[:16].upper()}"


class TestScansLiveRawProbes:
    def test_raw_create_response_contract(
        self,
        workbench_client,
        workbench_version,
        test_project_code,
    ):
        scan_code = f"api_probe_{uuid.uuid4().hex[:10]}"
        response = workbench_client.scans._api._send_request(
            {
                "group": "scans",
                "action": "create",
                "data": {
                    "scan_code": scan_code,
                    "scan_name": "API probe scan",
                    "project_code": test_project_code,
                    "description": "contract probe; delete via cleanup",
                },
            }
        )
        assert_contract(
            "scans.create",
            response,
            workbench_version=workbench_version,
        )
        try:
            workbench_client.scan_deletion.delete_scan(
                scan_code,
                wait_retry_count=30,
                wait_retry_interval=2,
            )
        except ApiError:
            pass

    def test_list_scans_id_field_types(
        self, workbench_client, test_scan_code
    ):
        scans = workbench_client.scans.list_scans()
        sample = next(
            s for s in scans if isinstance(s, dict) and s.get("code") == test_scan_code
        )
        scan_id = sample.get("id")
        assert isinstance(scan_id, (str, int)), (
            f"Unexpected id type: {type(scan_id)}"
        )


@pytest.fixture(scope="class")
def mutation_scan_code():
    return f"api_test_scan_{uuid.uuid4().hex[:12]}"


@pytest.fixture(scope="class")
def ephemeral_scan(
    workbench_client,
    test_project_code,
    mutation_scan_code,
):
    """Create one ephemeral scan per mutation class; delete after tests."""
    scan_id = workbench_client.scans.create(
        {
            "scan_code": mutation_scan_code,
            "scan_name": "API Live Test Scan",
            "project_code": test_project_code,
            "description": "created by test_scans_operations_live",
        }
    )
    assert scan_id > 0
    yield mutation_scan_code
    try:
        workbench_client.scan_deletion.delete_scan(
            mutation_scan_code,
            delete_identifications=True,
            wait_retry_count=30,
            wait_retry_interval=2,
        )
    except ApiError:
        pass


@pytest.mark.usefixtures("allow_mutations")
class TestScansLiveMutations:
    def test_create_listed_and_get_information(
        self,
        workbench_client,
        workbench_version,
        ephemeral_scan,
    ):
        listed = workbench_client.scans.list_scans()
        codes = {s.get("code") for s in listed if isinstance(s, dict)}
        assert ephemeral_scan in codes

        info = workbench_client.scans.get_information(ephemeral_scan)
        assert_data_contract(
            "scans.get_information",
            info,
            workbench_version=workbench_version,
        )
        assert info.get("code") == ephemeral_scan

    def test_update_scan(
        self,
        workbench_client,
        ephemeral_scan,
    ):
        assert workbench_client.scans.update(
            ephemeral_scan,
            scan_name="API Live Test Scan Updated",
            description="updated by live test",
        )
        info = workbench_client.scans.get_information(ephemeral_scan)
        assert info.get("name") == "API Live Test Scan Updated"

    def test_delete_queues_process_and_finishes(
        self,
        workbench_client,
        workbench_version,
        test_project_code,
    ):
        scan_code = f"api_del_{uuid.uuid4().hex[:10]}"
        workbench_client.scans.create(
            {
                "scan_code": scan_code,
                "scan_name": "API delete probe",
                "project_code": test_project_code,
            }
        )
        delete_response = workbench_client.scans.delete(scan_code)
        assert_contract(
            "scans.delete",
            delete_response,
            workbench_version=workbench_version,
        )
        process_id = int(delete_response["data"]["process_id"])
        status = workbench_client.scans.check_status(
            None, "DELETE_SCAN", process_id=process_id
        )
        assert isinstance(status, dict)

    def test_create_duplicate_scan_code_raises(
        self, workbench_client, ephemeral_scan
    ):
        assert_api_error(
            lambda: workbench_client.scans.create(
                {
                    "scan_code": ephemeral_scan,
                    "scan_name": "Duplicate",
                    "project_code": "ignored",
                }
            ),
        )
